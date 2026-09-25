# jev-edge for LiteLLM proxy

LiteLLM proxy is where a lot of LLM traffic actually flows, and it has a guardrail hook that runs before model calls. [jev_edge_guardrail.py](jev_edge_guardrail.py) is that hook: it sends the request's text, in its original structure, to a running jev-edge (`/_jev/authz`, the same endpoint Envoy and the [recipes](../../docs/recipes.md) use) and blocks or annotates the call with the verdict. Nothing is judged in Python; jev-edge decides, with its thresholds, deployment context, cache and breaker. No core port, nothing new to keep in parity.

## Install

1. Run jev-edge on OpenResty (or APISIX) with the authz location enabled. `client_max_body_size` must be at least `JEV_EDGE_MAX_BODY_BYTES` (1 MiB by default, which is also nginx's default):

   ```nginx
   location /_jev/authz/ {
       client_max_body_size 1m;
       content_by_lua_block { require("resty.jev.edge").authz() }
   }
   ```

2. Put `jev_edge_guardrail.py` next to LiteLLM's `config.yaml`: LiteLLM loads `guardrail: <file>.<Class>` from the config file's directory. It needs only `httpx`, which LiteLLM already depends on.

3. Add it to `config.yaml`:

   ```yaml
   guardrails:
     - guardrail_name: jev-edge
       litellm_params:
         guardrail: jev_edge_guardrail.JevEdgeGuardrail
         mode: pre_call
         default_on: true
   ```

   Per-key or per-request guardrail selection works as for any LiteLLM guardrail (`guardrails: ["jev-edge"]` in the request or the key's metadata).

4. Configure it with environment variables in LiteLLM's environment. LiteLLM builds a custom guardrail with `guardrail_name`, `event_hook` and `default_on` only, so settings written under `litellm_params` never reach it.

   | Variable | Default | Meaning |
   | --- | --- | --- |
   | `JEV_EDGE_URL` | (required) | jev-edge's base URL, e.g. `http://jev-edge:8080` |
   | `JEV_EDGE_ENFORCE` | `true` | `false` = monitor: annotate, never block |
   | `JEV_EDGE_TIMEOUT` | `2.0` | seconds; exceeded = fail open |
   | `JEV_EDGE_PATH` | `/v1/chat/completions` | the path jev-edge's L1 sees; one its rules watch |
   | `JEV_EDGE_MAX_BODY_BYTES` | `1048576` | the largest body sent; keep it equal to jev-edge's `max_body_bytes` and at most `client_max_body_size` |
   | `JEV_EDGE_EXTRA_FIELDS` | none | comma list of top-level keys also sent: those of jev-edge's `untrusted.fields` (`documents[*].text` sends `documents`) |
   | `JEV_EDGE_UNJUDGED` | `pass` | `pass` or `block`: what a request nobody could judge gets; keep it equal to jev-edge's `policy.unjudgeable` |

   A bad value (`JEV_EDGE_ENFORCE=maybe`, a timeout of 0) stops LiteLLM at startup with a `ValueError` instead of being ignored, and the settings in effect are logged once at INFO. Code that builds the class itself can pass the same settings as keyword arguments (`jev_edge_url`, `enforce`, `timeout`, `path`, `max_body_bytes`, `extra_fields`, `unjudged`); they win over the environment.

## What it sends

- **The body** is the request's text keys with their structure: `system`, `instructions`, the `JEV_EDGE_EXTRA_FIELDS` keys, `query`, `text`, `prompt`, `input` and `messages`, in that order (the conversation last). Roles, content parts, Anthropic `tool_use` / `tool_result` blocks, `role: tool` messages and Responses API `function_call` / `function_call_output` items are sent as they are, so jev-edge judges tool results and retrieved content (`untrusted.enabled`) exactly as it does in-line. Gemini `contents` and `systemInstruction` are sent as `messages`. Media is left out: image, audio and file parts keep only their `type` (and any `text`), and base64 sources and inline data are removed. The model, tool definitions, sampling parameters and LiteLLM's metadata are not sent.
- **Encoding**: compact UTF-8 JSON; non-ASCII text is not escaped, so CJK text and emoji cost their UTF-8 size.
- **Size**: a body past `JEV_EDGE_MAX_BODY_BYTES` is sent as its head and its last 64 KiB (the newest turn) with `X-Jev-Body-Partial: 1`. jev-edge scans it the way it scans an oversized body in-line (the reason ends in `(window)`); text in the middle is not judged, and tool results in such a body are judged as text, without the retrieved-content question.
- **`X-Forwarded-For`** carries the request's whole `X-Forwarded-For` chain, so jev-edge's `client_ip.trusted_hops` picks the hop instead of the client-forgeable first entry (LiteLLM's `requester_ip_address` is only used when there is no `X-Forwarded-For`: with `use_x_forwarded_for` on it is that forgeable first entry), so jev-edge's reputation and L3 work per client, not per proxy.

## Call types

LiteLLM passes each route's call type to the hook (sync and async names are treated alike).

| Call type | What the guardrail does |
| --- | --- |
| `completion`, `text_completion`, `anthropic_messages`, `responses`, `generate_content`, pass-through routes, and any call type not listed below | judged: the body above |
| embeddings, `moderation`, `transcription`, `speech`, `rerank`, image generation, edit and variation, video generation | skipped without a round trip: `skipped`, source `adapter`, reason `call type <name> not judged`. In-line jev-edge does not watch these routes either. |
| `add_message` (a thread message) | its `role` and `content`, judged as a message |
| `run_thread` | `instructions` and `additional_instructions` as system messages, then `additional_messages` |
| `create_thread` | its `messages` |
| `create_assistants` | its `instructions`, as a system message |
| `create_file` with purpose `batch` | the generation requests in the JSONL file (lines for chat completions, completions, responses and messages; embeddings lines are left out), judged as one body |
| `create_file` with any other purpose or a batch file that is not UTF-8 JSONL, `create_batch`, `realtime` | **unjudgeable**: the prompts are not in the request the hook sees. `skipped`, source `adapter`, reason `unjudgeable: call type <name>: ...`, passed or blocked with 403 as `JEV_EDGE_UNJUDGED` says |

LiteLLM, not this file, decides which routes run pre-call guardrails at all. In the LiteLLM source this was written against (not run here), the Assistants and Threads handlers do not appear to call them, and a Batch's prompts run at the provider without passing through LiteLLM. Where the guardrail is your control, leave `assistant_settings` and `files_settings` off, or keep `/v1/threads`, `/v1/assistants`, `/v1/files` and `/v1/batches` away from keys that should be judged.

## What it does with the answer

- Every request gets `jev_verdict` with `verdict`, `score`, `source`, `reason`, `action` and, from jev-edge, `request_id`, in `metadata`, or in `litellm_metadata` on the routes where LiteLLM keeps its own metadata there (Responses, Anthropic messages, batches, files, assistants). It shows up in LiteLLM's spend logs and callbacks.
- With `JEV_EDGE_ENFORCE=true`, a block from jev-edge (status >= 400 with `X-Jev-Verdict`, 403 by default) raises `HTTPException(<that status>, {"error": "request rejected", "jev": {...}})` and the call never reaches the model. With `false` the request continues annotated; use this for the monitor week and read the scores from the logs.
- **Unjudgeable**: an answer without `X-Jev-Verdict` below 500 means the server in front of jev-edge refused the request before jev-edge ran (413 past `client_max_body_size`, 400 or 431 for headers, 414, a 404 from something that is not jev-edge). It is annotated `skipped`, source `adapter`, reason `unjudgeable: authz answered <status>`, and passed or blocked with 403 as `JEV_EDGE_UNJUDGED` says. This matches the Envoy shim's and the HAProxy agent's `-unjudged`.
- **Fail-open**: connection errors, timeouts and a 5xx without the header annotate `verdict: error` and let the call through, whatever `JEV_EDGE_UNJUDGED` says. Requests without text are `skipped`, source `adapter`, reason `no text`, without a round trip.

## Thresholds

Set them in jev-edge, not here. `make calibrate` in the repo root works on jev-edge's own log; the guardrail adds nothing to calibrate.

## Test

```bash
make test-litellm
```

Pytest cases against a fake `/_jev/authz` (httpx `MockTransport`): pass with annotation, block, monitor mode, unreachable, 5xx, unjudgeable answers with `JEV_EDGE_UNJUDGED` pass and block, the forwarded structure (tool results, media dropped, extra fields, Gemini contents), UTF-8 and the head-and-tail cut (checked with a port of jev-edge's partial-body scanner, with every cut position around a key, colon and value), each call-type group, and settings from the environment as LiteLLM builds the class. LiteLLM itself is not required; when it is installed, one more case checks the hook's signature against LiteLLM's `CustomGuardrail`.
