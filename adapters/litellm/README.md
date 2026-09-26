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

3. Add it to `config.yaml`, with `default_on: true`:

   ```yaml
   guardrails:
     - guardrail_name: jev-edge
       litellm_params:
         guardrail: jev_edge_guardrail.JevEdgeGuardrail
         mode: pre_call
         default_on: true
   ```

   Without `default_on: true` LiteLLM runs the hook only for requests that name the guardrail (`guardrails: ["jev-edge"]`) and keys whose metadata names it, so a client that leaves it out is never judged; the guardrail logs a warning at startup when it is built that way. With it, nothing switches the guardrail off for a request: it ignores `disable_global_guardrail`, `disable_global_guardrails` and `opted_out_global_guardrails` wherever they are set, in the request, its key or its team, since none of them is the operator's alone. LiteLLM 1.80 reads the first from the request itself; a client can write the key and team settings into its own metadata under names 1.80 never overwrites (`user_api_key_team_metadata`); and a key's metadata is often written by whoever holds the key. Traffic that should not be judged belongs on a LiteLLM without the guardrail.

4. Configure it with environment variables in LiteLLM's environment. From LiteLLM 1.81.0 the same settings can go under `litellm_params` instead (`jev_edge_url`, `enforce`, `timeout`, `path`, `max_body_bytes`, `extra_fields`, `unjudged`, `test_endpoint`); they reach the class as keyword arguments and win over the environment. Earlier versions (1.80.11 was checked) build a custom guardrail with `guardrail_name`, `event_hook` and `default_on` only, so there settings under `litellm_params` are ignored and the environment is the only way.

   | Variable | Default | Meaning |
   | --- | --- | --- |
   | `JEV_EDGE_URL` | (required) | jev-edge's base URL, e.g. `http://jev-edge:8080` |
   | `JEV_EDGE_ENFORCE` | `true` | `false` = monitor: annotate, never block |
   | `JEV_EDGE_TIMEOUT` | `2.0` | seconds; exceeded = fail open |
   | `JEV_EDGE_PATH` | `/v1/chat/completions` | the path jev-edge's L1 sees; one its rules watch |
   | `JEV_EDGE_MAX_BODY_BYTES` | `1048576` | the largest body sent; keep it equal to jev-edge's `max_body_bytes` and at most `client_max_body_size` |
   | `JEV_EDGE_EXTRA_FIELDS` | none | comma list of top-level keys also sent: those of jev-edge's `untrusted.fields` (`documents[*].text` sends `documents`) |
   | `JEV_EDGE_UNJUDGED` | `pass` | `pass` or `block`: what a request nobody could judge gets; keep it equal to jev-edge's `policy.unjudgeable` |
   | `JEV_EDGE_TEST_ENDPOINT` | `judge` | `judge` or `refuse`: what a call from LiteLLM's `/guardrails/apply_guardrail` gets ([below](#the-test-endpoint)) |

   A bad value (`JEV_EDGE_ENFORCE=maybe`, a timeout of 0) stops LiteLLM at startup with a `ValueError` instead of being ignored, and the settings in effect are logged once at INFO.

5. Let clients reach LiteLLM only through a proxy that appends the address it saw to `X-Forwarded-For` (nginx's `$proxy_add_x_forwarded_for`, a load balancer), and set jev-edge's `client_ip.trusted_hops` to the number of such proxies. The guardrail passes the header on as LiteLLM received it; a client that reaches LiteLLM directly writes all of it, and so picks the address jev-edge's reputation and L3 count against ([details](#what-it-sends)).

### LiteLLM versions

Checked against LiteLLM 1.80.11 and 1.102.1, each running the guardrail as a proxy with a stub jev-edge and a stub provider.

- **1.81.0 and later** pass the `litellm_params` settings to the class; before, only the environment variables work.
- **1.80.11** lets a request switch every `default_on` guardrail off with `"disable_global_guardrail": true` in its body or `metadata`, and never writes a team's settings into the request (`user_api_key_team_metadata`), so a copy the client sends stands. The guardrail ignores every such switch, on every version (step 3).
- **Batch files** are judged line by line only where LiteLLM scans them (1.99 and later, see below). 1.80.11 runs no guardrail on `/v1/files` at all.
- **Realtime text** is judged where LiteLLM's realtime bridge calls `apply_guardrail` for typed messages and tool outputs (1.102.1 does; 1.80.11 does not).
- **The Bedrock pass-through** keeps LiteLLM's metadata in `metadata` on 1.80.11 and in `litellm_metadata` on 1.102.1. The guardrail takes the proxy's own metadata to be the one holding LiteLLM's key object (`user_api_key_auth`, which no request body can hold), on every route, and falls back to the route only without one.
- **Gemini's `generateContent`** (`/v1beta/models/<model>:generateContent`, `/models/<model>:generateContent` and their `streamGenerateContent`) runs the pre-call hook on 1.102.1, with call type `agenerate_content` or `agenerate_content_stream`; 1.80.11 calls the model without running it ([not covered](#not-covered)).
- **A multipart pass-through request** (a transcription through `/openai/v1/audio/transcriptions`, an image edit through `/openai/v1/images/edits`) reaches the hook without its body on 1.102.1, which does not parse the form there, and with the form's fields on 1.80.11.
- **A file upload through `/<provider>/v1/files`** (`/openai/v1/files`) is not a pass-through on 1.102.1: LiteLLM's own files endpoint takes it, as it takes `/v1/files`, with call type `acreate_file`, and runs the hook over each line of a batch file after it ([below](#call-types)). On 1.80.11 it is a pass-through: the hook gets the form's fields (`purpose`, `file`), none the guardrail reads, and the upload is unjudgeable.
- **`/guardrails/apply_guardrail`** calls `apply_guardrail` alone on 1.80.11; 1.102.1 runs the pre-call hooks of every `default_on` guardrail first, whichever guardrail the call names, with call type `apply_guardrail` ([below](#the-test-endpoint)).

## What it sends

- **The body** is the request's text with its structure. First the tool definitions, `tools` (Gemini's `functionDeclarations` too), `functions`, `response_format` and the Responses API's `text` object (its `text.format` is that API's `response_format`), unchanged: jev-edge judges them on their own. Then Gemini's `systemInstruction` (or `system_instruction`), the `JEV_EDGE_EXTRA_FIELDS` keys, `query`, `text`, `prompt`, `input`, `messages` and Gemini's `contents`, the conversation last. A system prompt (Anthropic's top-level `system`, a string or text blocks, and the Responses API's `instructions`) is sent as the first entry of `messages`, with role `system`, since every jev-edge version reads `messages[*].content`, none reads a top-level `instructions` and not every version reads `system`. Roles, content parts, Anthropic `tool_use` / `tool_result` blocks, `role: tool` messages and Responses API `function_call` / `function_call_output` items are sent as they are, so jev-edge judges tool results and retrieved content (`untrusted.enabled`) exactly as it does in-line.
- **A Gemini body** (`generateContent`, and the `/gemini` and `/vertex_ai` pass-through) keeps Gemini's own shape: `tools`, `systemInstruction` and `contents`, as the client sent them. jev-edge's default rules read `systemInstruction.parts`, `system_instruction.parts` and `contents[*].parts`; jev-edge 0.6.1 and earlier do not, and neither do rules that set their own `text_fields` without them, so add those paths there, or a Gemini request is judged as having no text. A `parts` that is one object instead of a list is sent as a list: the object, which jev-edge reads as one part, as Gemini takes it, then each of its keys as a text part, since LiteLLM 1.102.1's `generateContent` adapter iterates the object and sends the model every key as text. The request LiteLLM sends on is not changed.
- **Media** is left out: image, audio and file parts keep only their `type` (and any `text`), and base64 sources, inline data and Bedrock's `bytes` are removed. Tool calls and tool results the model reads as JSON are the exception, sent whole like the tool definitions, since a `bytes` or `image_url` key there is text the model reads: OpenAI's `tool_calls[*].function.arguments` and `custom.input` and `function_call.arguments`, Anthropic's `tool_use` `input`, a Responses `function_call`'s `arguments` and a custom tool call's `input`, which jev-edge's rules for tool-call arguments read key and string alike; Gemini's `functionResponse.response` (`function_response` in snake_case), which jev-edge reads whole as a tool result; and Bedrock's `toolUse.input`, a Bedrock `toolResult`'s `json` blocks and Gemini's `functionCall.args` (`function_call`), which no jev-edge rule reads, sent as the model gets them all the same. A part keeps them whatever `type` it has, since LiteLLM's `generateContent` adapter reads a function response next to a `type` of `image`. The media in a function response's own `parts` and in a `toolResult`'s image, document and video blocks is left out. The model, sampling parameters and LiteLLM's metadata are not sent.
- **Depth**: values nested more than 999 levels below a top-level key are left out. jev-edge's decoder refuses JSON nested more than 1000 levels, and the body's own object is the first of them. The body is copied and encoded without recursion, so Python's recursion limit caps nothing, on 3.10 and 3.11 either (where `json.dumps` counts each level against it).
- **Encoding**: compact UTF-8 JSON; non-ASCII text is not escaped, so CJK text and emoji cost their UTF-8 size.
- **Size**: a body past `JEV_EDGE_MAX_BODY_BYTES` is sent as its head and its last 64 KiB (the newest turn) with `X-Jev-Body-Partial: 1`. jev-edge scans it the way it scans an oversized body in-line (the reason ends in `(window)`): only string values that follow a key, so the value the tail starts in or just before, an array element too, is given its key again. Text in the middle is not judged, and tool results in such a body are judged as text, without the retrieved-content question.
- **`X-Forwarded-For`** is the request's whole `X-Forwarded-For` header as LiteLLM's proxy received it (from the `proxy_server_request` the proxy builds, never from body or metadata fields a client sends), or, without one, the proxy's own `requester_ip_address` (the address of the peer on 1.102.1; on 1.80.11 only with a premium licence). The header is only as good as what is in front of LiteLLM: a proxy there that appends the address it saw makes the rightmost entry real, and jev-edge's `client_ip.trusted_hops` picks it (1 for one such proxy); a client that reaches LiteLLM directly writes the whole chain, and so chooses the address jev-edge's per-client reputation and L3 count against (step 5 of the install). With `use_x_forwarded_for` on, `requester_ip_address` is that header too. With neither, nothing is sent and jev-edge counts every such request against LiteLLM's own address, as it does for the generic pass-through routes (LiteLLM records no address for them) and for `/guardrails/apply_guardrail` on 1.80.11. A batch file's lines and a realtime session's messages carry the address of the upload or the session.

## Call types

LiteLLM passes each route's call type to the hook (sync and async names are treated alike).

| Call type | What the guardrail does |
| --- | --- |
| `completion`, `text_completion`, `anthropic_messages`, `responses`, `agenerate_content` and `agenerate_content_stream` (Gemini's `generateContent`, [above](#what-it-sends)), and any call type not listed below | judged: the body above |
| `allm_passthrough_route`: the Bedrock and Gigachat pass-through for a model of the config (`/bedrock/model/...`, `/gigachat/...`) | judged: LiteLLM nests the client's body under `data` (Bedrock) or `json` (Gigachat), and the guardrail reads it there like any body (Converse `messages` and `system`, Anthropic's format on `/invoke`, `prompt`). |
| `pass_through_endpoint`: the generic pass-through (`/anthropic`, `/openai`, `/gemini`, `/vertex_ai`, `/vllm`, ..., and the config's `pass_through_endpoints`) | judged: the client's body, as sent. These requests carry no client address. |
| a pass-through body with none of the fields the guardrail reads (Titan's `inputText`, Cohere's `message`, an Anthropic batch's `requests`, Vertex's `instances`), a generic pass-through that reaches the hook without a body (a multipart form, such as a transcription or an image edit, on 1.102.1; a `GET` looks the same), and a WebSocket pass-through (Vertex AI Live), whose messages never reach the hook | **unjudgeable**, as below: reason `unjudgeable: call type <name>: no field the guardrail reads in the <provider> body`, `...: no body visible to the guardrail (a multipart form, or none)` or `...: a WebSocket pass-through's messages are not visible to the guardrail`. LiteLLM hands the hook the same empty body for a multipart request and for one without a body, so with `JEV_EDGE_UNJUDGED=block` a `GET` through the generic pass-through (`/openai/v1/models`) is refused too. A Bedrock pass-through without a body has no text. |
| embeddings, `moderation`, `transcription`, `speech`, `rerank`, image generation, edit and variation, video generation, remix, edit and extension, `vector_store_search`, `search` | skipped without a round trip: `skipped`, source `adapter`, reason `call type <name> not judged`. In-line jev-edge does not watch these routes either; what a search returns reaches a model only in a later request, which is judged. |
| `create_file` with purpose `batch`, on LiteLLM 1.99 and later | the upload's hook sees only the file's name, type and size: `skipped`, reason `call type acreate_file: batch file lines are judged one by one as LiteLLM scans them`. LiteLLM then runs the hook over every line as a request of its own (chat, completion, responses and messages lines judged, embeddings lines skipped), and drops a line jev-edge blocks from the file, reporting it in the response's `litellm_batch_guardrail`. That needs jev-edge's block status to be 400, 403 or 422: LiteLLM treats any other status as a failure and refuses the whole upload. |
| `create_file` with any other purpose (or `batch` on a LiteLLM that does not scan batch files), `create_batch`, `_arealtime` and `arealtime_calls` (realtime over WebSocket and WebRTC), `_aresponses_websocket` (the Responses API's WebSocket mode: the hook runs once, as the socket opens) | **unjudgeable**: the prompts are not in the request the hook sees. `skipped`, source `adapter`, reason `unjudgeable: call type <name>: ...`, passed or blocked with 403 as `JEV_EDGE_UNJUDGED` says. A batch's prompts are in its input file, judged only when it was uploaded through this proxy with the guardrail on, on LiteLLM 1.99 and later. |
| realtime messages (`apply_guardrail`) | a realtime session's typed user messages and `function_call_output` items, one text at a time, each judged as a user message; on a block LiteLLM keeps the item from the model (a tool output is replaced by an error marker) and sends the client a `guardrail_violation` error. Audio, its transcripts and the session's `instructions` are not judged. |
| `/guardrails/apply_guardrail`: call type `apply_guardrail` (1.102.1), then an `apply_guardrail` call | judged, or refused with `JEV_EDGE_TEST_ENDPOINT=refuse`: [the test endpoint](#the-test-endpoint) |

### Not covered

LiteLLM, not this file, decides which routes run pre-call guardrails at all, and on these the hook never runs, so nothing is judged or recorded (checked on 1.80.11 and 1.102.1):

- `/v1/assistants`, `/v1/threads` and a thread's messages and runs: an assistant's instructions and a thread's messages reach the model unjudged.
- `/v1/files` on LiteLLM 1.80: no hook, no batch scan.
- Gemini's `generateContent` and `streamGenerateContent` on LiteLLM 1.80: the model is called without the pre-call hooks.
- A `/vllm` or `/azure` pass-through request for a model of the config: LiteLLM routes it without running pre-call hooks (checked on `/vllm` with a `hosted_vllm` model; `/azure` takes the same path in LiteLLM's code).
- The frames of the Responses API's WebSocket mode (only the socket's opening is seen, and recorded unjudgeable), and realtime audio.

Where the guardrail is your control, leave `assistant_settings` off, or keep `/v1/assistants` and `/v1/threads` (and on older LiteLLM `/v1/files` and `/v1/batches`) away from keys that should be judged.

## What it does with the answer

- Every request gets `jev_verdict` with `verdict`, `score`, `source`, `reason`, `action` and, from jev-edge, `request_id`, in the metadata LiteLLM keeps for itself: `metadata`, or `litellm_metadata` on the routes where the API has a `metadata` parameter of its own (Responses, Anthropic messages, batches, files, assistants, and Bedrock on 1.102.1); the client's `metadata` there is sent on to the provider and never written. On a generic pass-through, whose data is the client's body itself, it goes in that body's `metadata`, which LiteLLM takes out before it sends the body on. The same verdict is recorded as LiteLLM's standard guardrail information (status `success`, `guardrail_intervened` for a block, `guardrail_failed_to_respond` when jev-edge could not be asked), which logging callbacks receive whole (`standard_logging_object.guardrail_information`). The spend logs' `guardrail_information` records the guardrail and its status; the verdict itself (`guardrail_response`) is there on 1.80.11, but 1.102.1 writes `REDACTED_BY_LITELM` unless `store_prompts_in_spend_logs` is on. `jev_verdict` is not a spend-log field.
- With `JEV_EDGE_ENFORCE=true`, a block from jev-edge (status >= 400 with `X-Jev-Verdict`, 403 by default) raises `HTTPException(<that status>, {"error": "request rejected", "jev": {...}})` and the call never reaches the model. With `false` the request continues annotated; use this for the monitor week and read the scores from the logs.
- **Unjudgeable**: an answer without `X-Jev-Verdict` below 500, other than 429, means the server in front of jev-edge refused the request before jev-edge ran (413 past `client_max_body_size`, 400 or 431 for headers, 414, a 404 from something that is not jev-edge). It is annotated `skipped`, source `adapter`, reason `unjudgeable: authz answered <status>`, and passed or blocked with 403 as `JEV_EDGE_UNJUDGED` says. `JEV_EDGE_UNJUDGED` is the counterpart of the `-unjudged` flag of the [Envoy gRPC shim](../envoy/README.md) and the [HAProxy agent](../haproxy/README.md): the same values and default.
- **Fail-open**: connection errors, timeouts, and a 5xx or a 429 without the header (the judge, or a proxy or rate limiter in front of it, unavailable) annotate `verdict: error` and let the call through, whatever `JEV_EDGE_UNJUDGED` says. Requests without text are `skipped`, source `adapter`, reason `no text`, without a round trip.

## The test endpoint

LiteLLM's `/guardrails/apply_guardrail` is one of its LLM API routes: any key that may call a model may also ask for a guardrail's verdict on any text, and a block answers with jev-edge's verdict, score and reason. With this guardrail that is a free oracle for tuning an attack against jev-edge: nothing reaches a model, and on 1.80.11 the call carries no client address, so jev-edge counts it against LiteLLM's own. On 1.102.1 the endpoint first runs the pre-call hooks (call type `apply_guardrail`, the text in `input`), which judge the text with the caller's address, and the `apply_guardrail` call that follows is not judged a second time.

With `JEV_EDGE_TEST_ENDPOINT=refuse` every call from the endpoint is refused with 403 (`skipped`, source `adapter`, reason `refused: /guardrails/apply_guardrail is off (JEV_EDGE_TEST_ENDPOINT=refuse)`) before jev-edge is asked, in monitor mode too; LiteLLM's realtime bridge, which passes the session's key object with each text, is still judged. The endpoint's calls are told apart by that object, which no request can send: 1.80.11 passes nothing with them, 1.102.1 the caller's `messages` and `metadata`. Refuse it wherever keys belong to people you would not show jev-edge's scores to.

1.102.1 runs the pre-call hook of every `default_on` guardrail for the endpoint, whichever guardrail the call names, and passes the name asked for (`guardrail_name`) with it. The guardrail neither judges nor refuses a call that names another guardrail (`skipped`, reason `call type apply_guardrail: /guardrails/apply_guardrail asked for guardrail <name>`), so `refuse` turns the endpoint off for jev-edge only, and another guardrail's test calls never reach jev-edge. A guardrail built by code without a `guardrail_name` cannot tell and takes every call as its own.

## Thresholds

Set them in jev-edge, not here. `make calibrate` in the repo root works on jev-edge's own log; the guardrail adds nothing to calibrate.

## Test

```bash
make test-litellm
```

Pytest cases against a fake `/_jev/authz` (httpx `MockTransport`): pass with annotation, block, monitor mode, unreachable, 5xx and 429, unjudgeable answers with `JEV_EDGE_UNJUDGED` pass and block, the forwarded structure (tool results, system prompts, tool definitions, media dropped outside the tool calls and tool results sent whole, extra fields, Gemini bodies with their function responses and a `parts` object), UTF-8 and the head-and-tail cut (checked with a port of jev-edge's partial-body scanner, with every cut position around a key, colon, value and array element), each call-type group as LiteLLM passes it (batch uploads and their per-line scan, realtime text, Gemini's `generateContent`, the Bedrock, Gigachat and generic pass-through with and without a body, the test endpoint on 1.80 and 1.102 and for another guardrail), bodies exactly as deep as jev-edge's decoder takes, copied and encoded without `json.dumps` under a low recursion limit, where the verdict and the client address are read and written, the switches a request or key has used to turn a `default_on` guardrail off, and settings from the environment and from `litellm_params` as LiteLLM builds the class. LiteLLM itself is not required; when it is installed, more cases check the hooks' signatures against LiteLLM's `CustomGuardrail` and that its own `should_run_guardrail` runs the guardrail whatever those switches say.
