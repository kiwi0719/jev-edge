# jev-edge for LiteLLM proxy

LiteLLM proxy is where a lot of LLM traffic actually flows, and it has a guardrail hook that runs before every call. [jev_edge_guardrail.py](jev_edge_guardrail.py) is that hook: it sends the request's messages to a running jev-edge (`/_jev/authz`, the same endpoint Envoy and the [recipes](../../docs/recipes.md) use) and blocks or annotates the call with the verdict. Nothing is judged in Python; jev-edge decides, with its thresholds, deployment context, cache and breaker. About 150 lines, no core port, nothing new to keep in parity.

## Install

1. Run jev-edge on OpenResty (or APISIX) with the authz location enabled:

   ```nginx
   location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
   ```

2. Make the guardrail importable by the proxy, for example by copying the file next to your config or adding this directory to `PYTHONPATH`. It needs only `httpx`, which LiteLLM already depends on.

3. Add it to `config.yaml`:

   ```yaml
   guardrails:
     - guardrail_name: jev-edge
       litellm_params:
         guardrail: jev_edge_guardrail.JevEdgeGuardrail
         mode: pre_call
         jev_edge_url: http://jev-edge:8080     # or env JEV_EDGE_URL
         enforce: true                          # false = monitor: annotate, never block
         timeout: 2.0                           # seconds; exceeded = fail open
         path: /v1/chat/completions             # the path jev-edge's L1 sees
   ```

   Per-key or per-request guardrail selection works as for any LiteLLM guardrail (`guardrails: ["jev-edge"]` in the request or the key's metadata).

## What it sends and what it does with the answer

- Chat requests: `{"messages": [...]}` with the string contents of every message (text parts of multimodal messages are kept, images dropped). Completion requests: `{"prompt": "..."}`. `X-Forwarded-For` carries the request's whole `X-Forwarded-For` chain, so jev-edge's `client_ip.trusted_hops` picks the hop instead of the client-forgeable first entry (LiteLLM's `requester_ip_address` is only used when there is no `X-Forwarded-For`: with `use_x_forwarded_for` on it is that forgeable first entry), so jev-edge's reputation and L3 work per client, not per proxy.
- Every request gets `metadata.jev_verdict` with `verdict`, `score`, `source`, `reason`, `action` and `request_id`. It shows up in LiteLLM's spend logs and callbacks.
- With `enforce: true`, a block from jev-edge (status >= 400 with `X-Jev-Verdict`, 403 by default) raises `HTTPException(<that status>, {"error": "request rejected", "jev": {...}})` and the call never reaches the model. With `enforce: false` the request continues annotated; use this for the monitor week and read the scores from the logs.
- Fail-open: only an answer carrying `X-Jev-Verdict` is trusted. Connection errors, timeouts and any answer without the header (a 404 or 5xx from something that is not jev-edge) annotate `verdict: error` and let the call through. Requests without text (tool-only calls, embeddings) are `skipped` without a round trip.

## Thresholds

Set them in jev-edge, not here. `make calibrate` in the repo root works on jev-edge's own log; the guardrail adds nothing to calibrate.

## Test

```bash
make test-litellm
```

Eight pytest cases against a fake `/_jev/authz` (httpx `MockTransport`): pass with annotation, block, monitor mode, unreachable, 5xx, prompt and multimodal bodies, no-text skip, URL from the environment. LiteLLM itself is not required to run them.
