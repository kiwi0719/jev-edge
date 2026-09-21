# jev-edge for HAProxy

HAProxy cannot run jev-edge in-process, but its Stream Processing Offload Engine (SPOE) can hand each request, body included, to an external agent and act on the variables the agent sets. This directory is that agent plus the two config files that wire it in.

```
client ──► HAProxy ──SPOE──► jev-spoa ──HTTP──► jev-edge /_jev/authz
              │                  │
              │◄── txn.jev.* ◄───┘
              ├─ action=block → 403 with the block body
              └─ else → X-Jev-* headers → backend
```

`jev-spoa` is about 150 lines of Go and has one job: turn the SPOE message into the `/_jev/authz` request every other adapter makes, and turn the answer into `txn.jev.verdict`, `score`, `source`, `reason`, `rid` and `action`. Judgment, thresholds, the deployment context, cache, breaker and L3 stay in jev-edge. The agent fails open: any error reaching jev-edge sets `verdict=error, action=pass`.

## Files

| file | role |
|---|---|
| [spoa/](spoa/) | the agent (`go build`, or the Dockerfile) |
| [spoe.conf](spoe.conf) | the SPOE engine: one message, `check-request`, with method, path, client IP, content type, headers and body |
| [haproxy.cfg](haproxy.cfg) | reference frontend: `option http-buffer-request`, the SPOE filter, the `deny` rule and the `set-header` lines |
| [e2e/](e2e/) | Docker Compose against real HAProxy 3.1; `make e2e-haproxy` |

## Install

1. Run the agent next to HAProxy, pointing at your jev-edge:

   ```bash
   cd adapters/haproxy/spoa && go build -o jev-spoa . && ./jev-spoa -listen :9000 -upstream http://jev-edge:8080/_jev/authz -timeout 2s
   ```

2. Copy [spoe.conf](spoe.conf) next to `haproxy.cfg` and add to the frontend that carries LLM traffic:

   ```
   frontend llm
       option http-buffer-request
       filter spoe engine jev-edge config /usr/local/etc/haproxy/spoe.conf
       http-request deny deny_status 403 content-type application/json string '{"error":"request rejected"}' if { var(txn.jev.action) -m str block }
       http-request set-header X-Jev-Verdict %[var(txn.jev.verdict)] if { var(txn.jev.verdict) -m found }
       http-request set-header X-Jev-Score   %[var(txn.jev.score)]   if { var(txn.jev.score) -m found }
       http-request set-header X-Jev-Source  %[var(txn.jev.source)]  if { var(txn.jev.source) -m found }
       http-request set-header X-Jev-Reason  %[var(txn.jev.reason)]  if { var(txn.jev.reason) -m found }

   backend jev-spoa
       mode tcp
       server spoa 127.0.0.1:9000
   ```

   [haproxy.cfg](haproxy.cfg) has the complete version including the inbound `del-header` lines.

3. Reload HAProxy. `monitor` versus `enforce` is decided in jev-edge's config, not here: in `monitor` mode jev-edge never answers 403, so `txn.jev.action` is never `block` and the `deny` line never fires.

## Limits that come from SPOE

- **Body size.** SPOE carries the body inside a frame. The default `tune.bufsize` (16 KB) caps what the agent sees; the reference config raises it to 128 KB to cover jev-edge's `rules.max_body_bytes` (64 KB). A body larger than the frame arrives truncated; jev-edge judges the truncated text, which is the one place this adapter is weaker than Envoy's `ext_authz`.
- **`option http-buffer-request`** is required so the body is available when the message fires. It makes HAProxy wait for the full body before forwarding, which for chat requests is the normal case anyway.
- **`timeout processing`** in `spoe.conf` (2 s) is the hard stop; with `option continue-on-error` an agent timeout leaves the variables unset and the request continues without `X-Jev-*`. Set it above jev-edge's `timeout_max_ms`.
- The agent forwards the original request headers (from `req.hdrs`), so anything jev-edge's rules look at is there. `Host`, `Content-Length`, `Transfer-Encoding` and `Connection` are recomputed.

## Test

```bash
make e2e-haproxy
```

Real HAProxy 3.1 with the SPOE filter, the agent, one jev-edge (mock provider) and a stub app: skipped / safe / suspicious / blocked, the block body and headers, header stripping, fail-open on provider failure, and fail-open with jev-edge stopped.
