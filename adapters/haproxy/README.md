# jev-edge for HAProxy

HAProxy cannot run jev-edge in-process, but its Stream Processing Offload Engine (SPOE) can hand each request, body included, to an external agent and act on the variables the agent sets. This directory is that agent plus the two config files that wire it in.

```
client ──► HAProxy ──SPOE──► jev-spoa ──HTTP──► jev-edge /_jev/authz
              │                  │
              │◄── txn.jev.* ◄───┘
              ├─ action=block → deny with jev-edge's status and the block body
              └─ else → X-Jev-* headers → backend
```

`jev-spoa` is about 150 lines of Go and has one job: turn the SPOE message into the `/_jev/authz` request every other adapter makes, and turn the answer into `txn.jev.verdict`, `score`, `source`, `reason`, `rid`, `action` and `status`. Judgment, thresholds, the deployment context, cache, breaker and L3 stay in jev-edge. Only an answer carrying `X-Jev-Verdict` is trusted: 200 is a decision, any status >= 400 with the header is a block (`action=block`, `status=<that code>`, whatever `policy.block_status` is), and anything else fails open. Any error reaching jev-edge, a timeout, or a path containing `..`, `%2e` or `//` (which could reach the adapter's admin endpoints) sets `verdict=error, action=pass`. Inbound `X-Jev-*` headers are never copied to jev-edge.

## Files

| file | role |
|---|---|
| [spoa/](spoa/) | the agent (`go build`, or the Dockerfile) |
| [spoe.conf](spoe.conf) | the SPOE engine: one message, `check-request`, with method, path, client IP, content type, headers, body and the body's declared size |
| [haproxy.cfg](haproxy.cfg) | reference frontend: `option http-buffer-request`, the SPOE filter, the `deny` rules and the `set-header` lines |
| [e2e/](e2e/) | Docker Compose against real HAProxy 3.1; `make e2e-haproxy` |

## Install

1. Run the agent next to HAProxy, pointing at your jev-edge:

   ```bash
   cd adapters/haproxy/spoa && go build -o jev-spoa . && ./jev-spoa -listen :9000 -upstream http://jev-edge:8080/_jev/authz -timeout 1500ms
   ```

   `-timeout` must stay below `timeout processing` in `spoe.conf` (2 s in the reference) and above jev-edge's `timeout_max_ms`: when jev-edge is slow the agent gives up first and still answers `verdict=error`, instead of HAProxy dropping the whole message.

2. Copy [spoe.conf](spoe.conf) next to `haproxy.cfg` and add to the frontend that carries LLM traffic:

   ```
   frontend llm
       option http-buffer-request
       filter spoe engine jev-edge config /usr/local/etc/haproxy/spoe.conf
       http-request deny deny_status 429 content-type application/json string '{"error":"request rejected"}' if { var(txn.jev.action) -m str block } { var(txn.jev.status) -m str 429 }
       http-request deny deny_status 403 content-type application/json string '{"error":"request rejected"}' if { var(txn.jev.action) -m str block }
       http-request set-header X-Jev-Verdict %[var(txn.jev.verdict)] if { var(txn.jev.verdict) -m found }
       http-request set-header X-Jev-Score   %[var(txn.jev.score)]   if { var(txn.jev.score) -m found }
       http-request set-header X-Jev-Source  %[var(txn.jev.source)]  if { var(txn.jev.source) -m found }
       http-request set-header X-Jev-Reason  %[var(txn.jev.reason)]  if { var(txn.jev.reason) -m found }

   backend jev-spoa
       mode tcp
       timeout server 5m
       server spoa 127.0.0.1:9000
   ```

   [haproxy.cfg](haproxy.cfg) has the complete version including the inbound `del-header` lines. `deny_status` only accepts a literal, so the status jev-edge chose (`txn.jev.status`) cannot be passed through directly: add one `deny` line per `policy.block_status` you use, with the 403 line last as the catch-all. `timeout server` on the SPOA backend is deliberately long: SPOP connections sit idle between requests and a short value churns them; per-request time is `timeout processing` in `spoe.conf`.

3. Reload HAProxy. `monitor` versus `enforce` is decided in jev-edge's config, not here: in `monitor` mode jev-edge never blocks, so `txn.jev.action` is never `block` and the `deny` lines never fire.

## Limits that come from SPOE

- **Body size.** SPOE carries the body inside a frame, so `tune.bufsize` (16 KB by default, 128 KB in the reference config) caps what the agent sees, per connection. The `size` argument passes HAProxy's `req.body_size`; when it is larger than the body the agent received, the agent sends `X-Jev-Body-Partial: 1` (a client copy is dropped) and jev-edge scans the body as the head of a larger one for the text fields, instead of parsing truncated JSON as a whole. The reason then ends in `(window)`; a head with no text is `unjudgeable: body too large`. There is no tail, which is the one place this adapter is weaker than Envoy's `ext_authz`. Raising `tune.bufsize` toward `rules.max_body_bytes` (1 MiB) costs that much memory per connection; see [Body size and what L1 reads](../../README.md#body-size-and-what-l1-reads). The partial path is covered by `make e2e-haproxy` (Content-Length and chunked bodies).
- **`option http-buffer-request`** is required so the body is available when the message fires. It makes HAProxy wait for the full body before forwarding, which for chat requests is the normal case anyway.
- **`timeout processing`** in `spoe.conf` (2 s) is the hard stop; with `option continue-on-error` an agent timeout leaves the variables unset and the request continues without `X-Jev-*`. Keep the chain ordered: jev-edge `timeout_max_ms` < agent `-timeout` (1.5 s) < `timeout processing` (2 s), so each layer's fail-open answer arrives before the next one gives up. Your upstream should treat a missing `X-Jev-Verdict` as "not judged".
- The agent forwards the original request headers (from `req.hdrs`), so anything jev-edge's rules look at is there. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Expect`, `Accept-Encoding`, `TE`, `Upgrade`, `Keep-Alive` and inbound `X-Jev-*` are dropped; the first four are recomputed by the client.

## Test

```bash
make e2e-haproxy
```

Real HAProxy 3.1 with the SPOE filter, the agent, one jev-edge (mock provider) and a stub app: skipped / safe / suspicious / blocked, the block body and headers, header stripping, fail-open on provider failure, the partial-body path, and fail-open with jev-edge stopped. For the partial-body checks the compose file runs the reference `haproxy.cfg` with `tune.bufsize` lowered to 16 KiB (`run.sh` writes it to `e2e/.gen/`): a ~110 KB body with the attack at its start is blocked with 403 and a ~110 KB benign body passes with an `l2` verdict, sent with Content-Length and chunked, and jev-edge's log shows `X-Jev-Body-Partial: 1` arrived with a reason ending in `(window)`; a whole body is not flagged and a client's own `X-Jev-Body-Partial` is dropped.
