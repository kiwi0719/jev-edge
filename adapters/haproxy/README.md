# jev-edge for HAProxy

HAProxy cannot run jev-edge in-process, but its Stream Processing Offload Engine (SPOE) can hand each request, body included, to an external agent and act on the variables the agent sets. This directory is that agent plus the two config files that wire it in.

```
client ──► HAProxy ──SPOE──► jev-spoa ──HTTP──► jev-edge /_jev/authz
              │                  │
              │◄── txn.jev.* ◄───┘
              ├─ action=block → deny with jev-edge's status and the block body
              └─ else → X-Jev-* headers → backend
```

`jev-spoa` is about 150 lines of Go and has one job: turn the SPOE message into the `/_jev/authz` request every other adapter makes, and turn the answer into `txn.jev.verdict`, `score`, `source`, `reason`, `rid`, `action` and `status`. Judgment, thresholds, the deployment context, cache, breaker and L3 stay in jev-edge. Only an answer carrying `X-Jev-Verdict` is trusted: 200 is a decision, and any status >= 400 with the header is a block (`action=block`, `status=<that code>`, whatever `policy.block_status` is). An answer without the header, below 500, means the server in front of jev-edge refused the request before jev-edge ran (a 400 for a header past its buffers, 413, 414): nobody judged it, so it is **unjudgeable**, `verdict=skipped, source=adapter`, reason `unjudgeable: authz answered <status>`, passed or blocked as the agent's `-unjudged` says. A 5xx without the header (that server, or a proxy in front of it, failing), any error reaching jev-edge, a timeout, or a path containing `..`, `%2e` or `//` (which could reach the adapter's admin endpoints) sets `verdict=error, action=pass`. Inbound `X-Jev-*` headers are never copied to jev-edge.

When SPOE gets no answer from the agent at all (agent down, slower than `timeout processing`, a message that does not fit a frame), `haproxy.cfg` marks the request the same way from SPOE's error code: `verdict=skipped`, reason `unjudgeable: spoe error <code>`, and applies `proc.jev_unjudged`. No request reaches the backend without an `X-Jev-Verdict`.

## Files

| file | role |
|---|---|
| [spoa/](spoa/) | the agent (`go build`, or the Dockerfile) |
| [spoe.conf](spoe.conf) | the SPOE engine: one message, `check-request`, with method, path, client IP, the header block (every `Content-Type` included), the body (first 96 KiB) and the body's declared size; `set-on-error` puts SPOE's error code in `txn.jev.error` |
| [haproxy.cfg](haproxy.cfg) | reference frontend: `option http-buffer-request`, the SPOE filter, the size caps, the unjudgeable marking, the `deny` rules and the `set-header` lines; `proc.jev_unjudged` in `global` |
| [e2e/](e2e/) | Docker Compose against real HAProxy 3.1; `make e2e-haproxy` |

## Install

1. Run the agent next to HAProxy, pointing at your jev-edge:

   ```bash
   cd adapters/haproxy/spoa && go build -o jev-spoa . && ./jev-spoa -listen :9000 -upstream http://jev-edge:8080/_jev/authz -timeout 1500ms -unjudged pass
   ```

   `-timeout` must stay below `timeout processing` in `spoe.conf` (2 s in the reference) and above jev-edge's `timeout_max_ms`: when jev-edge is slow the agent gives up first and still answers `verdict=error`, instead of HAProxy dropping the whole message. `-unjudged` (`pass` by default, or `block`) decides what an unjudgeable request gets: `pass` forwards it marked `X-Jev-Verdict: skipped`, `block` sets `action=block, status=403`. Keep it equal to jev-edge's `policy.unjudgeable` and to `proc.jev_unjudged` in `haproxy.cfg`.

2. Copy [spoe.conf](spoe.conf) next to `haproxy.cfg` and add to the frontend that carries LLM traffic:

   ```
   global
       tune.bufsize 131072
       set-var proc.jev_unjudged str(pass)

   frontend llm
       option http-buffer-request
       filter spoe engine jev-edge config /usr/local/etc/haproxy/spoe.conf
       http-request deny deny_status 414 if { url,length gt 8192 }
       http-request deny deny_status 431 if { req.hdrs,length gt 16384 }
       http-request set-var(txn.jev.action) var(proc.jev_unjudged)  unless { var(txn.jev.verdict) -m found }
       http-request set-var(txn.jev.status) str(403)                unless { var(txn.jev.verdict) -m found }
       http-request set-var(txn.jev.score)  str(0.00)               unless { var(txn.jev.verdict) -m found }
       http-request set-var(txn.jev.source) str(adapter)            unless { var(txn.jev.verdict) -m found }
       http-request set-var-fmt(txn.jev.reason) "unjudgeable%%3A+spoe+error+%[var(txn.jev.error,none)]" unless { var(txn.jev.verdict) -m found }
       http-request set-var(txn.jev.verdict) str(skipped)           unless { var(txn.jev.verdict) -m found }
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

   [haproxy.cfg](haproxy.cfg) has the complete version including the inbound `del-header` lines, which go first. SPOE sends the message when the request's headers and body are in, before these rules run, so the order among them is what matters: the size caps first, so an oversized request gets 414 / 431 whatever the agent answered; then the unjudgeable marking, before the `deny` lines, so `proc.jev_unjudged = block` denies through them. `deny_status` only accepts a literal, so the status jev-edge chose (`txn.jev.status`) cannot be passed through directly: add one `deny` line per `policy.block_status` you use, with the 403 line last as the catch-all. `timeout server` on the SPOA backend is deliberately long: SPOP connections sit idle between requests and a short value churns them; per-request time is `timeout processing` in `spoe.conf`.

   Upgrading from 0.6.1: replace `spoe.conf` and the agent, and add the `set-var proc.jev_unjudged` line, the two caps and the unjudgeable lines to your config. The new `spoe.conf` and agent still work with the older frontend lines, but then nothing refuses an oversized request and nothing marks a request SPOE got no answer for.

3. Reload HAProxy. `monitor` versus `enforce` is decided in jev-edge's config, not here: in `monitor` mode jev-edge never blocks, so `txn.jev.action` is never `block` and the `deny` lines never fire.

## Limits that come from SPOE

- **Size contract.** The whole message (method, path, header block, body) must fit one SPOE frame, `tune.bufsize`, and the request the agent makes must fit the header buffers of the nginx serving `/_jev/authz`. A request that does not is never judged: before this contract a client could pick a header size that made nginx answer 400, or a message one frame too big, and the request passed with no verdict. The reference config holds it with three caps: `haproxy.cfg` refuses a URI over 8 KiB (414) and a header block over 16 KiB (431), and `spoe.conf` sends at most the first 96 KiB of the body (`req.body,bytes(0,98304)`). Together that fits the 128 KiB `tune.bufsize` with room for the rest. On the jev-edge side, the server block serving `/_jev/authz` needs `large_client_header_buffers 4 64k;` (nginx's default, 4 × 8k, refuses a single 9 KiB header). Raise a cap and you must raise `tune.bufsize` and the nginx buffers with it. Anything that still fails on the way is unjudgeable, never an unmarked pass.
- **Body size.** SPOE carries the body inside a frame, so `tune.bufsize` (16 KB by default, 128 KB in the reference config) caps what HAProxy holds, and `spoe.conf` sends at most 96 KiB of it so the frame always fits. The `size` argument passes HAProxy's `req.body_size`; when it is larger than the body the agent received, the agent sends `X-Jev-Body-Partial: 1` (a client copy is dropped) and jev-edge scans the body as the head of a larger one for the text fields, instead of parsing truncated JSON as a whole. The reason then ends in `(window)`; a head with no text is `unjudgeable: body too large`. There is no tail, which is the one place this adapter is weaker than Envoy's `ext_authz`. Raising `tune.bufsize` and the cut in `spoe.conf` toward `rules.max_body_bytes` (1 MiB) costs that much memory per connection; see [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads). To refuse larger bodies instead, add `http-request deny deny_status 413 if { req.body_size gt 98304 }` next to the other caps. The partial path is covered by `make e2e-haproxy` (Content-Length and chunked bodies).
- **`option http-buffer-request`** is required so the body is available when the message is sent. It makes HAProxy wait for the full body before forwarding, which for chat requests is the normal case anyway.
- **`timeout processing`** in `spoe.conf` (2 s) is the hard stop. Past it, and on any other SPOE error, `option set-on-error` sets `txn.jev.error` and `haproxy.cfg` marks the request unjudgeable (above), so it passes as `skipped` with `proc.jev_unjudged = pass` and gets 403 with `block`. Keep the chain ordered: jev-edge `timeout_max_ms` < agent `-timeout` (1.5 s) < `timeout processing` (2 s), so each layer's fail-open answer arrives before the next one gives up.
- The agent forwards the original request headers (from `req.hdrs`), so anything jev-edge's rules look at is there, `Content-Type` included: every occurrence of it, so a request is judged when any of its content types is watched, as jev-edge does inline. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Expect`, `Accept-Encoding`, `TE`, `Upgrade`, `Keep-Alive`, client-IP headers and inbound `X-Jev-*` are dropped; the first four are recomputed by the client. An older `spoe.conf` that still sends `ct=req.hdr(content-type)` (the last value only) is ignored on that argument.

## Test

```bash
make e2e-haproxy
```

Real HAProxy 3.1 with the SPOE filter, the agent, one jev-edge (mock provider) and a stub app, with the reference `haproxy.cfg` and `spoe.conf` as shipped on :8090 and a copy with `proc.jev_unjudged = block` and an agent run with `-unjudged block` on :8091 (`run.sh` writes that one to `e2e/.gen/`). Checked: skipped / safe / suspicious / blocked, the block body and headers, header stripping, fail-open on provider failure; a repeated `Content-Type` (`application/json`, then `image/png`) and `application/json; charset=utf-8, image/png` judged and blocked; the size caps (414 past an 8 KiB URI, 431 past 16 KiB of headers) and requests at them judged: a 9 KiB header, an 8 KB path, and 16 KB of headers plus an 8 KB path plus a 185 KB body in one message; the partial-body path: a ~185 KB body (past the 96 KiB cut and `tune.bufsize`) with the attack at its start is blocked with 403 and a benign one passes with an `l2` verdict, sent with Content-Length and chunked, and jev-edge's log shows `X-Jev-Body-Partial: 1` arrived with a reason ending in `(window)`; a whole body is not flagged and a client's own `X-Jev-Body-Partial` is dropped. Unjudgeable: jev-edge's nginx refusing a request (the e2e `nginx.conf` answers 400 to `X-E2e-Refuse`) passes marked `skipped` with reason `unjudgeable: authz answered 400`, or gets 403 on the block variant; with jev-edge stopped both fail open with `error`; with the agent stopped the request passes marked `skipped` with reason `unjudgeable: spoe error 1`, or gets 403 on the block variant.
