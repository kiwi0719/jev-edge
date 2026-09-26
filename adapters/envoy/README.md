# jev-edge for Envoy

Envoy talks to jev-edge through `ext_authz`. There is no second judgment engine: the OpenResty adapter exposes its evaluate path as an HTTP authorization service at `/_jev/authz`, and Envoy can call it directly (HTTP) or through a small gRPC shim.

```
HTTP   Envoy ──ext_authz/HTTP──► OpenResty /_jev/authz ──► verdict headers ──► upstream
gRPC   Envoy ──ext_authz/gRPC──► grpc-shim ──HTTP──► OpenResty /_jev/authz ──► ...
```

Both keep every property of the nginx deployment: L1 rules, cache, breaker, adaptive timeout, L3 reputation, `/_jev/config` hot reload, `/_jev/metrics`. Verdict headers reach your upstream through `allowed_upstream_headers`; a block becomes a 403 from Envoy with jev-edge's block body.

## HTTP ext_authz

1. Run OpenResty with jev-edge as usual and add, in the server block that serves it:

   ```nginx
   large_client_header_buffers 4 64k;   # anything Envoy accepts (max_request_headers_kb: 60) must fit
   client_max_body_size 1m;             # >= with_request_body.max_request_bytes
   location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
   ```

   Envoy sends the original method, the original path appended to `path_prefix`, the headers you allow, and the body. jev-edge strips the prefix, takes the client IP from `x-forwarded-for` (element `client_ip.trusted_hops` from the right; `use_remote_address` appends the peer, so 1 reads it) or, from the gRPC shim, `x-envoy-external-address`, runs the same evaluation as `access()`, and answers 200 with `X-Jev-*` headers or 403 with the block body. Adapter errors answer 200 + `X-Jev-Verdict: error`.

   **Size contract.** Every request Envoy accepts must fit that server, or nginx answers 400 / 414 / 413 before jev-edge runs and the request is never judged. Envoy caps the whole header block, path included, at `max_request_headers_kb` (set to its default, 60, in both reference configs; 431 past it), so one 64k buffer holds any header line or path it lets through; nginx's default, 4 × 8k, refuses a single 9 KiB header. Bodies are capped by `max_request_bytes`, which must not exceed `client_max_body_size`. Raise either Envoy limit and raise nginx's with it.

2. Configure the filter. [envoy-http.yaml](envoy-http.yaml) is a complete listener; the parts that matter:

   ```yaml
   max_request_headers_kb: 60              # on the HttpConnectionManager
   with_request_body: { max_request_bytes: 1048576, allow_partial_message: true }
   allowed_headers: { patterns: [ {exact: content-type}, {exact: content-encoding}, {exact: content-length},
                                  {exact: x-forwarded-for}, {exact: x-request-id} ] }
   http_service:
     server_uri: { uri: http://jev-edge:8080, cluster: jev-edge, timeout: 2s }
     path_prefix: /_jev/authz
     authorization_response:
       allowed_upstream_headers: { patterns: [ {prefix: x-jev-} ] }
       allowed_client_headers:   { patterns: [ {exact: content-type} ] }
   failure_mode_allow: true
   ```

   `max_request_bytes` matches `rules.max_body_bytes` (1 MiB). A larger body arrives cut to it with `x-envoy-auth-partial-body: true`, and jev-edge scans it as the head of a larger body for the text fields instead of parsing truncated JSON; the reason then ends in `(window)`, and a head with no text is `unjudgeable: body too large`. Raise both together for larger requests: see [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads). `content-encoding` must be allowed, or a compressed body cannot be decoded. Do not allow `x-envoy-external-address`: Envoy passes a client's own copy through from a peer on a private or loopback address, and a client could then pick the address reputation counts (an invariant fails on a config that allows it). With `subject.from = "header"` or `"cookie"`, add that header (or `cookie`) to `allowed_headers`, or no request has a subject; jev-edge logs a warning once per worker when requests through `/_jev/authz` carry none. Every authz answer names, in `x-envoy-auth-headers-to-remove`, the client `X-Jev-*` headers Envoy must drop before the upstream.

   `timeout` must exceed `jev.timeout_max_ms` plus network, otherwise Envoy gives up before jev-edge's own fail-open can answer. `failure_mode_allow: true` is the Envoy-level fail-open for when OpenResty itself is unreachable. Note that `failure_mode_allow` cannot add headers: a request that passed this way reaches your upstream with **no** `X-Jev-Verdict` at all (`failure_mode_allow_header_add` only adds `x-envoy-auth-failure-mode-allowed`). Treat a missing `X-Jev-Verdict` as "not judged", the same as `error`. Over HTTP, any other answer than 200 from the authz server is a denial with that status, so a request nginx refuses before jev-edge runs is rejected, not passed; the size contract above keeps that from happening. A path with a malformed escape (a `%` not followed by two hex digits, such as the IIS-style `%u0063` that cpp-httplib under llama.cpp decodes to `c`) is one of those: nginx answers 400 and Envoy hands it on, as nginx does inline.

   Both reference configs also set `normalize_path`, `merge_slashes` and `path_with_escaped_slashes_action: REJECT_REQUEST` on the connection manager, and strip inbound `x-jev-*` (verdict, score, reason, source, request-id, subject, body-partial) before ext_authz, so a client can neither forge a verdict or a cut flag nor steer the ext_authz path at `/_jev/config` through `..`, `//` or `..%2F`. jev-edge's admin endpoints refuse such a raw path too, whatever the relay does.

## gRPC ext_authz

`grpc-shim/` is a small Go service implementing `envoy.service.auth.v3.Authorization/Check`. It forwards each check to `/_jev/authz` and maps the answer to `OkHttpResponse` (with the `X-Jev-*` headers to add upstream) or `DeniedHttpResponse` (status and body from jev-edge, with `Content-Type`, `X-Jev-Verdict` and `X-Jev-Request-Id` only: never the score, reason or source, which Envoy would hand the client). It drops every client `X-Jev-*` header and sets `x-envoy-external-address` from the source address Envoy reports. Only an answer carrying `X-Jev-Verdict` is trusted: 200 is a decision, and any status >= 400 with the header is a block (whatever `policy.block_status` is). An answer without the header, below 500 (nginx refusing the request before jev-edge runs, such as a 400 for a header past its buffers or a 414, or a 404 from something that is not jev-edge), means nobody judged the request: it is **unjudgeable**, and `-unjudged` decides. `pass` (the default) allows it with `X-Jev-Verdict: skipped`, `X-Jev-Score: 0.00`, `X-Jev-Source: shim` and `X-Jev-Reason: unjudgeable: authz answered <status>` (URL-encoded, as jev-edge encodes reasons). `block` denies it with 403 and `{"error":"request rejected"}`. Keep it equal to jev-edge's `policy.unjudgeable`. A 5xx without the header (the server, or a proxy in front of it, failing), a timeout or a connection error still fails open with `X-Jev-Verdict: error`, `X-Jev-Source: shim`, whatever `-unjudged` says. On every path the shim overwrites the `X-Jev-*` headers it sets and removes the others, so a forged inbound value cannot survive even without the route-level strip. A path nginx refuses with 400 before jev-edge runs (a `%` not followed by two hex digits, such as `%u0063`, or a `%00`), or one with a control character, which Go cannot put in a URL, is denied with 400 and `{"error":"request rejected"}` without asking jev-edge, whatever `-unjudged` says: the answer HTTP ext_authz gives it, and never a fail-open. An escape of a byte that is not UTF-8 (`%FF`, the overlong `%C0%AE`) is well formed, as it is to nginx, and is judged on the path as sent. A path with `..`, `%2e` or `//` is forwarded as nginx reads it inline: escapes decoded, dot segments resolved, doubled slashes merged, each segment escaped again, so it is judged as the inline deployment judges it and cannot climb out of `/_jev/authz/` to the adapter's admin endpoints; a `..` above the root, or a path that does not start with `/`, gets 400.

```bash
cd adapters/envoy/grpc-shim && go build -o jev-shim . && ./jev-shim -listen :9001 -upstream http://127.0.0.1:8080/_jev/authz -unjudged pass
```

or `docker build -t jev-shim adapters/envoy/grpc-shim`. Envoy side: [envoy-grpc.yaml](envoy-grpc.yaml), with `pack_as_bytes: true` so bodies arrive as `raw_body`. Envoy sends the shim the full header map, so the size contract above matters most here: the shim copies every header and the path to `/_jev/authz`. The shim's gRPC server takes messages up to gRPC's default 4 MiB, far above a 1 MiB `max_request_bytes` plus 60 KiB of headers. Keep the timeouts ordered: jev-edge `timeout_max_ms` < the shim's `-timeout` (1.5 s by default) < the `grpc_service` `timeout` (2 s): when jev-edge is slow the shim gives up first and still answers `X-Jev-Verdict: error`, instead of Envoy passing the request via `failure_mode_allow` with no verdict at all.

## End-to-end test

```bash
make e2e-envoy
```

Brings up one jev-edge (mock provider), a stub upstream, two shims (one with `-unjudged block`), and three Envoys (HTTP on :10000, gRPC on :10001, gRPC through the blocking shim on :10002) with Docker Compose, then checks on each transport: unwatched path skipped, safe verdict reaches the app, malicious request blocked with jev-edge's body, provider failure fails open, forged inbound `X-Jev-Verdict` ignored, and the partial-body path: the compose file runs the reference configs with `max_request_bytes` lowered to 64 KiB (`run.sh` writes them to `e2e/.gen/`), a ~110 KB body with the attack at its start is blocked with 403, a ~110 KB benign body passes with an `l2` verdict, jev-edge's log shows `x-envoy-auth-partial-body: true` arrived on both transports (Envoy puts it in the gRPC `CheckRequest` headers too) and a reason ending in `(window)`, and a client's own copy of the header is overwritten with `false`. The size contract: an attack with a 9 KiB or a 50 KB header, or on a 9 KiB or a 50 KB watched path, is judged and blocked, and headers past `max_request_headers_kb` get 431. Malformed paths: `%u0063` (`/v1/%u0063ompletions`, `/v1/chat/%u0063ompletions`, `/v1%u002fchat/completions`) and `%zz` get 400 on every transport, with the block body from both shims, while the overlong `/v1/chat/%C0%AEcompletions` is judged and blocked on all three. Unjudgeable, on gRPC: jev-edge's nginx refusing a request (the e2e `nginx.conf` answers 400 to `X-E2e-Refuse`) passes marked `skipped` with reason `unjudgeable: authz answered 400`, and the blocking shim denies it with 403. Finally it stops jev-edge and checks that the HTTP path passes via `failure_mode_allow` and both gRPC shims pass via their own fail-open (`error`).

## Not covered yet

- Bodies larger than `max_request_bytes`: Envoy sends only the head, so text that sits only past it (the tail included) is not seen. The partial-body path itself is tested (the e2e above on both transports, and `t/04-authz.t`); to refuse such bodies instead, set `allow_partial_message: false` and Envoy answers 413. See [Traffic L1 does not see](../../docs/design.md#traffic-l1-does-not-see).
- Streaming / gRPC upstream traffic through Envoy. jev-edge only judges buffered HTTP bodies.
