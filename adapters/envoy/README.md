# jev-edge for Envoy

Envoy talks to jev-edge through `ext_authz`. There is no second judgment engine: the OpenResty adapter exposes its evaluate path as an HTTP authorization service at `/_jev/authz`, and Envoy can call it directly (HTTP) or through a small gRPC shim.

```
HTTP   Envoy ──ext_authz/HTTP──► OpenResty /_jev/authz ──► verdict headers ──► upstream
gRPC   Envoy ──ext_authz/gRPC──► grpc-shim ──HTTP──► OpenResty /_jev/authz ──► ...
```

Both keep every property of the nginx deployment: L1 rules, cache, breaker, adaptive timeout, L3 reputation, `/_jev/config` hot reload, `/_jev/metrics`. Verdict headers reach your upstream through `allowed_upstream_headers`; a block becomes a 403 from Envoy with jev-edge's block body.

## HTTP ext_authz

1. Run OpenResty with jev-edge as usual and add:

   ```nginx
   location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
   ```

   Envoy sends the original method, the original path appended to `path_prefix`, the headers you allow, and the body. jev-edge strips the prefix, takes the client IP from `x-envoy-external-address` / `x-forwarded-for`, runs the same evaluation as `access()`, and answers 200 with `X-Jev-*` headers or 403 with the block body. Adapter errors answer 200 + `X-Jev-Verdict: error`.

2. Configure the filter. [envoy-http.yaml](envoy-http.yaml) is a complete listener; the parts that matter:

   ```yaml
   with_request_body: { max_request_bytes: 1048576, allow_partial_message: true }
   allowed_headers: { patterns: [ {exact: content-type}, {exact: content-encoding}, {exact: content-length},
                                  {exact: x-forwarded-for}, {exact: x-envoy-external-address} ] }
   http_service:
     server_uri: { uri: http://jev-edge:8080, cluster: jev-edge, timeout: 2s }
     path_prefix: /_jev/authz
     authorization_response:
       allowed_upstream_headers: { patterns: [ {prefix: x-jev-} ] }
       allowed_client_headers:   { patterns: [ {exact: content-type} ] }
   failure_mode_allow: true
   ```

   `max_request_bytes` matches `rules.max_body_bytes` (1 MiB). A larger body arrives cut to it with `x-envoy-auth-partial-body: true`, and jev-edge scans it as the head of a larger body for the text fields instead of parsing truncated JSON; the reason then ends in `(window)`, and a head with no text is `unjudgeable: body too large`. Raise both together for larger requests: see [Body size and what L1 reads](../../README.md#body-size-and-what-l1-reads). `content-encoding` must be allowed, or a compressed body cannot be decoded.

   `timeout` must exceed `jev.timeout_max_ms` plus network, otherwise Envoy gives up before jev-edge's own fail-open can answer. `failure_mode_allow: true` is the Envoy-level fail-open for when OpenResty itself is unreachable. Note that `failure_mode_allow` cannot add headers: a request that passed this way reaches your upstream with **no** `X-Jev-Verdict` at all (`failure_mode_allow_header_add` only adds `x-envoy-auth-failure-mode-allowed`). Treat a missing `X-Jev-Verdict` as "not judged", the same as `error`.

   Both reference configs also set `normalize_path` and `merge_slashes` on the connection manager and strip inbound `x-jev-*` (verdict, score, reason, source, request-id, subject) with `request_headers_to_remove` on the virtual host, so a client can neither forge a verdict nor steer the ext_authz path at `/_jev/config` through `..` or `//`.

## gRPC ext_authz

`grpc-shim/` is a ~150-line Go service implementing `envoy.service.auth.v3.Authorization/Check`. It forwards each check to `/_jev/authz` and maps the answer to `OkHttpResponse` (with the `X-Jev-*` headers to add upstream) or `DeniedHttpResponse` (status and body from jev-edge). Only an answer carrying `X-Jev-Verdict` is trusted: 200 is a decision, any status >= 400 with the header is a block (whatever `policy.block_status` is), and everything else (a 404 or 5xx from something that is not jev-edge, a timeout, a connection error) fails open with `X-Jev-Verdict: error`, `X-Jev-Source: shim`. On every path the shim overwrites all five `X-Jev-*` headers or removes the ones jev-edge did not set, so a forged inbound value cannot survive even without the route-level strip. Paths containing `..`, `%2e` or `//` are not forwarded (they fail open and are logged): the adapter's admin endpoints sit next to the authz prefix.

```bash
cd adapters/envoy/grpc-shim && go build -o jev-shim . && ./jev-shim -listen :9001 -upstream http://127.0.0.1:8080/_jev/authz
```

or `docker build -t jev-shim adapters/envoy/grpc-shim`. Envoy side: [envoy-grpc.yaml](envoy-grpc.yaml), with `pack_as_bytes: true` so bodies arrive as `raw_body`. Keep the timeouts ordered: jev-edge `timeout_max_ms` < the shim's `-timeout` (1.5 s by default) < the `grpc_service` `timeout` (2 s): when jev-edge is slow the shim gives up first and still answers `X-Jev-Verdict: error`, instead of Envoy passing the request via `failure_mode_allow` with no verdict at all.

## End-to-end test

```bash
make e2e-envoy
```

Brings up one jev-edge (mock provider), a stub upstream, the shim, and two Envoys (HTTP on :10000, gRPC on :10001) with Docker Compose, then checks on each transport: unwatched path skipped, safe verdict reaches the app, malicious request blocked with jev-edge's body, provider failure fails open, forged inbound `X-Jev-Verdict` ignored, and the partial-body path: the compose file runs the reference configs with `max_request_bytes` lowered to 64 KiB (`run.sh` writes them to `e2e/.gen/`), a ~110 KB body with the attack at its start is blocked with 403, a ~110 KB benign body passes with an `l2` verdict, jev-edge's log shows `x-envoy-auth-partial-body: true` arrived on both transports (Envoy puts it in the gRPC `CheckRequest` headers too) and a reason ending in `(window)`, and a client's own copy of the header is overwritten with `false`. Finally it stops jev-edge and checks that the HTTP path passes via `failure_mode_allow` and the gRPC path passes via the shim's own fail-open.

## Not covered yet

- Bodies larger than `max_request_bytes`: Envoy sends only the head, so text that sits only past it (the tail included) is not seen. The partial-body path itself is tested (the e2e above on both transports, and `t/04-authz.t`); to refuse such bodies instead, set `allow_partial_message: false` and Envoy answers 413. See [Traffic L1 does not see](../../docs/design.md#traffic-l1-does-not-see).
- Streaming / gRPC upstream traffic through Envoy. jev-edge only judges buffered HTTP bodies.
