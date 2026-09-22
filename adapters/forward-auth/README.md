# jev-edge as a forward-auth service

For gateways that speak the generic "forward-auth" pattern: send a sub-request describing the original request, allow on 2xx, deny otherwise, copy some response headers onto the request that continues upstream. One endpoint on the OpenResty adapter serves all of them:

```nginx
location = /_jev/forward-auth { content_by_lua_block { require("resty.jev.edge").forward_auth() } }
```

It reads the original method and URI from `X-Forwarded-Method` / `X-Forwarded-Uri` (Traefik, Caddy) or `X-Original-Method` / `X-Original-URI` (nginx), the client from `X-Forwarded-For`, and the body if one was forwarded. Then it runs the same evaluation as `access()` and answers 200 + `X-Jev-*` or 403 + the block body.

## What each gateway can do

| Gateway | Forwards the body? | What jev-edge can judge | Config |
|---|---|---|---|
| **Traefik** ≥ 3.3 ForwardAuth with `forwardBody: true` | yes, up to `maxBodySize` | everything: L1, L2, cache, L3 | [traefik.yml](traefik.yml) |
| **Caddy** `forward_auth` | no | path, method, IP reputation | [Caddyfile](Caddyfile) |
| **nginx** `auth_request` (plain nginx, no Lua) | no | path, method, IP reputation | [nginx-auth-request.conf](nginx-auth-request.conf) |

Without a body the verdict is `skipped` with reason `no body` and nothing is sent to Jev. A blocked IP is still denied: reputation is checked before anything that needs a body. Reputation only accumulates from paths that *do* judge bodies (Traefik with `forwardBody`, or the OpenResty `access()` / Envoy paths), and only when `async.rep_block_after` is set.

If you run Caddy or plain nginx and want real judgment, put jev-edge's OpenResty in the request path instead (`access_by_lua`) and let Caddy / nginx proxy to it.

Two rules every config here follows, whatever the gateway:

- **Strip inbound `X-Jev-*`.** The verdict headers are set by the gateway after the sub-request; a client must not be able to pre-fill them. The Caddyfile uses `request_header -X-Jev-*`, traefik.yml a `headers` middleware with empty `customRequestHeaders` ahead of `forwardAuth`, and nginx `proxy_set_header` for every header (an empty value removes it).
- **Fail-open means "not judged".** On a deny the gateway returns jev-edge's status and body (any status >= 400 with `X-Jev-Verdict`, 403 by default). When jev-edge is unreachable, Traefik and Caddy deny (there is no fail-open switch in forward-auth), and nginx's `auth_request` returns 500 unless you add `error_page 500 = @allow`-style handling; either way, an upstream request without `X-Jev-Verdict` was not judged. Keep `/_jev/config`, `/_jev/samples` and the other admin endpoints on a separate server block or port so they are never reachable through the gateway's path.

## Notes per gateway

**Traefik.** `authRequestHeaders` limits what is forwarded; keep `Content-Type` and `Content-Length` or L1 will not recognise the body. `authResponseHeaders` must list the `X-Jev-*` headers or they never reach your service. Traefik strips nothing on deny: a 403 from jev-edge is returned to the client with jev-edge's body.

**Caddy.** `forward_auth` rewrites the sub-request to `GET` with an empty body and sets `X-Forwarded-Method` / `X-Forwarded-Uri` itself. `copy_headers` lists the verdict headers. On non-2xx Caddy returns jev-edge's response to the client.

**nginx.** `auth_request` cannot forward a body (`proxy_pass_request_body off` is mandatory for the sub-request). Set `X-Original-URI $request_uri` and `X-Original-Method $request_method`, capture `$upstream_http_x_jev_*` with `auth_request_set`, and `proxy_set_header` them upstream. Apply `auth_request` only to watched locations; other requests then never touch jev-edge. Inside OpenResty itself the same wiring works with `$sent_http_x_jev_*` and a local `content_by_lua` location, but there `access_by_lua` is the better tool.

## End-to-end test

```bash
make e2e-forward-auth
```

Docker Compose with one jev-edge (mock provider), a stub app, and real Traefik v3.3, Caddy 2 and nginx 1.27. Checks: Traefik gets full L2 verdicts, a 403 for a malicious body and fail-open on provider failure; Caddy and nginx get `skipped` on watched paths without a body; after jev-edge is told the client IP is bad, both headers-only gateways deny it with 403.
