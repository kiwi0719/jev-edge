# jev-edge for Kong Gateway

Kong is OpenResty too, so this is the same engine as the nginx adapter with a Kong plugin contract around it: two Lua files, [kong/plugins/jev-edge/handler.lua](kong/plugins/jev-edge/handler.lua) and [schema.lua](kong/plugins/jev-edge/schema.lua), that reuse the cache, provider client, breaker, body reader and L3 timer from `adapters/openresty` and map Kong's PDK onto core. Nothing in `core/` changes; the golden vectors apply as they are. Tested against Kong 3.9 (OSS, DB-less).

On a route, service, consumer or globally, with the same keys as the Lua config file (declarative `kong.yml` shown; the Admin API takes the same `config` object):

```yaml
plugins:
  - name: jev-edge
    route: llm
    config:
      jev:
        provider: jev
        model: jev-latest
        deployment_context: "A support assistant on Acme's billing website. ..."
        timeout_ms: 400
        timeout_max_ms: 1000
      rules: ["llm-endpoints"]
      policy: { mode: monitor, block_threshold: 0.7, suspect_threshold: 0.5 }
```

## Install

1. Put the Lua sources on Kong's path. Either from a checkout:

   ```bash
   KONG_LUA_PACKAGE_PATH="/opt/jev-edge/adapters/kong/?.lua;/opt/jev-edge/adapters/openresty/lib/?.lua;/opt/jev-edge/?.lua;/opt/jev-edge/?/init.lua;;"
   ```

   or with the rock, which installs core, rules and the `resty.jev.*` modules flattened (`jev.core`, `jev.rules.*`), plus the plugin directory from a checkout:

   ```bash
   luarocks install lua-resty-jev-edge
   KONG_LUA_PACKAGE_PATH="/opt/jev-edge/adapters/kong/?.lua;;"
   ```

   (or copy `adapters/kong/kong/plugins/jev-edge/` to `kong/plugins/jev-edge/` anywhere on the path). The trailing `;;` keeps Kong's own path. `lua-resty-http` ships with Kong.

2. Enable the plugin and declare the shared dict and the key's environment variable, in `kong.conf` or as `KONG_*` variables:

   ```bash
   KONG_PLUGINS=bundled,jev-edge
   KONG_NGINX_HTTP_LUA_SHARED_DICT="jev_cache 64m"     # kong.conf: nginx_http_lua_shared_dict = jev_cache 64m
   KONG_NGINX_MAIN_ENV=TYPESAFE_API_KEY                 # kong.conf: nginx_main_env = TYPESAFE_API_KEY
   ```

   Kong turns each `nginx_http_<directive>` into one `<directive> <value>;` line, so a second dict (for `subject`) rides on the same value: `"jev_cache 64m; lua_shared_dict jev_subject 16m"`. A custom nginx template works too. Instead of the environment variable, `jev.api_key` is referenceable: `api_key: "{vault://env/typesafe-api-key}"`.

3. Start Kong with `TYPESAFE_API_KEY` in its environment and add the plugin to a route or service (above).

Your upstream receives `X-Jev-Verdict`, `X-Jev-Score`, `X-Jev-Source`, `X-Jev-Reason` and `X-Jev-Request-Id`; the same headers sent by the client are removed first. In `enforce` mode a block is `policy.block_status` (403) with `policy.block_body`, `X-Jev-Verdict` and `X-Jev-Request-Id` on the response, via `kong.response.exit`; the score, reason and source go to the upstream and the log only, never to the client. Any error in the plugin fails open: the request goes upstream with `X-Jev-Verdict: error` and `X-Jev-Source: adapter`, and the error is in Kong's error log.

## What maps to what

| nginx adapter / APISIX plugin | Kong plugin |
|---|---|
| `/etc/nginx/jev-edge.conf.lua`, APISIX plugin conf | plugin `config`, validated by `schema.lua`; same keys: `jev`, `rules`, `policy`, `cache`, `breaker`, `async`, `subject`, `sampling`. No schema defaults: unset keys take core's defaults (`core/defaults.lua`), and core's cross-field checks (threshold order, `timeout_max_ms >= timeout_ms`, subject salt) run as an entity check, so a bad config is refused at load, not at request time |
| `rules`: ids or inline tables in one list | `rules`: array of rule set ids; `rules_json`: the full list as a JSON string, ids and inline tables mixed, exactly the APISIX / Lua-config value, and it replaces `rules` when set. Kong's schema has no "string or record" element type. Example: `rules_json: '[{"id":"billing","extends":"llm-endpoints","watch_paths":["^/v1/billing"]},"llm-endpoints"]'` |
| `access_by_lua_block`, APISIX priority 2450 | `access` phase, `PRIORITY = 905`: after authentication (`key-auth` 1250, `jwt` 1450, ...), `ip-restriction` 990, `request-size-limiting` 951, `acl` 950 and `rate-limiting` 910, so refused requests never cost a judge call; before `request-transformer` 801 and the `ai-*` plugins (770s), so the judged body is the client's and `ai-proxy` only sees admitted requests |
| `env TYPESAFE_API_KEY;` | `nginx_main_env`, read through `jev.api_key_env` (default `TYPESAFE_API_KEY`); or `jev.api_key` inline or as a vault reference |
| `lua_shared_dict jev_cache` | `nginx_http_lua_shared_dict`; missing dict = cache and breaker state disabled, with a warning |
| client address | `kong.client.get_forwarded_ip()`: honours `trusted_ips`, `real_ip_header` and `real_ip_recursive` |
| request path | `ngx.var.uri`, fully decoded and normalised, as the nginx adapter and APISIX match `watch_paths`. Not `kong.request.get_path()`, which keeps reserved escapes: `/v1%2Fchat/completions` would miss `^/v1/chat` and be skipped, while Kong forwards it as is and a backend that decodes `%2F` (uvicorn / Starlette) serves the chat endpoint |
| request body | the same `resty.jev.body` on `ngx.req`, not `kong.request.get_raw_body()`, which returns nil once nginx has spooled the body to disk (past `nginx_http_client_body_buffer_size`, 8k by default). Whole up to `max_body_bytes`, head and tail past it, `gzip` / `deflate` / `br` decoded (the `kong` image has zlib and libbrotlidec). Raise `nginx_http_client_max_body_size` for long-context traffic. See [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads) |
| `$jev_log` | the decision is added to Kong's log serializer as `jev` (`kong.log.set_serialize_value`), so `http-log`, `file-log`, `tcp-log`, `kafka-log` ... carry it with no extra config. `log_line: true` also writes it as one JSON line to the error log at NOTICE |
| `PUT /_jev/config` hot reload | the Admin API or a new declarative config: Kong rebuilds the plugin conf and the plugin builds a new runtime for it |
| `/_jev/health`, `/_jev/metrics`, `/_jev/feedback` | not exposed; Kong's `prometheus` plugin and the log serializer carry the verdict fields |
| L3 side-path, reputation | same modules, same `async` config. IP reputation (`rep:<ip>` in `jev_cache`) is one namespace for every plugin instance: a plugin instance blocks on it only with its own `async.rep_block_after > 0`, and those that turn it on block the IPs any of them flagged |
| `subject` | same keys; `from = "ip"` uses the forwarded IP; needs the `jev_subject` dict |
| `/_jev/samples` | `sampling` is honoured and samples land in `jev_cache`; read them with `sampling.log = true`, or expose `resty.jev.edge.samples()` from a plain OpenResty location on the same box |

One runtime (provider client, breaker, adaptive timeout) is built per plugin conf table and kept until Kong hands over a new one (config change, declarative reload). Breaker, adaptive timeout and in-flight counters are keyed by provider, endpoint and model, so plugin instances calling the same provider share its health. Verdict-cache keys are scoped by rule, templates, deployment context, provider and model (`core.cache_key`).

## Not supported

- `ai-prompt-guard` ordering: Kong OSS runs plugins by static priority, and `ai-prompt-guard` (771) runs after jev-edge (905). On APISIX the regex guard can go first; on Kong OSS it cannot without dynamic plugin ordering (Enterprise). Both still see the same body; the only cost is that a request the guard would reject may be judged first.
- Stream routes (`tcp`, `tls`, `udp`): the plugin declares Kong's HTTP protocols only.
- The admin endpoints of the nginx adapter (`/_jev/*`), as above.
- A Kong-specific rock: `luarocks install lua-resty-jev-edge` installs the engine, the plugin directory comes from the repo.

## Test

```bash
make e2e-kong
```

Real Kong (`kong:3.9`, DB-less, declarative [e2e/kong.yml](e2e/kong.yml)) in front of a stub app, mock provider, twenty-one checks: skipped / safe / suspicious / blocked, `/v1%2Fchat/completions` (and `%2f`) judged like `/v1/chat/completions`, block body and headers, inbound header stripping, fail-open on provider failure, GET at L1, gzip bodies decoded and judged, a body spooled to disk read and blocked, an inline tenant rule through `rules_json`, and the decision log line. Configs in [e2e/](e2e/).
