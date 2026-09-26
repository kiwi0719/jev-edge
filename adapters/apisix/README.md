# jev-edge for Apache APISIX

APISIX is OpenResty, so this is the same engine as the nginx adapter with an APISIX plugin contract around it: one Lua file, [apisix/plugins/jev-edge.lua](apisix/plugins/jev-edge.lua), that reuses the cache, provider client, breaker and L3 timer from `adapters/openresty` and maps APISIX's request API onto core. Nothing in `core/` changes; the golden vectors apply as they are.

Per route, per service or global, with the same keys as the Lua config file:

```json
{
  "jev-edge": {
    "jev": { "provider": "jev", "model": "jev-latest",
             "deployment_context": "A support assistant on Acme's billing website. ...",
             "timeout_ms": 400, "timeout_max_ms": 1000 },
    "rules": ["llm-endpoints"],
    "policy": { "mode": "monitor", "block_threshold": 0.7, "suspect_threshold": 0.5 }
  }
}
```

## Install

1. Put the repo where APISIX can see it and add three things to `conf/config.yaml`:

   ```yaml
   apisix:
     extra_lua_path: "/opt/jev-edge/adapters/apisix/?.lua;/opt/jev-edge/adapters/openresty/lib/?.lua;/opt/jev-edge/?.lua;/opt/jev-edge/?/init.lua"
   plugins:
     - jev-edge          # plus the plugins you already use
   nginx_config:
     envs:
       - TYPESAFE_API_KEY
     http:
       lua_shared_dict:
         jev_cache: 64m
   ```

   `lua-resty-http` ships with APISIX. Listing `plugins:` replaces the default list, so copy the defaults from `conf/config-default.yaml` and add `jev-edge`.

2. Start APISIX with `TYPESAFE_API_KEY` in its environment.

3. Enable the plugin on a route (Admin API, `apisix.yaml` in standalone mode, or the `ApisixRoute` CRD):

   ```bash
   curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/llm -H "X-API-KEY: $ADMIN_KEY" -d '{
     "uri": "/v1/*",
     "upstream": { "type": "roundrobin", "nodes": { "llm-backend:8000": 1 } },
     "plugins": { "jev-edge": {
       "jev": { "deployment_context": "...", "timeout_ms": 400 },
       "policy": { "mode": "monitor" }
     } }
   }'
   ```

Your upstream receives `X-Jev-Verdict`, `X-Jev-Score`, `X-Jev-Source`, `X-Jev-Reason` and `X-Jev-Request-Id`. In `enforce` mode a block is a 403 with `policy.block_body`, `X-Jev-Verdict` and `X-Jev-Request-Id` on the response; the score, reason and source go to the upstream and the log only, never to the client.

## What maps to what

| nginx adapter | APISIX plugin |
|---|---|
| `/etc/nginx/jev-edge.conf.lua` | the plugin conf on the route / service / global rule; same keys, JSON-schema validated |
| `access_by_lua_block` | `access` phase, priority 2450 (after the auth plugins, before `proxy-rewrite` and the `ai-*` plugins) |
| `env TYPESAFE_API_KEY;` | `nginx_config.envs`, read through `jev.api_key_env` (default `TYPESAFE_API_KEY`); or `jev.api_key` inline |
| `lua_shared_dict jev_cache` | `nginx_config.http.lua_shared_dict.jev_cache`; missing dict = cache and breaker state disabled, with a warning |
| `$jev_log` | `$jev_log`, registered as an APISIX variable: use it in `log_format` of `http-logger`, `file-logger`, `kafka-logger` |
| `PUT /_jev/config` hot reload | the Admin API: change the route's plugin conf, APISIX pushes it without a reload |
| `/_jev/health`, `/_jev/metrics` | not exposed; APISIX's own `prometheus` plugin and the logger carry the verdict fields |
| L3 side-path, reputation | same modules, same `async` config |
| inline tenant rules | same: `"rules": [{"id": "billing", "extends": "llm-endpoints", "watch_paths": ["^/v1/billing"], "deployment_context": "..."}, "llm-endpoints"]`; or simply one route per tenant, each with its own `jev.deployment_context` |
| `subject` | same keys; needs `nginx_config.http.lua_shared_dict.jev_subject` |
| `client_max_body_size`, `max_body_bytes` | `nginx_config.http.client_max_body_size` in `config.yaml` and `max_body_bytes` in the plugin `rules`; the body is read by the same `resty.jev.body` (whole up to 1 MiB, head and tail past it, `gzip` / `deflate` / `br` decoded; `br` needs `libbrotli1` in the image). See [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads) |
| `/_jev/samples` | `sampling` config is honoured and samples land in `jev_cache`; read them with `sampling.log = true` through a logger plugin, or expose `resty.jev.edge.samples()` from a plain OpenResty location on the same box |

One runtime (provider client, breaker, adaptive timeout) is built per distinct plugin conf and kept until the conf object changes, so routes with different `deployment_context` do not share a runtime. Breaker, adaptive timeout and in-flight counters are keyed by provider, endpoint and model, so routes calling the same provider share its health and a route with another provider does not. The runtime is keyed on the conf *table* APISIX hands the plugin, so a conf merged per consumer (`consumer` plugin config on top of the route's) is its own table and gets its own breaker and adaptive timeout; the same applies after every route update. Verdict-cache keys are scoped by rule, templates, deployment context, provider and model (`core.cache_key`), so a verdict is only reused where the same prompt would have been judged; operator trust is keyed by the text alone.

## Alongside `ai-prompt-guard`

APISIX's `ai-prompt-guard` is a regex allow / deny list on the prompt. It is L1-shaped: cheap, exact, blind to paraphrase. jev-edge is L2-shaped. They compose: put `ai-prompt-guard` first (higher priority) for the patterns you never want to reach a model, and jev-edge behind it for everything that gets through. Both see the same body.

## Test

```bash
make e2e-apisix
```

Real APISIX (`apache/apisix:3.13.0-debian`, standalone mode) in front of a stub app, mock provider, ten checks: skipped / safe / suspicious / blocked, block body and headers, inbound header stripping, fail-open on provider failure. Configs in [e2e/](e2e/).
