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
       custom_lua_shared_dict:
         jev_cache: 64m
         # jev_subject: 16m       # with subject
         # jev_subject_rep: 4m    # with subject.reputation
   ```

   The dicts go under `custom_lua_shared_dict`: APISIX's nginx template renders only its own dicts from `lua_shared_dict`, so jev-edge's would be dropped, leaving it with no verdict cache, no breaker, no in-flight cap and no reputation (the plugin logs an error at startup when `jev_cache` is missing). `lua-resty-http` ships with APISIX. Listing `plugins:` replaces the default list, so copy the defaults from `conf/config-default.yaml` and add `jev-edge`.

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

**Where to put it.** Put jev-edge on routes, services or plugin configs behind your authentication, not only in a global rule: a global rule runs before a route's rewrite-phase auth plugins, so it judges (and charges reputation for) requests that auth would have refused. A global rule leaves alone a request that matched no route, and APISIX answers it 404 as usual.

**Watch the path the client sends.** `watch_paths` match `ctx.var.uri`, the client-facing path, before `proxy-rewrite`. On a route that serves an LLM under a prefix of its own (`/openai-chat`, an `ai-proxy` route), the default `llm-endpoints` paths match nothing: scope a rule to the route, `"rules": [{"id": "route", "extends": "llm-endpoints", "watch_paths": ["^/"]}]`.

Your upstream receives `X-Jev-Verdict`, `X-Jev-Score`, `X-Jev-Source`, `X-Jev-Reason` and `X-Jev-Request-Id`. In `enforce` mode a block is a 403 with `policy.block_body`, `X-Jev-Verdict` and `X-Jev-Request-Id` on the response; the score, reason and source go to the upstream and the log only, never to the client.

## What maps to what

| nginx adapter | APISIX plugin |
|---|---|
| `/etc/nginx/jev-edge.conf.lua` | the plugin conf on the route / service / consumer / global rule; same keys, JSON-schema validated, then checked by core's validation and rule resolution, so a misspelt rule set id or a broken inline rule refuses the conf and the route is not loaded |
| which conf applies | one per request, in APISIX's order: consumer > consumer group > route > plugin_config > service. A consumer-level conf replaces the route's whole, with no field-level merge, so it must repeat `jev`, `rules`, `policy.mode` and `subject`; a key it leaves out takes core's default (`policy.mode = "monitor"`). The plugin declares `run_policy = "prefer_route"`: where the matched route (with its service and plugin config) carries jev-edge, a global rule's jev-edge is skipped, and a second run in the same request (two global rules, a consumer conf) reuses the first verdict, so a request is judged and charged once. A route whose own jev-edge carries a `_meta.filter` that does not match a request is judged by neither |
| `access_by_lua_block` | `access` phase, priority 1000: after every rewrite-phase plugin (auth, `proxy-rewrite`, `ai-prompt-decorator`, `ai-prompt-template`, `body-transformer`) and after the access-phase gatekeepers (`consumer-restriction`, `forward-auth`, `opa`, `authz-keycloak`), `ai-prompt-guard`, `ai-rate-limiting` and the `limit-*` plugins, so a request they refuse costs no judge call; `ai-proxy` calls the model later, in `before_proxy`. `ai-request-rewrite` (1073) calls its LLM before jev-edge; raise jev-edge with `_meta.priority` if it must judge the client's text first |
| `env TYPESAFE_API_KEY;` | `nginx_config.envs`, read through `jev.api_key_env` (default `TYPESAFE_API_KEY`); or `jev.api_key` inline, or as an APISIX secret reference (`"$env://NAME"`, `"$secret://vault/1/jev/api_key"`), resolved for each plugin conf and read again every five minutes, so a rotated secret is picked up. A reference that does not resolve is logged and never sent: `jev.api_key_env` applies. `jev.api_key` and `subject.salt` (which takes references too) are `encrypt_fields`: with `apisix.data_encryption` on (the default) etcd keeps them encrypted |
| `lua_shared_dict jev_cache` | `nginx_config.http.custom_lua_shared_dict.jev_cache`; missing dict = cache and breaker state disabled, with an error at startup |
| `$jev_log` | `$jev_log`, registered as an APISIX variable: use it in `log_format` of `http-logger`, `file-logger`, `kafka-logger` |
| `PUT /_jev/config` hot reload | the Admin API: change the route's plugin conf, APISIX pushes it without a reload |
| `/_jev/health`, `/_jev/metrics` | not exposed; APISIX's own `prometheus` plugin and the logger carry the verdict fields |
| L3 side-path, reputation | same modules, same `async` config. IP reputation (`rep:<ip>` in `jev_cache`) is one namespace for every route: a route blocks on it only with its own `async.rep_block_after > 0`, and those that turn it on block the IPs any of them flagged |
| inline tenant rules | same: `"rules": [{"id": "billing", "extends": "llm-endpoints", "watch_paths": ["^/v1/billing"], "deployment_context": "..."}, "llm-endpoints"]`; or simply one route per tenant, each with its own `jev.deployment_context` |
| `subject` | same keys; needs `nginx_config.http.custom_lua_shared_dict.jev_subject` (trajectories: never evicts, drops new entries when full), and `jev_subject_rep` with `reputation` (points and blocks; without it they share `jev_subject`, with a warning). If a `$env://` or `$secret://` reference for `subject.salt` does not resolve, it is never used as the salt: subject tracking and subject reputation are off for that conf, with an error in the log, until it resolves |
| `client_max_body_size`, `max_body_bytes` | `nginx_config.http.client_max_body_size` in `config.yaml` and `max_body_bytes` in the plugin `rules`; the body is read by the same `resty.jev.body` (whole up to 1 MiB, head and tail past it, `gzip` / `deflate` / `br` decoded; `br` needs `libbrotli1` in the image). See [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads) |
| `/_jev/samples` | `sampling` config is honoured and samples land in `jev_cache`; read them with `sampling.log = true` through a logger plugin, or expose `resty.jev.edge.samples()` from a plain OpenResty location on the same box |

One runtime (provider client, breaker, adaptive timeout) is built per distinct plugin conf and kept until the conf object changes or a resolved secret does, so routes with different `deployment_context` do not share a runtime. Breaker, adaptive timeout and in-flight counters are keyed by provider, endpoint, model, a hash of the key, `max_inflight` and the breaker settings, so routes share them only when all of those match: a route with a revoked key opens its own breaker, not its neighbours'. Verdict-cache keys are scoped by rule, templates, deployment context, provider, model, and when set the endpoint and question wording (`core.cache_key`), so a verdict is only reused where the same prompt would have been judged; operator trust is keyed by the text alone. A route that names a rule set the node does not have is refused at load; one whose rule still fails to load at run time answers `X-Jev-Verdict: error` naming it (403 with `policy.unjudgeable = "block"` in enforce), never "no rules".

## Alongside `ai-prompt-guard`

APISIX's `ai-prompt-guard` is a regex allow / deny list on the prompt. It is L1-shaped: cheap, exact, blind to paraphrase. jev-edge is L2-shaped. They compose: put `ai-prompt-guard` first (higher priority) for the patterns you never want to reach a model, and jev-edge behind it for everything that gets through. Both see the same body.

## Test

```bash
make e2e-apisix
```

Real APISIX (`apache/apisix:3.13.0-debian`, standalone mode) in front of a stub app, mock provider, about fifty checks: skipped / safe / suspicious / blocked, block body and headers (no score, reason or source), inbound header stripping, fail-open on provider failure, the verdict cache through `custom_lua_shared_dict`, ordering after `limit-count`, a global rule with routes and consumers judged once, an unrouted request left to APISIX, `$env://` secrets, a revoked key opening only its own route's breaker, subject reputation, provider `laya`, and a missing or broken rule set refused at load. Configs in [e2e/](e2e/).
