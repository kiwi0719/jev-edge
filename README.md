# jev-edge

**Typed-judgment admission control at the traffic edge.**

jev-edge sits in nginx / OpenResty (Envoy and Cloudflare adapters planned) and asks one question about incoming requests: *what is this request trying to do to my service?* It uses [TypeSafe Jev](https://typesafe.ai/) — a System One model that returns probabilities instead of prose — to catch prompt injection and abuse at the entry point of LLM-backed applications, before the request ever reaches your backend.

It is built for SREs and platform engineers, not agent authors. Existing Jev guards run on the developer's machine and judge what an AI is about to do; jev-edge runs at the gateway and judges what the outside world is about to do.

> **Status:** M1 done (core logic + unit tests), OpenResty adapter next. See [DESIGN.md](DESIGN.md) (Chinese) for the full plan. Nothing here is production-ready yet.

## How it works

Three filters, ordered by cost. Most traffic never pays for the expensive one.

```
L1  cheap rules        99% of normal traffic passes here, zero added latency
    ↓ suspicious 1%
L2  Jev sync judgment  70–500 ms, hard cut at 300 ms, spent only on this slice
    ↓ ambiguous
L3  async side-path    never blocks the response; feeds reputation + alerts
```

Guarantees the project is built around:

- **Fail-open.** Jev slow or down → traffic flows, a log line fires. A circuit breaker stops the gateway from waiting 300 ms per request when the API is unhealthy.
- **Shared-dict cache.** Normalized body fingerprints are reused within a TTL; scrapers and replay abuse are highly repetitive.
- **Verdict headers.** `X-Jev-Verdict` and `X-Jev-Score` are passed to the upstream so the application can make its own second decision instead of getting only allow/deny.
- **Hot-reloadable thresholds.** Flip from `enforce` to `monitor` with one local PUT, no nginx reload.
- **Pluggable judgment backend.** A provider is two functions (`build_request`, `parse_response`). Ships with `jev` (TypeSafe), `openai-compat` (any chat endpoint) and `mock` (tests / bench).

## Quick look (target API)

```nginx
lua_shared_dict jev_cache  64m;
lua_shared_dict jev_config  1m;
env TYPESAFE_API_KEY;

init_by_lua_block        { require("resty.jev.edge").init("/etc/nginx/jev-edge.conf.lua") }
init_worker_by_lua_block { require("resty.jev.edge").init_worker() }

location /v1/ {
    access_by_lua_block { require("resty.jev.edge").access() }
    proxy_pass http://llm_backend;
}
```

```lua
-- /etc/nginx/jev-edge.conf.lua
return {
  jev    = { provider = "jev", model = "jev-latest", timeout_ms = 300 },
  rules  = { "llm-endpoints" },
  policy = { mode = "monitor", block_threshold = 0.85, suspect_threshold = 0.5 },
}
```

Start in `monitor` mode. Look at the headers and logs for a week. Then decide your thresholds on your own traffic — no default threshold is a measured operating point.

## Repository layout

```
core/       judgment logic, question templates, policy — no ngx.* dependency, unit-tested with busted
adapters/   openresty/ (first), cloudflare/, envoy/
rules/      L1 rule sets, CRS-style
bench/      false-positive rate, miss rate, P99 under normal / slow-Jev / dead-Jev scenarios
```

## Roadmap

| Milestone | Scope |
|---|---|
| M1 ✅ | core skeleton: normalize, rules, policy, breaker; busted green |
| M2 | OpenResty access path with mock provider, headers, fail-open |
| M3 | shared-dict cache, circuit breaker, L3 async timer |
| M4 | hot reload, config API, Prometheus metrics |
| M5 | bench datasets + report |
| M6 | v0.1.0 on opm as `lua-resty-jev-edge` |
| v0.2 | `/_jev/authz` endpoint → Envoy HTTP ext_authz for free |

## Non-goals

- Replacing a traditional WAF. SQLi, path traversal and scanners belong to CRS / ModSecurity, which are faster and better at it.
- Response-side content filtering.
- Training or hosting a judgment model.

## Contributing

Issues and PRs are welcome. Read [DESIGN.md](DESIGN.md) first; decisions recorded there are settled unless a PR argues otherwise with bench data.

## License

[MIT](LICENSE). Not affiliated with or endorsed by TypeSafe AI.
