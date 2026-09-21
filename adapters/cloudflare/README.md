# jev-edge for Cloudflare

One npm package, the same core as the OpenResty adapter, three ways to run it. Which one you want depends on what you already have:

| you have | you want | use |
|---|---|---|
| jev-edge on OpenResty or Envoy, Cloudflare as CDN in front | the edge to agree with the origin: one set of thresholds, one deployment context | **`thinWorker`**: L1 rules and the fingerprint cache at the edge, judgment via your origin's `/_jev/authz` |
| Workers and nothing else | something that runs on its own | **`fullWorker`**: the whole core in the Worker; KV for the cache, a Durable Object for breaker and adaptive timeout, TypeSafe or any OpenAI-compatible endpoint as provider |
| a Pages project (Next.js, Remix, Astro, …) | one middleware line | **`pagesMiddleware`**: `fullWorker` as a Pages Functions middleware |

All three call the same `evaluate()` in [src/core](src/core), which is held to the repository's golden vectors: [test/golden.test.ts](test/golden.test.ts) replays [core/golden/*.json](../../core/golden/README.md), the same files the Lua core replays under busted. A verdict computed here and one computed on nginx for the same request are the same verdict.

```
npm install @jev-edge/cloudflare      # or pnpm add / yarn add
```

## Thin Worker

```ts
// src/worker.ts
import { thinWorker } from "@jev-edge/cloudflare";
export default thinWorker({ config: { policy: { mode: "enforce" } } });
```

```toml
# wrangler.toml
[vars]
JEV_ORIGIN = "https://gateway.example.com"   # the jev-edge you already run
```

Per request the Worker runs L1 (watch paths, method, content type, body size, `always_suspect` patterns, reputation) and checks its fingerprint cache. Only requests that would reach L2 are sent to the origin's `/_jev/authz/<path>` with the body and `X-Forwarded-For`, exactly as Envoy sends them. The origin answers with `X-Jev-*` headers or a 403; the Worker applies its own `policy.mode` to the score and forwards to the upstream with the headers attached. A 403 from the origin is a block at the edge; `X-Jev-Verdict: error` from the origin fails open, like everywhere else.

What stays at the origin: thresholds, the deployment context, the provider key, `/_jev/config` hot reload, `/_jev/metrics`, L3 reputation. What the Worker adds: L1 rejection of unwatched traffic before it leaves Cloudflare, and a cache hit for replays. Set `upstream` when the app is not behind the same host as the gateway. Bind `JEV_CACHE` (KV) if you want the cache shared across isolates; without it each isolate keeps a memory cache and the origin's cache still applies. [wrangler.thin.toml](wrangler.thin.toml), [examples/thin.ts](examples/thin.ts).

## Full Worker

```ts
import { fullWorker, JevState } from "@jev-edge/cloudflare";
export { JevState };
export default fullWorker({
  upstream: "https://app.internal.example.com",
  config: {
    jev: { provider: "jev", deployment_context: "…", timeout_ms: 400, timeout_max_ms: 1000 },
    policy: { mode: "monitor", block_threshold: 0.7, suspect_threshold: 0.5 },
  },
});
```

```toml
[[kv_namespaces]]
binding = "JEV_CACHE"
id = "…"
[[durable_objects.bindings]]
name = "JEV_STATE"
class_name = "JevState"
[[migrations]]
tag = "v1"
new_sqlite_classes = ["JevState"]
```

`wrangler secret put TYPESAFE_API_KEY`. The config object has the same keys as the Lua config file, so the [deployment context guidance](../../README.md#writing-the-deployment-context) applies unchanged. `provider: "openai-compat"` with `endpoint` and `model` uses any OpenAI-style chat endpoint instead; `provider: "mock"` with `mock_score` runs without a network call for tests. [wrangler.full.toml](wrangler.full.toml), [examples/full.ts](examples/full.ts).

**Bindings and what they change.** Without `JEV_CACHE` the fingerprint cache is per isolate. Without `JEV_STATE` the breaker and the adaptive timeout are per isolate too, which means each isolate has to see `breaker.min_samples` failures on its own before it stops calling a dead provider. Both bindings are optional and both are recommended in production.

## Pages middleware

```ts
// functions/_middleware.ts
import { pagesMiddleware, JevState } from "@jev-edge/cloudflare";
export { JevState };
export const onRequest = pagesMiddleware({ config: { jev: { provider: "jev", deployment_context: "…", timeout_ms: 400 } } });
```

Same runtime and bindings as the full Worker. Allowed requests continue to your Pages Functions and static assets with `X-Jev-*` on the request; blocked ones get the 403 from the middleware. [examples/pages-middleware.ts](examples/pages-middleware.ts).

## Any other framework

`handle(request, runtime, next)` is what the presets wrap:

```ts
import { createRuntime, handle } from "@jev-edge/cloudflare";
const rt = createRuntime({ config: { … }, cache: env.JEV_CACHE, state: env.JEV_STATE.get(env.JEV_STATE.idFromName("jev-edge")) });
return handle(request, rt, (req) => fetch(req));
```

`evaluate(request, rt)` returns the verdict without forwarding, for code that wants to make its own decision. `GET /_jev/health` is served by `handle` unless `health: false`.

## What is the same as nginx, and what is not

Same, guaranteed by the golden vectors: text extraction, normalisation and fingerprints, every L1 decision, thresholds and the async flag, verdict headers and reason encoding, the order L1 / cache / breaker / L2. Same by construction: provider request bodies (the `jev` and `openai-compat` providers build the same JSON as the Lua ones), config keys and defaults, `/_jev/health`.

Different, by platform:

- **Cache TTL.** KV's minimum TTL is 60 s and it is eventually consistent; `cache.fp_ttl` below 60 becomes 60, and a fresh verdict can take a moment to be visible in every location. A shared dict on nginx is exact and immediate.
- **Breaker and adaptive timeout.** On nginx every worker shares one dict. Here they share a Durable Object, which is a network hop per L2 call. Without the binding they are per isolate.
- **Fingerprint hash.** nginx uses `crc32_long`; this adapter uses the reference `djb2`. Fingerprints are not comparable across the two, which only matters if you try to share a cache between them. You cannot, so it does not.
- **No `/_jev/config` hot reload.** Config is code here; redeploy or read it from KV yourself in the options function.
- **No L3 side-path yet.** `verdict.async` is set; nothing consumes it. Reputation entries written by a nginx L3 are read by the thin Worker only if you share nothing, so they are not: the origin applies them on its own side.
- **Body size.** Requests over the largest `max_body_bytes` (64 KB by default) are not read at all; L1 passes them with `body too large` from the `Content-Length` header.

## Development

```
pnpm install
pnpm test          # 116 golden cases + worker tests
pnpm typecheck
pnpm build         # dist/ for publishing
```

`pnpm golden` runs only the parity suite. When `core/golden/*.json` changes upstream, this suite is what tells you the port has to follow.
