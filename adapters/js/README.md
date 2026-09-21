# jev-edge for JavaScript runtimes

One npm package, `@jev-edge/js`, one TypeScript port of core, several hosts. The port is held to the repository's golden vectors: [test/golden.test.ts](test/golden.test.ts) replays [core/golden/*.json](../../core/golden/README.md), the same files the Lua core replays under busted. A verdict computed here and one computed on nginx for the same request are the same verdict.

```
npm install @jev-edge/js      # or pnpm add / yarn add
```

| host | export | what it is |
|---|---|---|
| Cloudflare Workers, in front of a jev-edge you already run | `thinWorker` | L1 and the fingerprint cache at the edge, judgment via your origin's `/_jev/authz`; one set of thresholds, kept at the origin |
| Cloudflare Workers, standalone | `fullWorker` | the whole core in the Worker; KV cache, Durable Object breaker and adaptive timeout, TypeSafe or OpenAI-compatible provider |
| Cloudflare Pages | `pagesMiddleware` | `fullWorker` as a Pages Functions middleware |
| Next.js (Vercel edge or Node runtime) | `nextMiddleware` | `middleware.ts` export; allowed requests continue with `X-Jev-*` on the request headers |
| Node: Express, Connect, Fastify raw | `nodeMiddleware` | `(req, res, next)`; verdict on `req.jev` and `req.headers` |
| Hono, and anything with a `Request` in its context | `honoMiddleware` | `c.get("jev")` in handlers |
| AWS Lambda@Edge (CloudFront viewer-request / origin-request) | `lambdaEdgeHandler` | returns the request with headers or a 403 response |
| anything else | `createRuntime` + `handle` / `evaluate` | the primitives the presets are built from |

All V8 hosts, so one golden-vector column covers them. What differs per host is the request shape and which store backs the cache and breaker state; the table under [What is the same as nginx](#what-is-the-same-as-nginx-and-what-is-not) has the details.

## Cloudflare

### Thin Worker

```ts
// src/worker.ts
import { thinWorker } from "@jev-edge/js";
export default thinWorker({ config: { policy: { mode: "enforce" } } });
```

```toml
# wrangler.toml
[vars]
JEV_ORIGIN = "https://gateway.example.com"   # the jev-edge you already run
```

Per request the Worker runs L1 (watch paths, method, content type, body size, `always_suspect` patterns, reputation) and checks its fingerprint cache. Only requests that would reach L2 are sent to the origin's `/_jev/authz/<path>` with the body and `X-Forwarded-For`, exactly as Envoy sends them. A 403 from the origin is a block at the edge; `X-Jev-Verdict: error` from the origin fails open. Set `upstream` when the app is not behind the same host as the gateway; bind `JEV_CACHE` (KV) to share the cache across isolates. [wrangler.thin.toml](wrangler.thin.toml), [examples/thin.ts](examples/thin.ts).

### Full Worker

```ts
import { fullWorker, JevState } from "@jev-edge/js";
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

`wrangler secret put TYPESAFE_API_KEY`. The config object has the same keys as the Lua config file, so the [deployment context guidance](../../README.md#writing-the-deployment-context) applies unchanged. `provider: "openai-compat"` with `endpoint` and `model` uses any OpenAI-style chat endpoint; `provider: "mock"` with `mock_score` runs without a network call. Without `JEV_CACHE` the cache is per isolate; without `JEV_STATE` the breaker and adaptive timeout are per isolate too. [wrangler.full.toml](wrangler.full.toml), [examples/full.ts](examples/full.ts).

### Pages

```ts
// functions/_middleware.ts
import { pagesMiddleware, JevState } from "@jev-edge/js";
export { JevState };
export const onRequest = pagesMiddleware({ config: { jev: { provider: "jev", deployment_context: "…", timeout_ms: 400 } } });
```

## Next.js

```ts
// middleware.ts
import { NextResponse } from "next/server";
import { nextMiddleware } from "@jev-edge/js";

export const middleware = nextMiddleware(
  { config: { jev: { provider: "jev", api_key: process.env.TYPESAFE_API_KEY, deployment_context: "…", timeout_ms: 400 }, policy: { mode: "monitor" } } },
  NextResponse,
);
export const config = { matcher: ["/api/chat/:path*", "/v1/:path*"] };
```

Next buffers the body for middleware on both runtimes, so the whole pipeline runs there. Route handlers read `X-Jev-Verdict` and `X-Jev-Score` from the request headers. On Vercel the edge runtime is V8 and the cache is per isolate; pass a `cache` Store (Vercel KV, Upstash) in the options to share it. [examples/next-middleware.ts](examples/next-middleware.ts).

## Node

```ts
import express from "express";
import { nodeMiddleware } from "@jev-edge/js";

const app = express();
app.use("/v1", nodeMiddleware({ config: { jev: { provider: "jev", api_key: process.env.TYPESAFE_API_KEY, deployment_context: "…", timeout_ms: 400 } } }));
app.post("/v1/chat/completions", (req, res) => { /* req.jev, req.headers["x-jev-verdict"] */ });
```

Mount it before the routes that carry natural language. If `express.json()` ran first the parsed body is re-serialised for evaluation; otherwise the stream is read (up to `max_body_bytes`) and exposed as `req.body` for the handlers. A block ends the response with the 403; a middleware error fails open with `x-jev-verdict: error`.

## Hono

```ts
import { Hono } from "hono";
import { honoMiddleware } from "@jev-edge/js";
const app = new Hono();
app.use("/v1/*", honoMiddleware({ config: { … } }));
app.post("/v1/chat/completions", (c) => c.json({ verdict: c.get("jev") }));
```

## AWS Lambda@Edge

```ts
// handler.ts, deployed in us-east-1 and attached to the viewer-request trigger with "Include Body"
import { lambdaEdgeHandler } from "@jev-edge/js/aws";
export const handler = lambdaEdgeHandler({
  config: { jev: { provider: "jev", api_key: "<from Secrets Manager at cold start>", deployment_context: "…", timeout_ms: 400 }, policy: { mode: "monitor" } },
});
```

CloudFront hands the body over base64-encoded, truncated at 40 KB on viewer-request (1 MB on origin-request) with `bodyTruncated` set. A truncated body passes at L1 as `body too large` and the full body still reaches the origin; that is the same fail-open the other adapters apply. Lambda@Edge has no environment variables, no VPC and no KV: cache, breaker and adaptive timeout are per execution environment unless you pass Store implementations (DynamoDB Global Tables is the usual choice, at a round trip per lookup). API Gateway's Lambda authorizer and CloudFront Functions do not see the body and are not supported; [the recipes page](../../docs/recipes.md) explains what a headers-only integration can and cannot do. [examples/lambda-edge.ts](examples/lambda-edge.ts).

## Any other framework

`handle(request, runtime, next)` is what the presets wrap:

```ts
import { createRuntime, handle } from "@jev-edge/js";
const rt = createRuntime({ config: { … }, cache: env.JEV_CACHE, state: env.JEV_STATE.get(env.JEV_STATE.idFromName("jev-edge")) });
return handle(request, rt, (req) => fetch(req));
```

`evaluate(request, rt)` returns the verdict without forwarding. `GET /_jev/health` is served by `handle` unless `health: false`.

**Tenants and sampling.** `rules` accepts rule set ids, complete `Rule` objects, or `{ id, extends, watch_paths, deployment_context, ... }` inline rules, first match wins, same as the Lua config. `config.sampling` plus an `onSample(sample, request)` option gives you the sampled decisions (normalized text, fingerprint, score, verdict); write them to KV, a log or an analytics binding. There is no `/_jev/samples` endpoint here because storage is yours.

## What is the same as nginx, and what is not

Same, guaranteed by the golden vectors: text extraction, normalisation and fingerprints, every L1 decision, thresholds and the async flag, verdict headers and reason encoding, the order L1 / cache / breaker / L2. Same by construction: provider request bodies (the `jev` and `openai-compat` providers build the same JSON as the Lua ones), config keys and defaults, `/_jev/health`.

Different, by platform:

| | cache | breaker + adaptive timeout | notes |
|---|---|---|---|
| nginx / APISIX | shared dict, exact TTL, all workers | shared dict | reference |
| Cloudflare Workers | KV: 60 s minimum TTL, eventually consistent | Durable Object, one hop per L2 call | per isolate without the bindings |
| Next.js on Vercel, Node, Hono | memory per process / isolate | memory | pass a `Store` to share |
| Lambda@Edge | memory per execution environment | memory | no env vars; key from Secrets Manager |

- **Fingerprint hash.** nginx uses `crc32_long`; this package uses the reference `djb2`. Caches are never shared between the two, so it does not matter.
- **No `/_jev/config` hot reload.** Config is code; redeploy, or read it from your store in an options function.
- **No L3 side-path yet.** `verdict.async` is set; nothing consumes it.
- **Body size.** Requests over the largest `max_body_bytes` (64 KB by default) are not read; L1 passes them with `body too large` from `Content-Length`.

## Development

```
pnpm install
pnpm test          # 116 golden cases + worker and host tests
pnpm typecheck
pnpm build         # dist/ for publishing
```

`pnpm golden` runs only the parity suite. When `core/golden/*.json` changes upstream, this suite is what tells you the port has to follow.
