# jev-edge for JavaScript runtimes

One npm package, `@jev-edge/js`, one TypeScript port of core, several hosts. The port is held to the repository's golden vectors: [test/golden.test.ts](test/golden.test.ts) replays [core/golden/*.json](../../core/golden/README.md), the same files the Lua core replays under busted. A verdict computed here and one computed on nginx for the same request are the same verdict.

```
npm install @jev-edge/js      # or pnpm add / yarn add; Node 20+ (global crypto)
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
| Deno Deploy, `Deno.serve` | `denoHandler` | the whole core in the isolate, proxying to `upstream`; optional Deno KV store (`denoKvStore`) |
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

Per request the Worker runs L1 (watch paths, method, content type, body size, `always_suspect` patterns, reputation) and checks its fingerprint cache. Only requests that would reach L2 are sent to the origin's `/_jev/authz/<path>` with the body and `X-Forwarded-For`, exactly as Envoy sends them. A block from the origin, any 4xx carrying `X-Jev-Verdict` (so a `policy.block_status` of 429 or 451 too), is a block at the edge whatever the Worker's own thresholds, and is cached as one; a 4xx without `X-Jev-Verdict` is not jev-edge's answer and fails open. So does a 200 the origin did not judge (`X-Jev-Verdict: skipped` while its breaker is open, `error`, or no `X-Jev-*` at all), which is never cached at the edge and does not count against the Worker's breaker. Set `upstream` when the app is not behind the same host as the gateway; bind `JEV_CACHE` (KV) to share the cache across isolates. [wrangler.thin.toml](wrangler.thin.toml), [examples/thin.ts](examples/thin.ts).

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

`wrangler secret put TYPESAFE_API_KEY`. The config object has the same keys as the Lua config file, so the [deployment context guidance](../../docs/design.md#writing-the-deployment-context) applies unchanged. `provider: "openai-compat"` with `endpoint` and `model` uses any OpenAI-style chat endpoint; `provider: "mock"` with `mock_score` runs without a network call. Without `JEV_CACHE` the cache is per isolate; without `JEV_STATE` the breaker and adaptive timeout are per isolate too. [wrangler.full.toml](wrangler.full.toml), [examples/full.ts](examples/full.ts).

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
export const config = { matcher: ["/api/chat/:path*", "/api/completion/:path*", "/api/completions/:path*", "/v1/:path*"] };
```

Next buffers the body for middleware on both runtimes, so the whole pipeline runs there. Route handlers read `X-Jev-Verdict` and `X-Jev-Score` from the request headers. The returned function takes Next's `(request, event)`, and with `config.subject` on the trajectory write goes to `event.waitUntil` so it outlives the response. On Vercel the edge runtime is V8 and the cache is per isolate; pass a `cache` Store (Vercel KV, Upstash) in the options to share it. [examples/next-middleware.ts](examples/next-middleware.ts).

## Node

```ts
import express from "express";
import { nodeMiddleware } from "@jev-edge/js";

const app = express();
app.use("/v1", nodeMiddleware({ config: { jev: { provider: "jev", api_key: process.env.TYPESAFE_API_KEY, deployment_context: "…", timeout_ms: 400 } } }));
app.post("/v1/chat/completions", (req, res) => { /* req.jev, req.headers["x-jev-verdict"] */ });
```

Mount it before the routes that carry natural language. Under a mount path, as above or in a Router, it still judges the whole path (`req.originalUrl`), because that is what the rules' `watch_paths` name; `GET /_jev/health` is answered under the mount path (`/v1/_jev/health` here). The URL it judges is the request-target on a fixed origin, normalized like on every other host (`//v1/chat/completions` is `/v1/chat/completions`): the client's `Host` header plays no part, so a value the URL parser rejects cannot turn a request into a fail-open error. If `express.json()` ran first the parsed body is re-serialised for evaluation; otherwise the stream is read to completion and exposed, unchanged, as `req.body` (string) for the handlers. A body over the largest `max_body_bytes` is still handed to the app as-is and judged on its head and tail, like on every other host (see Body size below); the reason then ends in `(window)`. The middleware buffers the whole body and never truncates or replaces what the app receives, so put a size limit in front of it (a proxy limit, or a body parser with `limit`) if unbounded uploads can reach the route. A stream something else already consumed (`req.readableEnded`) is treated as "no body" instead of waiting for it. A block ends the response with the 403; a middleware error fails open with `x-jev-verdict: error` and `x-jev-source: adapter`.

## Hono

```ts
import { Hono } from "hono";
import { honoMiddleware } from "@jev-edge/js";
const app = new Hono();
app.use("/v1/*", honoMiddleware({ config: { … } }));
app.post("/v1/chat/completions", (c) => c.json({ verdict: c.get("jev") }));
```

`c.req.raw` is replaced with the request carrying the verdict's `X-Jev-*` (client-supplied ones removed), on a middleware error too, where they say `error` / `adapter`. A body an earlier middleware already read with `c.req.json()` or `c.req.text()` is judged from Hono's cached copy. The response gets `X-Jev-Request-Id` only: the verdict, score, reason, source and subject stay with the handlers and the log.

## AWS Lambda@Edge

```ts
// handler.ts, deployed in us-east-1 and attached to the viewer-request trigger with "Include Body"
import { lambdaEdgeHandler } from "@jev-edge/js/aws";
export const handler = lambdaEdgeHandler({
  config: { jev: { provider: "jev", api_key: "<from Secrets Manager at cold start>", deployment_context: "…", timeout_ms: 400 }, policy: { mode: "monitor" } },
});
```

CloudFront hands the body over base64-encoded, truncated at 40 KB on viewer-request (1 MB on origin-request) with `bodyTruncated` set. A truncated body is scanned as the head of a larger one for the text fields, with no tail (the reason ends in `(window)`; a head with no text is `unjudgeable: body too large`), and the full body still reaches the origin. Use origin-request if prompts can be longer than 40 KB. Lambda@Edge has no environment variables, no VPC and no KV: cache, breaker and adaptive timeout are per execution environment unless you pass Store implementations (DynamoDB Global Tables is the usual choice, at a round trip per lookup). API Gateway's Lambda authorizer and CloudFront Functions do not see the body and are not supported; [the recipes page](../../docs/recipes.md) explains what a headers-only integration can and cannot do. [examples/lambda-edge.ts](examples/lambda-edge.ts).

## Deno Deploy

```ts
import { denoHandler } from "npm:@jev-edge/js/deno";

Deno.serve(denoHandler({
  upstream: "https://app.internal.example.com",
  kv: await Deno.openKv(),   // optional: cache, breaker / adaptive state and subject ring in Deno KV
  config: { jev: { provider: "jev", api_key: Deno.env.get("TYPESAFE_API_KEY"), deployment_context: "…" }, policy: { mode: "monitor" } },
}));
```

`denoHandler` is `fullWorker` for `Deno.serve`: one runtime per isolate, allowed requests forwarded to `upstream`'s origin with the request's path and query (a `//host` path stays on the upstream) and `X-Jev-*` attached, redirects passed back rather than followed, blocks answered with the 403. The client IP is the peer Deno reports in `info.remoteAddr.hostname`, appended to `X-Forwarded-For` the way `nodeMiddleware` appends the socket address, so with the default `client_ip.trusted_hops = 1` a client-sent `X-Forwarded-For` cannot choose it. If Deploy sits behind a proxy of yours, raise `trusted_hops` to match.

`denoKvStore(kv, prefix?)` is a `Store` over Deno KV, typed structurally (no dependency on Deno's types). ttl becomes `expireIn`, and reads check the expiry themselves because Deno KV deletes expired keys lazily. `incr` and `expire` are check-and-set loops on `kv.atomic()`, so the subject ring counter is atomic across isolates and regions; the breaker's counters use plain get / set and can lose an increment under contention. Without `kv` every store is memory per isolate.

`Deno.serve` has no `waitUntil`: the subject write is fire-and-forget, not awaited on the request path and not guaranteed to finish if the isolate is stopped. `br` bodies decode through `node:zlib`, which Deno resolves via its Node compatibility layer. [examples/deno.ts](examples/deno.ts).

## Any other framework

`handle(request, runtime, next)` is what the presets wrap:

```ts
import { createRuntime, handle, type Runtime } from "@jev-edge/js";
let rt: Runtime | undefined; // module scope: one runtime for the isolate's life
// in the fetch handler:
rt ??= createRuntime({ config: { … }, cache: env.JEV_CACHE, state: env.JEV_STATE });
return handle(request, rt, (req) => fetch(req), ctx);
```

`evaluate(request, rt)` returns the verdict without forwarding; both take an optional `{ waitUntil }` (a Workers `ExecutionContext`) so the subject write outlives the response. `GET /_jev/health` is served by `handle` unless `health: false`.

Pass `state` the Durable Object namespace, `env.JEV_STATE`, not a stub. workerd binds a stub to the request that made it, so the runtime makes its own per operation (`idFromName("jev-edge")` is a hash and `get` no round trip); that is what lets the runtime above live at module scope, and it is what `fullWorker` and `pagesMiddleware` pass. For an object other than `jev-edge`, say one per environment when several Workers bind the same class, pass `state: { namespace: env.JEV_STATE, name: "staging" }` (a preset keeps the `state` its options give); `createRuntime` refuses one whose namespace is missing or whose name is empty. `cache` and `subjectStore` take the same forms: `subjectStore: env.JEV_STATE` gives the subject ring an atomic increment (see Subjects). A Durable Object as `cache` works, but puts every lookup through one object, and `JevState` keeps an expired entry until the key is written again, so KV is the cache to bind.

A stub is still accepted, for a runtime built per request. Kept across requests, it fails with "Cannot perform I/O on behalf of a different request". Instead of failing open on every later request, the runtime then logs one `console.error` naming this fix, once per stub in each isolate that hits it, and from then on keeps what went through that stub (breaker, adaptive timeout, a `cache` or `subjectStore` given the same stub) in that isolate's memory. Each isolate then trips its breaker and learns its timeout on its own, as without the binding. Operations still run one at a time, as inside the object, so an increment or a half-open probe claim is atomic within the isolate, though not across isolates. Only workerd's own refusal does this: an exception thrown inside the object, whatever its message, reaches the caller marked `remote` and is handled like any other store error. `state` is taken for a namespace when it has `idFromName` and `get` and no `fetch`, for a stub when it has a `fetch` method (a real stub answers every property name, so nothing else tells it apart), for `{ namespace, name }` when it has a `namespace` key and no `get` method, and for a `Store` otherwise.

**Fail-open.** `evaluate` never throws. Whatever fails between "we have a Request" and "we have a verdict" (the body read, the subject store, the judge, `onVerdict`, building the block response) passes the request with `X-Jev-Verdict: error`, `X-Jev-Source: adapter` and a `console.error` line, the same contract as `access()` in the OpenResty adapter. Every preset inherits it. The writes that follow a verdict are best effort: a verdict-cache put, a breaker or adaptive-timeout record, or a subject write that the store rejects (KV over its per-key write rate or daily quota, a Durable Object answering 5xx, Deno KV over quota) is logged with `console.warn` and the verdict stands, as when a shared dict `set` fails on nginx. The body is only read for a request some rule watches (path and method), from a clone, and never beyond 4 x the largest `max_body_bytes`, whatever `Content-Length` says. Inbound `X-Jev-*` headers are dropped before forwarding, `X-Jev-Subject` included unless `config.subject` is set to consume it (`from: "header", name: "x-jev-subject"`); `cf-ray` is used as the request id only under the Cloudflare presets.

**Malformed paths.** A path nginx would refuse with 400 (a `%` not followed by two hex digits, such as the IIS-style `%u0063` that cpp-httplib under llama.cpp decodes to `c`, a bare `%`, `%zz`, or a `%00`) is answered 400 with `policy.block_body` and `X-Jev-Verdict: skipped`, `X-Jev-Source: adapter`, `X-Jev-Reason: invalid path`, in `monitor` mode too and whatever `policy.unjudgeable` says: the runtime cannot tell what the origin makes of such a path, so it answers as nginx does inline, never passes it, and logs a `console.warn` line. An escape of a byte that is not UTF-8 (`%FF`, the overlong `%C0%AE`) is well formed, as it is to nginx, and is judged on the path as sent. The query string is not checked.

**Subjects.** `config.subject = { enabled: true, from: "cookie", name: "sid", salt: env.JEV_SUBJECT_SALT }` gives every request a hashed subject id (`<from>:` + SHA-256 hex over `salt \0 value`; the raw cookie or header is never stored, values over 512 bytes are dropped) and records its trajectory in `subjectStore` (KV, the `JevState` Durable Object, or memory), `max_entries` per subject for `history_ttl`. The OpenResty adapter uses SHA-256 as well since 0.3.1, so the same salt and value give the same id on both. The id is forwarded upstream as `X-Jev-Subject` (the thin Worker also sends it with the `/_jev/authz` call); configure the origin with `subject = { enabled = true, from = "header", name = "x-jev-subject", hashed = true }`. With `hashed = true` only values of the form `<letters>:<hex>` are accepted as ids; anything else is ignored.

The trajectory uses the same ring layout as the Lua core: one counter per subject (`subj:<id>:n`, bumped with the store's `incr`) and one key per entry (`subj:<id>:<slot>`), so concurrent requests from one subject do not overwrite each other's entries. That needs a store with an atomic `incr`: the memory store (per isolate) and the `JevState` Durable Object have one. Pass `subjectStore: env.JEV_STATE` (or `{ namespace, name }`, or `durableStore(...)` of either); the object runs each increment on its own, and keeps a subject's entries until they are overwritten, so its storage grows with the number of distinct subjects. A stub kept past its request falls back as for `state`: to isolate memory, where an increment is atomic within the isolate only. KV has no increment, so its `incr` is a get and a put: best effort, and two isolates writing for the same subject at once can still lose an entry. A custom `Store` without `incr` keeps the older one-list-per-subject layout (`subj:<id>`), a read-then-write with the same caveat.

**Tenants and sampling.** `rules` accepts rule set ids, complete `Rule` objects, or `{ id, extends, watch_paths, deployment_context, ... }` inline rules, first match wins, same as the Lua config. Watch paths match the path the app routes on: ASCII case folded (Express and Koa route `/V1/Chat/Completions` to `/v1/chat/completions`) and `;` path parameters dropped; a rule with `paths_case_sensitive: true` keeps the case. `config.sampling` plus an `onSample(sample, request)` option gives you the sampled decisions (normalized text, fingerprint, score, verdict); write them to KV, a log or an analytics binding. There is no `/_jev/samples` endpoint here because storage is yours.

## What is the same as nginx, and what is not

Same, guaranteed by the golden vectors: text extraction, normalisation and fingerprints, every L1 decision, thresholds and the async flag, verdict headers and reason encoding, the order L1 / cache / breaker / L2, and what core reports to the breaker (only a transport error, a timeout, a 5xx or a 429 is a failure; a 200 with no usable answer and any other 4xx are not, and in half-open hand the probe on). Same by construction: provider request bodies (the `jev` and `openai-compat` providers build the same JSON as the Lua ones) and the error kind each provider gives a failed call, config keys and defaults, `/_jev/health`.

Different, by platform:

| | cache | breaker + adaptive timeout | notes |
|---|---|---|---|
| nginx / APISIX | shared dict, exact TTL, all workers | shared dict | reference |
| Cloudflare Workers | KV: 60 s minimum TTL, eventually consistent | Durable Object: the breaker and adaptive read-modify-write run inside `JevState`, one hop per operation, atomic | per isolate without the bindings |
| Next.js on Vercel, Node, Hono | memory per process / isolate | memory | pass a `Store` to share |
| Lambda@Edge | memory per execution environment | memory | no env vars; key from Secrets Manager |
| Deno Deploy | Deno KV (`kv`), else memory per isolate | Deno KV, get / set (not atomic), else memory | subject ring `incr` is atomic (check-and-set) |

- **Client IP.** `cf-connecting-ip` on Cloudflare (presets, or a request carrying the `cf` object), a header you name with `clientIpHeader`, or else `X-Forwarded-For` element `client_ip.trusted_hops` from the right, as on nginx. The Node middleware and the Deno handler append the peer address (socket / `info.remoteAddr`) to `X-Forwarded-For` first, so with no proxy in front the IP is the peer's.
- **Fingerprint hash.** SHA-256 hex over the whole normalized text, on both (`core.sha256Hex` here, `resty.sha256` on nginx), so the same text has the same fingerprint everywhere. `djb2` is only the golden vectors' reference hash. `cache.fp_prefix_bytes` only bounds sampled text.
- **Byte truncation of sampled text.** Lua's `s:sub(1, n)` keeps the bytes of a code point split at `n`; this package drops the partial code point, so the sampled text is never longer than `n` bytes and never contains U+FFFD. The golden normalize vectors cut on ASCII and agree; only a logged sample that ends inside a multi-byte character differs, by at most three bytes.
- **Adaptive timeout state.** One document (`adapt`) instead of the three `adapt:*` keys the OpenResty adapter keeps; the value is outside the parity contract either way.
- **No `/_jev/config` hot reload.** Config is code; redeploy, or read it from your store in an options function.
- **No L3 side-path yet.** `verdict.async` is set; nothing consumes it.
- **Body size.** Up to the largest `max_body_bytes` (1 MiB by default) the body is parsed whole. Past it the runtime keeps the first `max_body_bytes` and the last 64 KiB, reading on to at most 4 x the limit; a body longer than that is scanned on its head and the last 64 KiB read, not the body's real tail. Workers cap request size by plan. See [Body size and what L1 reads](../../docs/design.md#body-size-and-what-l1-reads).
- **Content-Type and Content-Encoding.** Content-Type is a hint, as in the Lua core: the body decides the format, and a media type in `skip_content_types` is skipped only when its body really is binary (JSON or text under `image/png` is judged). `gzip` and `deflate` are decoded with `DecompressionStream`, `br` with `node:zlib` where the runtime has it (Node, Lambda@Edge, Next on the Node runtime, Deno via its `node:` compatibility layer); elsewhere a `br` body is `unjudgeable`. Decoding is capped at `max_body_bytes`.

## Development

```
pnpm install
pnpm test          # 142 golden cases + core, worker and host tests
pnpm typecheck
pnpm build         # dist/ for publishing
```

`pnpm golden` runs only the parity suite. When `core/golden/*.json` changes upstream, this suite is what tells you the port has to follow.

The published build is plain ESM that Node and Deno load without a bundler, so relative imports in `src/` carry their `.js` extension; `tsconfig.build.json` uses `NodeNext` resolution and fails the build on one that does not. `pnpm pack` rebuilds `dist/` first (`prepack`) and ships `dist/`, this README, `LICENSE` (a copy of the repository's, checked by the release workflow) and the two wrangler configs. Releases go out from [.github/workflows/release-npm.yml](../../.github/workflows/release-npm.yml) on a `v<version>` tag.
