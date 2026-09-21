// jev-edge for Cloudflare. One handler, three presets:
//
//   thinWorker(opts)      you already run jev-edge on OpenResty/Envoy and put
//                         Cloudflare in front of it. The Worker runs L1 and the
//                         fingerprint cache at the edge and asks your origin's
//                         /_jev/authz for the judgment. One set of thresholds,
//                         one deployment context, kept at the origin.
//   fullWorker(opts)      you have Workers and nothing else. The whole core
//                         runs here: KV for the cache, a Durable Object for the
//                         breaker and adaptive timeout, TypeSafe (or any
//                         OpenAI-compatible endpoint) as the provider.
//   pagesMiddleware(opts) same as fullWorker, exported as a Pages Functions
//                         middleware: `export const onRequest = pagesMiddleware({...})`.
//
// Every preset is the same evaluate() from ./core, which is held to the golden
// vectors in core/golden/. What differs is which store backs the cache and the
// breaker, and where judge.call goes.

import * as core from "./core";
import { load as loadRule } from "./rules";
import { load as loadProvider, type Provider, type ProviderRequestInfo } from "./providers";
import { kvStore, memoryStore, durableStore, JevState, type KVLike, type DOStubLike } from "./cf/stores";
import { Adaptive } from "./cf/adaptive";
import type { Store } from "./core/breaker";

export { JevState };
export * as core from "./core";
export * as providers from "./providers";
export { kvStore, memoryStore, durableStore } from "./cf/stores";

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

export interface Options {
  /** Same shape as the Lua config file: jev, rules, policy, cache, breaker. */
  config?: DeepPartial<core.Config> & { rules?: string[] };
  /** Rule sets by id (defaults to config.rules, "llm-endpoints"). Custom Rule objects may be passed. */
  rules?: (string | core.Rule)[];
  /** Overrides config.jev.provider with an instance. */
  provider?: Provider;
  /** KV namespace for the fingerprint / reputation cache. Memory (per isolate) if absent. */
  cache?: KVLike | Store;
  /** Durable Object stub (or any Store) for breaker + adaptive timeout. Memory (per isolate) if absent. */
  state?: DOStubLike | Store;
  /** Header carrying the client IP (Cloudflare sets cf-connecting-ip). */
  clientIpHeader?: string;
  /** Called once per judged request with the verdict; wire to console.log or an analytics binding. */
  onVerdict?: (v: core.Verdict, req: Request) => void;
  /** Serve GET /_jev/health from the Worker (default true). */
  health?: boolean;
}

export interface Runtime {
  config: core.Config;
  rules: core.Rule[];
  provider: Provider;
  cache: Store;
  state: Store;
  breaker: core.breaker.Breaker;
  adaptive: Adaptive;
  opts: Options;
}

function isKV(x: unknown): x is KVLike {
  return typeof x === "object" && x !== null && "put" in x && typeof (x as KVLike).put === "function";
}
function isStub(x: unknown): x is DOStubLike {
  return typeof x === "object" && x !== null && "fetch" in x && !("get" in x);
}

export function createRuntime(opts: Options): Runtime {
  const config = core.defaults.merge(core.defaults.config, opts.config ?? {});
  const [ok, err] = core.defaults.validate(config);
  if (!ok) throw new Error("jev-edge config: " + err);
  const rules = (opts.rules ?? config.rules).map((r) => (typeof r === "string" ? loadRule(r) : r));
  const provider = opts.provider ?? loadProvider(config.jev.provider ?? "jev");
  const clock = () => Date.now() / 1000;
  const cache: Store = isKV(opts.cache) ? kvStore(opts.cache) : (opts.cache as Store | undefined) ?? memoryStore(clock);
  const state: Store = isStub(opts.state) ? durableStore(opts.state) : (opts.state as Store | undefined) ?? memoryStore(clock);
  const breaker = new core.breaker.Breaker(state, clock, config.breaker);
  const adaptive = new Adaptive(state, config.jev);
  return { config, rules, provider, cache, state, breaker, adaptive, opts };
}

const HEADER_NAMES = ["X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id"];

async function readReq(request: Request, rt: Runtime): Promise<[core.Req, ProviderRequestInfo]> {
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k] = v));
  const ipHeader = rt.opts.clientIpHeader ?? "cf-connecting-ip";
  const clientIp = request.headers.get(ipHeader) ?? (request.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  let body: string | null = null;
  const maxBytes = Math.max(...rt.rules.map((r) => r.max_body_bytes ?? 65536));
  const len = Number(request.headers.get("content-length"));
  if (request.body && !(Number.isFinite(len) && len > maxBytes)) {
    body = await request.clone().text();
  }
  const req: core.Req = {
    method: request.method,
    path: url.pathname,
    headers,
    body: body ?? undefined,
    body_size: body !== null ? core.normalize.byteLength(body) : Number.isFinite(len) ? len : 0,
    client_ip: clientIp,
  };
  return [req, { method: request.method, path: url.pathname, headers: request.headers, body, clientIp }];
}

/** Evaluate one request. Returns the verdict and, when it must be returned as-is, a Response. */
export async function evaluate(request: Request, rt: Runtime): Promise<{ verdict: core.Verdict; response?: Response; requestId: string }> {
  const requestId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  const [req, info] = await readReq(request, rt);
  const ctx: core.Ctx = {
    config: rt.config,
    rules: rt.rules,
    cache: rt.cache,
    breaker: rt.breaker,
    clock: () => Date.now() / 1000,
    hash: core.normalize.djb2,
    json_decode: (s) => JSON.parse(s),
    re_find: core.rules.reFind,
    judge: {
      call: async (prompt) => {
        const timeoutMs = await rt.adaptive.current();
        const t0 = Date.now();
        const r = await rt.provider.call(prompt, rt.config.jev, timeoutMs, info);
        const elapsed = Date.now() - t0;
        if (r[0]) await rt.adaptive.success(elapsed);
        else if (String(r[1]).includes("timeout")) await rt.adaptive.timeout(timeoutMs);
        return r;
      },
    },
    log: (level, msg) => console[level === "error" ? "error" : "warn"](msg),
  };
  let verdict: core.Verdict;
  try {
    verdict = await core.evaluate(req, ctx);
  } catch (e) {
    console.error("jev-edge: evaluate error, failing open: " + (e instanceof Error ? e.message : String(e)));
    verdict = core.verdict.newVerdict({ verdict: core.verdict.ERROR, source: core.verdict.SRC_L2, reason: "adapter error" });
  }
  if (rt.opts.onVerdict) rt.opts.onVerdict(verdict, request);
  if (verdict.action === core.verdict.ACTION_BLOCK) {
    return {
      verdict, requestId,
      response: new Response(rt.config.policy.block_body ?? '{"error":"request rejected"}', {
        status: rt.config.policy.block_status ?? 403,
        headers: { "Content-Type": "application/json", ...core.verdict.headers(verdict), "X-Jev-Request-Id": requestId },
      }),
    };
  }
  return { verdict, requestId };
}

/** The request to forward upstream: original plus X-Jev-* headers (client-supplied ones stripped). */
export function withVerdictHeaders(request: Request, verdict: core.Verdict, requestId: string): Request {
  const headers = new Headers(request.headers);
  for (const h of HEADER_NAMES) headers.delete(h);
  for (const [k, v] of Object.entries(core.verdict.headers(verdict))) headers.set(k, v);
  headers.set("X-Jev-Request-Id", requestId);
  return new Request(request, { headers });
}

function healthResponse(rt: Runtime): Response {
  return Response.json({
    ok: true, adapter: "cloudflare", core: core.VERSION,
    provider: rt.provider.name, model: rt.config.jev.model ?? null, mode: rt.config.policy.mode,
    endpoint: rt.config.jev.endpoint ?? null,
  });
}

/**
 * Generic handler: evaluate, then either return the block or call `next` with
 * the request carrying X-Jev-* headers. Works for any framework that gives
 * you a Request and a way to continue.
 */
export async function handle(request: Request, rt: Runtime, next: (req: Request) => Promise<Response>): Promise<Response> {
  const url = new URL(request.url);
  if (rt.opts.health !== false && url.pathname === "/_jev/health" && request.method === "GET") return healthResponse(rt);
  const { verdict, response, requestId } = await evaluate(request, rt);
  if (response) return response;
  return next(withVerdictHeaders(request, verdict, requestId));
}

// ---------------------------------------------------------------------------
// presets
// ---------------------------------------------------------------------------

export interface WorkerEnv {
  JEV_CACHE?: KVLike;
  JEV_STATE?: { idFromName(name: string): unknown; get(id: unknown): DOStubLike };
  TYPESAFE_API_KEY?: string;
  JEV_ORIGIN?: string;
  [k: string]: unknown;
}

type Resolve<E> = Options | ((env: E) => Options);

function runtimeFor<E extends WorkerEnv>(resolve: Resolve<E>, env: E, cache: WeakMap<object, Runtime>): Runtime {
  const hit = cache.get(env);
  if (hit) return hit;
  const o = typeof resolve === "function" ? resolve(env) : { ...resolve };
  if (!o.cache && env.JEV_CACHE) o.cache = env.JEV_CACHE;
  if (!o.state && env.JEV_STATE) o.state = env.JEV_STATE.get(env.JEV_STATE.idFromName("jev-edge"));
  if (env.TYPESAFE_API_KEY) o.config = { ...o.config, jev: { api_key: env.TYPESAFE_API_KEY, ...o.config?.jev } };
  const rt = createRuntime(o);
  cache.set(env, rt);
  return rt;
}

/**
 * Thin Worker: L1 + cache at the edge, judgment by the jev-edge you already
 * run. `origin` is that gateway's base URL (or env.JEV_ORIGIN); the Worker
 * proxies to `upstream` (default: the same origin) with X-Jev-* attached.
 */
export function thinWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> & { origin?: string; upstream?: string } = {},
): { fetch(request: Request, env: E): Promise<Response> } {
  const cache = new WeakMap<object, Runtime>();
  return {
    async fetch(request, env) {
      const o = typeof opts === "function" ? opts(env) : opts;
      const origin = (opts as { origin?: string }).origin ?? env.JEV_ORIGIN;
      if (!origin) throw new Error("thinWorker: origin (or env.JEV_ORIGIN) is required");
      const rt = runtimeFor(() => ({
        ...o,
        config: { ...o.config, jev: { provider: "backend", endpoint: origin, ...o.config?.jev } },
      }), env, cache);
      const upstream = (opts as { upstream?: string }).upstream ?? origin;
      return handle(request, rt, (req) => {
        const u = new URL(req.url);
        const target = new URL(u.pathname + u.search, upstream);
        return fetch(new Request(target.toString(), req));
      });
    },
  };
}

/**
 * Full Worker: everything runs here. `upstream` is where allowed requests go;
 * bind JEV_CACHE (KV) and JEV_STATE (Durable Object, class JevState) in
 * wrangler.toml, and TYPESAFE_API_KEY as a secret.
 */
export function fullWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> & { upstream: string },
): { fetch(request: Request, env: E): Promise<Response> } {
  const cache = new WeakMap<object, Runtime>();
  return {
    async fetch(request, env) {
      const rt = runtimeFor(opts, env, cache);
      return handle(request, rt, (req) => {
        const u = new URL(req.url);
        return fetch(new Request(new URL(u.pathname + u.search, opts.upstream).toString(), req));
      });
    },
  };
}

/** Pages Functions middleware: `export const onRequest = pagesMiddleware({...})` in functions/_middleware.ts. */
export function pagesMiddleware<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> = {},
): (context: { request: Request; env: E; next: (req?: Request) => Promise<Response> }) => Promise<Response> {
  const cache = new WeakMap<object, Runtime>();
  return async (context) => {
    const rt = runtimeFor(opts, context.env, cache);
    return handle(context.request, rt, (req) => context.next(req));
  };
}
