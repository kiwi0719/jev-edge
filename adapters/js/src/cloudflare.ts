// Cloudflare presets. Three ways to run the same runtime:
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
import { createRuntime, handle, type Options, type Runtime, type RequestCtx } from "./runtime.js";
import { JevState, type KVLike, type DOStubLike } from "./cf/stores.js";

export { JevState };

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
  const o: Options = { ...(typeof resolve === "function" ? resolve(env) : resolve), platform: "cloudflare" };
  if (!o.cache && env.JEV_CACHE) o.cache = env.JEV_CACHE;
  if (!o.state && env.JEV_STATE) {
    // A stub is an I/O object of the request that made it: workerd refuses
    // it in any later one ("Cannot perform I/O on behalf of a different
    // request"), and this runtime lives as long as the isolate. So every
    // call gets a fresh stub; idFromName is a hash and get() no round trip.
    const ns = env.JEV_STATE;
    o.state = { fetch: (input, init) => ns.get(ns.idFromName("jev-edge")).fetch(input, init) };
  }
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
): { fetch(request: Request, env: E, ctx?: RequestCtx): Promise<Response> } {
  const cache = new WeakMap<object, Runtime>();
  return {
    async fetch(request, env, ctx) {
      const o = typeof opts === "function" ? opts(env) : opts;
      const origin = (opts as { origin?: string }).origin ?? env.JEV_ORIGIN;
      if (!origin) throw new Error("thinWorker: origin (or env.JEV_ORIGIN) is required");
      const rt = runtimeFor(() => ({
        ...o,
        config: { ...o.config, jev: { provider: "backend", endpoint: origin, ...o.config?.jev } },
      }), env, cache);
      const upstream = (opts as { upstream?: string }).upstream ?? origin;
      return handle(request, rt, (req) => {
        return fetch(new Request(upstreamUrl(req.url, upstream), req));
      }, ctx);
    },
  };
}

/**
 * The upstream URL for a request: upstream's origin, the request's path and
 * query. Never `new URL(path, upstream)`: a path starting with `//` is a
 * scheme-relative reference there and would send the request to another host.
 */
export function upstreamUrl(requestUrl: string, upstream: string): string {
  const u = new URL(requestUrl);
  return new URL(upstream).origin + u.pathname + u.search;
}

/**
 * Full Worker: everything runs here. `upstream` is where allowed requests go;
 * bind JEV_CACHE (KV) and JEV_STATE (Durable Object, class JevState) in
 * wrangler.toml, and TYPESAFE_API_KEY as a secret.
 */
export function fullWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> & { upstream: string },
): { fetch(request: Request, env: E, ctx?: RequestCtx): Promise<Response> } {
  const cache = new WeakMap<object, Runtime>();
  return {
    async fetch(request, env, ctx) {
      const rt = runtimeFor(opts, env, cache);
      return handle(request, rt, (req) => {
        return fetch(new Request(upstreamUrl(req.url, opts.upstream), req));
      }, ctx);
    },
  };
}

/** Pages Functions middleware: `export const onRequest = pagesMiddleware({...})` in functions/_middleware.ts. */
export function pagesMiddleware<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> = {},
): (context: { request: Request; env: E; next: (req?: Request) => Promise<Response>; waitUntil?: (p: Promise<unknown>) => void }) => Promise<Response> {
  const cache = new WeakMap<object, Runtime>();
  return async (context) => {
    const rt = runtimeFor(opts, context.env, cache);
    const ctx: RequestCtx | undefined = context.waitUntil ? { waitUntil: (p) => context.waitUntil!(p) } : undefined;
    return handle(context.request, rt, (req) => context.next(req), ctx);
  };
}
