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
import { createRuntime, handle, normalizePath, type Options, type Runtime, type RequestCtx } from "./runtime.js";
import { JevState, isStateTarget, type KVLike, type DONamespaceLike } from "./cf/stores.js";

export { JevState };

// ---------------------------------------------------------------------------

export interface WorkerEnv {
  JEV_CACHE?: KVLike;
  JEV_STATE?: DONamespaceLike;
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
  // the namespace, not a stub: this runtime lives as long as the isolate,
  // and a stub only as long as the request that made it (cf/stores.ts)
  if (!o.state && env.JEV_STATE) o.state = env.JEV_STATE;
  // Subject reputation counts with the store's incr: atomic in the Durable
  // Object, lost under concurrency in KV, per isolate in memory. So with the
  // object bound (or named in `state`), the subject store is that object
  // unless the options name one.
  if (!o.subjectStore && isStateTarget(o.state) && reputationOn(o)) o.subjectStore = o.state;
  if (env.TYPESAFE_API_KEY) o.config = { ...o.config, jev: { api_key: env.TYPESAFE_API_KEY, ...o.config?.jev } };
  const rt = createRuntime(o);
  cache.set(env, rt);
  return rt;
}

function reputationOn(o: Options): boolean {
  const s = o.config?.subject;
  return s?.enabled === true && Number(s.reputation?.block_at) > 0;
}

/**
 * Is this one of the origin's own /_jev/* endpoints (authz, config, samples,
 * health), however the path is spelled (%5F, case, `//`, dot segments), as
 * the origin's nginx would route it? The Worker answers GET /_jev/health
 * itself (handle); nothing else under /_jev is ever passed to the origin or
 * the upstream, where /_jev/authz would judge (and answer) for anyone.
 */
function originEndpoint(request: Request): boolean {
  let p: string;
  try {
    p = normalizePath(new URL(request.url).pathname).toLowerCase();
  } catch {
    return false;
  }
  return p === "/_jev" || p.startsWith("/_jev/");
}

/** handle() answers exactly this request itself; any other /_jev path is originEndpoint's. */
function ownHealth(request: Request, rt: Runtime): boolean {
  return rt.opts.health !== false && request.method === "GET" && new URL(request.url).pathname === "/_jev/health";
}

const NOT_FOUND = () => new Response('{"error":"not found"}', { status: 404, headers: { "Content-Type": "application/json" } });

/**
 * Thin Worker: L1 + cache at the edge, judgment by the jev-edge you already
 * run. `origin` is that gateway's base URL (or env.JEV_ORIGIN); the Worker
 * proxies to `upstream` (default: the same origin) with X-Jev-* attached.
 * The origin's /_jev/* endpoints answer 404 here, except GET /_jev/health,
 * which the Worker serves itself.
 */
export function thinWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> & { origin?: string; upstream?: string } = {},
): { fetch(request: Request, env: E, ctx?: RequestCtx): Promise<Response> } {
  const cache = new WeakMap<object, Runtime>();
  return {
    async fetch(request, env, ctx) {
      const jevPath = originEndpoint(request);
      const o = typeof opts === "function" ? opts(env) : opts;
      const origin = (opts as { origin?: string }).origin ?? env.JEV_ORIGIN;
      if (!origin) throw new Error("thinWorker: origin (or env.JEV_ORIGIN) is required");
      const rt = runtimeFor(() => ({
        ...o,
        config: { ...o.config, jev: { provider: "backend", endpoint: origin, ...o.config?.jev } },
      }), env, cache);
      if (jevPath && !ownHealth(request, rt)) return NOT_FOUND();
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
