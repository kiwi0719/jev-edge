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
import { createRuntime, handle, type Options, type Runtime } from "./runtime";
import { JevState, type KVLike, type DOStubLike } from "./cf/stores";

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
