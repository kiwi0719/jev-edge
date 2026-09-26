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
import { createRuntime, handle, failOpen, normalizePath, type Options, type Runtime, type RequestCtx } from "./runtime.js";
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

/** The options, or a function of the Worker's env returning them (called once per env, like the runtime built from them). */
type Resolve<E, X = unknown> = (Options & X) | ((env: E) => Options & X);

function resolveOptions<E, X>(resolve: Resolve<E, X>, env: E): Options & X {
  return typeof resolve === "function" ? resolve(env) : resolve;
}

/** The runtime for these options, with the env's bindings filled in where the options name none. */
function presetRuntime<E extends WorkerEnv>(opts: Options, env: E): Runtime {
  const o: Options = { ...opts, platform: "cloudflare" };
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
  return createRuntime(o);
}

/** The runtime for this env, built once per env (and again after a failed build, which is not kept). */
function runtimeFor<E extends WorkerEnv>(resolve: Resolve<E>, env: E, cache: WeakMap<object, Runtime>): Runtime {
  const hit = cache.get(env);
  if (hit) return hit;
  const rt = presetRuntime(resolveOptions(resolve, env), env);
  cache.set(env, rt);
  return rt;
}

/** `v` when it is an absolute http(s) URL, else undefined. */
function usable(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  try {
    const u = new URL(v);
    return u.protocol === "https:" || u.protocol === "http:" ? v : undefined;
  } catch {
    return undefined;
  }
}

/** `v` as an address the preset forwards to, checked when the preset is built for an env, not per request. */
function address(name: string, v: unknown): string | undefined {
  if (v === undefined || v === null || v === "") return undefined;
  const ok = usable(v);
  if (!ok) throw new Error(`${name} must be an absolute http(s) URL, got ${JSON.stringify(String(v))}`);
  return ok;
}

/**
 * What a preset keeps per env: its runtime and where it forwards. `to` is
 * also where a failed build fails open to: whatever address the options did
 * name usably, else undefined (the request's own URL).
 */
interface Built { rt?: Runtime; to?: string; error?: unknown }

/**
 * The addresses set as properties of a resolver function, the one way a
 * function worked before the presets read them from what it returns; still
 * taken, after the returned ones.
 */
function attached<A>(opts: unknown): Partial<A> {
  return typeof opts === "function" ? (opts as unknown as Partial<A>) : {};
}

/** One Built per env, rebuilt after a failure. */
function builtFor<E extends WorkerEnv>(env: E, cache: WeakMap<object, Built>, build: (env: E) => Built): Built {
  const hit = cache.get(env);
  if (hit) return hit;
  const b = build(env);
  if (b.rt) cache.set(env, b);
  return b;
}

/** Forwards to `to` (its origin, the request's path and query), or the request as it is. */
function forwarder(to: string | undefined): (req: Request) => Promise<Response> {
  return (req) => fetch(to ? new Request(upstreamUrl(req.url, to), req) : req);
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
 * which the Worker serves itself. `opts` may be a function of env returning
 * the options, origin and upstream included: called once per env, and both
 * addresses checked then. An address it cannot use (missing origin, not an
 * absolute http(s) URL) fails open, logged once.
 */
export function thinWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E, { origin?: string; upstream?: string }> = {},
): { fetch(request: Request, env: E, ctx?: RequestCtx): Promise<Response> } {
  const cache = new WeakMap<object, Built>();
  const own = attached<{ origin: string; upstream: string }>(opts);
  const build = (env: E): Built => {
    let o: Options & { origin?: string; upstream?: string };
    try {
      o = resolveOptions(opts, env);
    } catch (e) {
      return { error: e, to: usable(own.upstream) ?? usable(own.origin ?? env.JEV_ORIGIN) };
    }
    const named = { origin: o.origin ?? own.origin ?? env.JEV_ORIGIN, upstream: o.upstream ?? own.upstream };
    const to = usable(named.upstream) ?? usable(named.origin);
    try {
      const origin = address("thinWorker: origin (or env.JEV_ORIGIN)", named.origin);
      if (!origin) throw new Error("thinWorker: origin (or env.JEV_ORIGIN) is required");
      const upstream = address("thinWorker: upstream", named.upstream) ?? origin;
      const rt = presetRuntime({
        ...o,
        config: { ...o.config, jev: { provider: "backend", endpoint: origin, ...o.config?.jev } },
      }, env);
      return { rt, to: upstream };
    } catch (e) {
      return { error: e, to };
    }
  };
  return {
    async fetch(request, env, ctx) {
      const jevPath = originEndpoint(request);
      const b = builtFor(env, cache, build);
      if (!b.rt) {
        // unjudged, but never the origin's own endpoints
        if (jevPath) return NOT_FOUND();
        return failOpen(request, forwarder(b.to), b.error);
      }
      if (jevPath && !ownHealth(request, b.rt)) return NOT_FOUND();
      return handle(request, b.rt, forwarder(b.to), ctx);
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
 * wrangler.toml, and TYPESAFE_API_KEY as a secret. `opts` may be a function
 * of env returning the options, upstream included, as for thinWorker.
 */
export function fullWorker<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E, { upstream: string }> | (((env: E) => Options) & { upstream: string }),
): { fetch(request: Request, env: E, ctx?: RequestCtx): Promise<Response> } {
  const cache = new WeakMap<object, Built>();
  const own = attached<{ upstream: string }>(opts);
  const build = (env: E): Built => {
    let o: Options & { upstream?: string };
    try {
      o = resolveOptions<E, { upstream?: string }>(opts, env);
    } catch (e) {
      return { error: e, to: usable(own.upstream) };
    }
    const named = o.upstream ?? own.upstream;
    const to = usable(named);
    try {
      const upstream = address("fullWorker: upstream", named);
      if (!upstream) throw new Error("fullWorker: upstream is required");
      return { rt: presetRuntime(o, env), to: upstream };
    } catch (e) {
      return { error: e, to };
    }
  };
  return {
    async fetch(request, env, ctx) {
      const b = builtFor(env, cache, build);
      if (!b.rt) return failOpen(request, forwarder(b.to), b.error);
      return handle(request, b.rt, forwarder(b.to), ctx);
    },
  };
}

/** Pages Functions middleware: `export const onRequest = pagesMiddleware({...})` in functions/_middleware.ts. */
export function pagesMiddleware<E extends WorkerEnv = WorkerEnv>(
  opts: Resolve<E> = {},
): (context: { request: Request; env: E; next: (req?: Request) => Promise<Response>; waitUntil?: (p: Promise<unknown>) => void }) => Promise<Response> {
  const cache = new WeakMap<object, Runtime>();
  return async (context) => {
    let rt: Runtime;
    try {
      rt = runtimeFor(opts, context.env, cache);
    } catch (e) {
      return failOpen(context.request, (req) => context.next(req), e);
    }
    const ctx: RequestCtx | undefined = context.waitUntil ? { waitUntil: (p) => context.waitUntil!(p) } : undefined;
    return handle(context.request, rt, (req) => context.next(req), ctx);
  };
}
