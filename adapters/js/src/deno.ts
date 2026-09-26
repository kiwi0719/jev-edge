// Deno Deploy (and plain `deno serve`) preset: the full core in the isolate,
// allowed requests proxied to `upstream`, optional Deno KV for the stores.
//
//   Deno.serve(denoHandler({ upstream: "https://app.internal.example.com", kv: await Deno.openKv() }))
//
// Nothing here depends on Deno's types: Deno KV is typed structurally
// (DenoKvLike), so the package builds and tests on Node.
//
// Two things differ from the Cloudflare presets:
//
//   client IP   Deno.serve hands the peer address to the handler as
//               `info.remoteAddr.hostname`. It is appended to X-Forwarded-For,
//               exactly as nodeMiddleware appends the socket address, so with
//               the default `client_ip.trusted_hops = 1` the client IP is the
//               peer and never a value the client wrote.
//   waitUntil   Deno.serve has none. The subject write is fire-and-forget: it
//               is not awaited on the request path and the isolate normally
//               lives long enough to finish it, but nothing guarantees that.
//               A lost write is one missing trajectory entry, nothing more.
//
// br request bodies: decodeBody imports `node:zlib` dynamically, and Deno
// resolves `node:` specifiers through its Node compatibility layer (Deploy
// included), so brotli decoding works here as it does on Node.
import { createRuntime, handle, failOpen, type Options, type Runtime } from "./runtime.js";
import { upstreamUrl } from "./cloudflare.js";
import type { Store } from "./core/breaker.js";

// ---------------------------------------------------------------------------
// Deno KV store
// ---------------------------------------------------------------------------

/** A Deno KV key: an array of parts. Only string parts are used here. */
export type DenoKvKey = readonly string[];

/** The subset of Deno.KvEntryMaybe this module reads. */
export interface DenoKvEntryLike {
  value: unknown;
  versionstamp: string | null;
}

/** The subset of Deno.AtomicOperation this module uses. */
export interface DenoKvAtomicLike {
  check(...checks: { key: DenoKvKey; versionstamp: string | null }[]): DenoKvAtomicLike;
  set(key: DenoKvKey, value: unknown, opts?: { expireIn?: number }): DenoKvAtomicLike;
  commit(): Promise<{ ok: boolean }>;
}

/** Deno KV's read consistency: "strong" (the default) reads the newest
 *  value from the primary region; "eventual" may read a slightly stale one
 *  from a nearby replica, with lower latency. */
export type DenoKvConsistency = "strong" | "eventual";

/** The subset of Deno.Kv this module uses; `await Deno.openKv()` satisfies it. */
export interface DenoKvLike {
  get(key: DenoKvKey, opts?: { consistency?: DenoKvConsistency }): Promise<DenoKvEntryLike>;
  /** Several keys in one round trip, entries in key order (Deno KV takes at
   *  most 10 per call). Optional here, so a KV-like without it still works:
   *  the store then reads the keys one get each, in parallel. */
  getMany?(keys: DenoKvKey[], opts?: { consistency?: DenoKvConsistency }): Promise<DenoKvEntryLike[]>;
  set(key: DenoKvKey, value: unknown, opts?: { expireIn?: number }): Promise<unknown>;
  delete(key: DenoKvKey): Promise<void>;
  atomic(): DenoKvAtomicLike;
}

/** Stored shape: the value and its expiry (epoch seconds, 0 = none). Deno KV
 *  deletes an expired key "at some point after" expireIn, so reads check the
 *  expiry themselves, as the memory and Durable Object stores do. */
interface Entry { v: unknown; exp: number }

/** Retries for one incr / expire before giving up. Each failed commit means
 *  another writer's commit succeeded, so this bounds contention, not latency. */
const MAX_CAS_ATTEMPTS = 64;

/** The most keys Deno KV reads in one getMany. */
const GET_MANY_MAX = 10;

export interface DenoKvStoreOptions {
  /** How plain reads (get, getMany) read: "strong" (default) or "eventual".
   *  The check-and-set loops of incr and expire always read strong: they
   *  need the current versionstamp, and a stale one only fails the commit. */
  consistency?: DenoKvConsistency;
}

function live(e: unknown, now: number): e is Entry {
  return typeof e === "object" && e !== null && "v" in e && !((e as Entry).exp && (e as Entry).exp <= now);
}

function expireIn(ttl: number): { expireIn: number } | undefined {
  return ttl > 0 ? { expireIn: Math.max(1, Math.ceil(ttl * 1000)) } : undefined;
}

/**
 * A Store over Deno KV. Keys are `[...prefix, key]`; values are stored as-is
 * (Deno KV serialises with structured clone, no JSON round trip). ttl is in
 * seconds, as everywhere in core, and becomes `expireIn` in milliseconds.
 *
 * `incr` and `expire` are check-and-set loops on `kv.atomic()`: read the
 * entry and its versionstamp, commit only if the versionstamp is unchanged,
 * retry otherwise. So the subject ring's counter is atomic across isolates
 * and regions, unlike the Cloudflare KV store's get-then-put. The breaker's
 * counters use plain get / set (core's Breaker is a read-modify-write), so
 * with this store they are shared across isolates but can lose an increment
 * under contention; that makes the breaker a little slower to trip, never
 * wrong about a request.
 *
 * `opts.consistency = "eventual"` makes plain reads (get, getMany) read from
 * the nearest replica: right for the verdict cache, whose entries a stale
 * read at worst judges again, and wrong for the breaker state and the
 * subject store. getMany reads several keys in one round trip each 10 keys
 * (kv.getMany), which the subject ring's load uses for its slots.
 */
export function denoKvStore(
  kv: DenoKvLike, prefix: DenoKvKey = ["jev"], clock: () => number = () => Date.now() / 1000,
  opts: DenoKvStoreOptions = {},
): Store {
  const key = (k: string): DenoKvKey => [...prefix, k];
  // strong is Deno KV's default: pass nothing, as before
  const read = opts.consistency === "eventual" ? { consistency: "eventual" as const } : undefined;
  const value = (res: DenoKvEntryLike | undefined): unknown =>
    res && live(res.value, clock()) ? (res.value as Entry).v : undefined;

  async function cas(k: string, update: (cur: Entry | undefined, now: number) => [Entry, number] | null): Promise<Entry | undefined> {
    for (let i = 0; i < MAX_CAS_ATTEMPTS; i++) {
      const res = await kv.get(key(k));
      const now = clock();
      const cur = live(res.value, now) ? (res.value as Entry) : undefined;
      const next = update(cur, now);
      if (!next) return cur;
      const [e, ttlLeft] = next;
      const { ok } = await kv.atomic().check({ key: key(k), versionstamp: res.versionstamp }).set(key(k), e, expireIn(ttlLeft)).commit();
      if (ok) return e;
    }
    throw new Error("denoKvStore: too much contention on " + k);
  }

  return {
    get: async (k) => value(await (read ? kv.get(key(k), read) : kv.get(key(k)))),
    // in batches of GET_MANY_MAX, the batches at once
    getMany: async (ks) => {
      const getMany = kv.getMany?.bind(kv);
      if (!getMany) return Promise.all(ks.map((k) => (read ? kv.get(key(k), read) : kv.get(key(k))).then(value)));
      const batches: Promise<DenoKvEntryLike[]>[] = [];
      for (let i = 0; i < ks.length; i += GET_MANY_MAX) {
        const part = ks.slice(i, i + GET_MANY_MAX).map(key);
        batches.push(read ? getMany(part, read) : getMany(part));
      }
      return (await Promise.all(batches)).flat().map(value);
    },
    set: async (k, v, ttl) => {
      if (v === null || v === undefined) return kv.delete(key(k));
      await kv.set(key(k), { v, exp: ttl > 0 ? clock() + ttl : 0 } satisfies Entry, expireIn(ttl));
    },
    // atomic; the ttl applies on creation only, as in the memory store
    incr: async (k, by, ttl) => {
      const e = await cas(k, (cur, now) => {
        if (cur) return [{ v: (Number(cur.v) || 0) + by, exp: cur.exp }, cur.exp ? cur.exp - now : 0];
        return [{ v: by, exp: ttl > 0 ? now + ttl : 0 }, ttl];
      });
      return Number(e!.v);
    },
    // Deno KV cannot change a key's expiry alone: rewrite the same value
    // with the new one, under the same check-and-set.
    expire: async (k, ttl) => {
      await cas(k, (cur, now) => (cur ? [{ v: cur.v, exp: ttl > 0 ? now + ttl : 0 }, ttl] : null));
    },
  };
}

// ---------------------------------------------------------------------------
// Deno.serve handler
// ---------------------------------------------------------------------------

/** The subset of Deno.ServeHandlerInfo this module reads. */
export interface DenoServeInfoLike {
  remoteAddr?: { hostname?: string; transport?: string };
}

export interface DenoOptions extends Options {
  /** Where allowed requests go: its origin plus the request's path and query. */
  upstream: string;
  /** Deno KV (`await Deno.openKv()`): backs the cache, the breaker / adaptive
   *  state and the subject store unless `cache`, `state` or `subjectStore`
   *  is given. Memory per isolate without it. */
  kv?: DenoKvLike;
}

/** The request as the runtime should see it: the peer appended to X-Forwarded-For. */
function withPeer(request: Request, info?: DenoServeInfoLike): Request {
  const peer = info?.remoteAddr?.hostname;
  if (!peer) return request;
  const headers = new Headers(request.headers);
  const xff = headers.get("x-forwarded-for");
  headers.set("x-forwarded-for", xff ? xff + ", " + peer : peer);
  return new Request(request, { headers });
}

/**
 * `Deno.serve(denoHandler({ upstream, kv, config }))`. One runtime per
 * isolate, created on the first request. Allowed requests go to `upstream`
 * with X-Jev-* attached and X-Forwarded-For carrying the peer; redirects from
 * the upstream are passed back, not followed. Blocked requests get the 403.
 * GET /_jev/health is served here unless `health: false`.
 */
export function denoHandler(opts: DenoOptions): (req: Request, info?: DenoServeInfoLike) => Promise<Response> {
  if (!opts.upstream) throw new Error("denoHandler: upstream is required");
  let rt: Runtime | undefined;
  const runtime = (): Runtime => {
    if (rt) return rt;
    const { upstream: _u, kv, ...o } = opts;
    if (kv) {
      // the verdict cache (and rep: records) reads the nearest replica: a
      // stale miss is one more judge call, a stale hit what KV caches
      // elsewhere accept; the breaker state and the subject store read strong
      o.cache ??= denoKvStore(kv, ["jev", "cache"], undefined, { consistency: "eventual" });
      o.state ??= denoKvStore(kv, ["jev", "state"]);
      o.subjectStore ??= denoKvStore(kv, ["jev", "subject"]);
    }
    return (rt = createRuntime(o));
  };
  const forward = (fwd: Request) => fetch(new Request(new Request(upstreamUrl(fwd.url, opts.upstream), fwd), { redirect: "manual" }));
  return async (req, info) => {
    let request = req;
    let r: Runtime;
    try {
      request = withPeer(req, info);
      r = runtime();
    } catch (e) {
      // a config createRuntime refuses: forwarded unjudged, as on any adapter error
      return failOpen(request, forward, e);
    }
    // no waitUntil on Deno.serve: the subject write is fire-and-forget
    return handle(request, r, forward);
  };
}
