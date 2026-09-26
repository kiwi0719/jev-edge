// Cloudflare-backed stores behind core's two interfaces.
//
//   cache   { get(key), set(key, value, ttl) }   fingerprints and reputation
//   store   same shape                           breaker state, adaptive samples
//
// Which platform primitive backs each one is the whole difference between the
// presets, and the part parity does not cover (core/golden/README.md):
//
//   KV              eventually consistent, minimum TTL 60 s. Fine for the
//                   fingerprint cache: a stale entry is a cached verdict.
//   Durable Object  strongly consistent, one per name. Right for breaker
//                   counters and the adaptive timeout, which are wrong if two
//                   isolates each keep their own.
//   memory          per isolate. The fallback when no binding is configured;
//                   documented as "each isolate learns on its own".

import { Breaker, type Store, type BreakerLike, type BreakerConfig, type State } from "../core/breaker.js";
import { Adaptive, tuning, type AdaptiveLike } from "./adaptive.js";
import type { JevConfig } from "../core/defaults.js";

export interface KVLike {
  get(key: string, type: "json"): Promise<unknown>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

const KV_MIN_TTL = 60;

export function kvStore(kv: KVLike, prefix = "jev:"): Store {
  return {
    get: (k) => kv.get(prefix + k, "json"),
    set: async (k, v, ttl) => {
      if (v === null || v === undefined) return kv.delete(prefix + k);
      const opts = ttl > 0 ? { expirationTtl: Math.max(KV_MIN_TTL, Math.ceil(ttl)) } : undefined;
      return kv.put(prefix + k, JSON.stringify(v), opts);
    },
    // Best effort, NOT atomic: KV has no increment, so this is a get and a
    // put, and two isolates (or two PoPs, eventually consistent) incrementing
    // at once can both get the same value. For the subject ring that costs
    // the same lost entry the list layout did, no more. The put always
    // carries the ttl (a KV put without one clears the expiry), so it also
    // extends the counter's life and no `expire` is needed.
    incr: async (k, by, ttl) => {
      const n = (Number(await kv.get(prefix + k, "json")) || 0) + by;
      const opts = ttl > 0 ? { expirationTtl: Math.max(KV_MIN_TTL, Math.ceil(ttl)) } : undefined;
      await kv.put(prefix + k, JSON.stringify(n), opts);
      return n;
    },
  };
}

interface Entry { v: unknown; exp: number }

export interface MemoryStoreOptions {
  /** Most entries kept; past it the least recently used goes. Unbounded (sweep only) when absent. */
  maxEntries?: number;
}

/** How many of the oldest entries each write looks at for expired ones. */
const SWEEP = 8;

/**
 * A Store in this isolate's (or process's) memory. A Map kept in use
 * order: a read of a live entry and every write move it to the end, so the
 * first entries are the least recently used. Each write deletes the expired
 * ones among the SWEEP oldest, so a key never read again does not stay
 * forever, and with `maxEntries` evicts the oldest past it: a flood of
 * distinct texts cannot grow the map without bound. The runtime caps its
 * default cache and subject store and leaves `state` uncapped, so breaker
 * and adaptive keys are never evicted.
 */
export function memoryStore(clock: () => number = () => Date.now() / 1000, opts: MemoryStoreOptions = {}): Store & { readonly size: number } {
  const m = new Map<string, Entry>();
  const max = typeof opts.maxEntries === "number" && opts.maxEntries >= 1 ? Math.floor(opts.maxEntries) : Infinity;
  const dead = (e: Entry, now: number) => e.exp !== 0 && e.exp <= now;
  const put = (k: string, e: Entry) => {
    m.delete(k); // to the end: the most recently used
    m.set(k, e);
    const now = clock();
    let seen = 0;
    for (const [key, old] of m) {
      if (++seen > SWEEP) break;
      if (key !== k && dead(old, now)) m.delete(key);
    }
    while (m.size > max) {
      const oldest = m.keys().next().value as string;
      if (oldest === k) break;
      m.delete(oldest);
    }
  };
  return {
    get: (k) => {
      const e = m.get(k);
      if (!e) return undefined;
      if (dead(e, clock())) {
        m.delete(k);
        return undefined;
      }
      m.delete(k);
      m.set(k, e);
      return e.v;
    },
    set: (k, v, ttl) => {
      if (v === null || v === undefined) m.delete(k);
      else put(k, { v, exp: ttl > 0 ? clock() + ttl : 0 });
    },
    // synchronous, so atomic within the isolate; the ttl applies on creation only
    incr: (k, by, ttl) => {
      const e = m.get(k);
      const live = e !== undefined && !dead(e, clock());
      const n = (live ? Number(e.v) || 0 : 0) + by;
      put(k, { v: n, exp: live ? e.exp : ttl > 0 ? clock() + ttl : 0 });
      return n;
    },
    expire: (k, ttl) => {
      const e = m.get(k);
      if (e && !dead(e, clock())) e.exp = ttl > 0 ? clock() + ttl : 0;
    },
    /** Entries held, expired ones not swept yet included. */
    get size() {
      return m.size;
    },
  };
}

/**
 * A Durable Object holding breaker and adaptive state for every isolate. One
 * instance per deployment (`idFromName("jev-edge")`, or the name passed as
 * `{ namespace, name }`). Export it from your Worker and bind it as JEV_STATE.
 *
 * Two kinds of endpoint:
 *   /get, /set, /incr, /expire  the plain Store interface (durableStore);
 *                               /incr is atomic for the same reason as below
 *   /breaker/<op>, /adaptive/<op>  the operation runs HERE, against this
 *                               object's storage, with the same Breaker and
 *                               Adaptive classes the in-process runtime uses.
 *                               One fetch per operation, and atomic: a
 *                               Durable Object delivers one request at a time
 *                               while the handler only awaits its own storage.
 */
export interface DOStateLike {
  storage: {
    get(key: string): Promise<unknown>;
    put(key: string, value: unknown): Promise<void>;
    delete(key: string): Promise<boolean>;
  };
}

function storeOver(state: DOStateLike, clock: () => number): Store {
  return {
    get: async (k) => {
      const e = (await state.storage.get(k)) as Entry | undefined;
      if (!e || (e.exp && e.exp <= clock())) return undefined;
      return e.v;
    },
    set: async (k, v, ttl) => {
      if (v === null || v === undefined) await state.storage.delete(k);
      else await state.storage.put(k, { v, exp: ttl && ttl > 0 ? clock() + ttl : 0 } satisfies Entry);
    },
    // a read-modify-write, atomic only because it runs inside the Durable
    // Object (one request at a time); the ttl applies on creation only
    incr: async (k, by, ttl) => {
      const e = (await state.storage.get(k)) as Entry | undefined;
      const live = e !== undefined && !(e.exp && e.exp <= clock());
      const n = (live ? Number(e.v) || 0 : 0) + by;
      await state.storage.put(k, { v: n, exp: live ? e.exp : ttl && ttl > 0 ? clock() + ttl : 0 } satisfies Entry);
      return n;
    },
    expire: async (k, ttl) => {
      const e = (await state.storage.get(k)) as Entry | undefined;
      if (!e || (e.exp && e.exp <= clock())) return;
      await state.storage.put(k, { v: e.v, exp: ttl && ttl > 0 ? clock() + ttl : 0 } satisfies Entry);
    },
  };
}

interface BreakerOp { op: "allow" | "state" | "trip" | "success" | "failure" | "release"; cfg?: BreakerConfig; now?: number }
interface AdaptiveOp { op: "current" | "success" | "timeout"; cfg: JevConfig; ms?: number }

export class JevState {
  private store: Store;
  private clock = () => Date.now() / 1000;

  constructor(state: DOStateLike) {
    this.store = storeOver(state, this.clock);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    const body = (await request.json()) as { key?: string; value?: unknown; ttl?: number; by?: number; op?: string; cfg?: unknown; now?: number; ms?: number };
    if (url.pathname === "/get") {
      const v = await this.store.get(String(body.key));
      return Response.json({ value: v ?? null });
    }
    if (url.pathname === "/set") {
      await this.store.set(String(body.key), body.value ?? null, body.ttl ?? 0);
      return Response.json({ ok: true });
    }
    if (url.pathname === "/incr") {
      const by = typeof body.by === "number" ? body.by : 1;
      return Response.json({ value: await this.store.incr!(String(body.key), by, body.ttl ?? 0) });
    }
    if (url.pathname === "/expire") {
      await this.store.expire!(String(body.key), body.ttl ?? 0);
      return Response.json({ ok: true });
    }
    if (url.pathname === "/breaker") {
      const b = new Breaker(this.store, this.clock, (body.cfg as BreakerConfig | undefined) ?? {});
      switch (body.op) {
        case "allow": return Response.json({ value: await b.allow() });
        case "state": return Response.json({ value: await b.state() });
        case "trip": await b.trip(typeof body.now === "number" ? body.now : undefined); return Response.json({ ok: true });
        case "success": await b.success(); return Response.json({ ok: true });
        case "failure": await b.failure(); return Response.json({ ok: true });
        case "release": await b.release(); return Response.json({ ok: true });
        default: return new Response("bad breaker op", { status: 400 });
      }
    }
    if (url.pathname === "/adaptive") {
      const a = new Adaptive(this.store, (body.cfg as JevConfig | undefined) ?? { timeout_ms: 400 });
      switch (body.op) {
        case "current": return Response.json({ value: await a.current() });
        case "success": await a.success(Number(body.ms) || 0); return Response.json({ ok: true });
        case "timeout": await a.timeout(typeof body.ms === "number" ? body.ms : undefined); return Response.json({ ok: true });
        default: return new Response("bad adaptive op", { status: 400 });
      }
    }
    return new Response("not found", { status: 404 });
  }
}

export interface DOStubLike {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}

/** The Durable Object namespace binding (env.JEV_STATE), not a stub made from it. */
export interface DONamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): DOStubLike;
}

/** The JevState object a namespace given as is resolves to: `idFromName` of this. */
export const STATE_OBJECT = "jev-edge";

/**
 * A namespace and the name of the JevState object to use in it, for more
 * than one breaker and adaptive timeout on one binding (a Worker per
 * environment or per upstream sharing the class): `{ namespace:
 * env.JEV_STATE, name: "staging" }`. Without `name`, STATE_OBJECT.
 */
export interface DONamed {
  namespace: DONamespaceLike;
  name?: string;
}

/** Where the durable* helpers find JevState: a namespace, a namespace and a name, or a stub. */
export type StateTarget = DONamespaceLike | DONamed | DOStubLike;

/**
 * A Durable Object stub, told apart from a Store by the one thing it always
 * has and a Store never does: a `fetch` method. Not by what it lacks: a
 * workerd stub answers every property name (each one an RPC method on
 * compatibility dates from 2024-04-03, the old Fetcher get / put / delete
 * before that), so `"get" in stub` is true for every real one.
 */
export function isStub(x: unknown): x is DOStubLike {
  return (typeof x === "object" || typeof x === "function") && x !== null && typeof (x as DOStubLike).fetch === "function";
}

/** A namespace binding: idFromName and get, and no `fetch`, which every stub has. */
export function isNamespace(x: unknown): x is DONamespaceLike {
  if (typeof x !== "object" || x === null || isStub(x)) return false;
  const n = x as DONamespaceLike;
  return typeof n.idFromName === "function" && typeof n.get === "function";
}

/**
 * `{ namespace, name }`: an object with a `namespace` key and no `get`
 * method. Not a stub, which has every key, nor a Store, which always has
 * `get` and may well carry a `namespace` of its own (a key prefix, say).
 */
export function isNamed(x: unknown): x is DONamed {
  return typeof x === "object" && x !== null && !isStub(x) && "namespace" in x && typeof (x as { get?: unknown }).get !== "function";
}

/** A namespace, `{ namespace, name }` or a stub: what createRuntime runs through JevState. */
export function isStateTarget(x: unknown): x is StateTarget {
  return isStub(x) || isNamespace(x) || isNamed(x);
}

// A stub is an I/O object of the request that made it: workerd refuses it in
// any later one. A namespace is not, so a runtime given one (and kept at
// module scope, or across requests by a preset) makes its stub per call;
// idFromName is a hash and get() no round trip.
//
// workerd's refusal is raised in the calling isolate, before anything is
// sent: an Error with this message and no `remote` property. An exception
// thrown inside the Durable Object reaches the caller with `remote: true`
// (checked in Miniflare 4.20260714 / workerd 1.20260714, fetch stubs on
// compatibility dates before and after RPC), whatever its message, and is the
// caller's to handle like any other.
const CROSS_REQUEST = /Cannot perform I\/O on behalf of a different request/;
const STALE_STUB =
  "jev-edge: a Durable Object stub made in one request was used in a later one, which workerd refuses " +
  '("Cannot perform I/O on behalf of a different request"). From now on this isolate keeps the breaker, ' +
  "adaptive timeout and any durableStore on this stub in its own memory, apart from every other isolate; " +
  "logged once per stub and isolate. Fix: pass the namespace, createRuntime({ state: env.JEV_STATE }) or " +
  "durableStore(env.JEV_STATE), which makes a stub per call; or build the runtime per request.";

/** workerd's refusal of a stub used past its request, and nothing else. */
function isCrossRequest(e: unknown): boolean {
  if (typeof e === "object" && e !== null && (e as { remote?: unknown }).remote === true) return false;
  return CROSS_REQUEST.test(e instanceof Error ? e.message : String(e));
}

const resolved = new WeakSet<object>();
const guards = new WeakMap<object, DOStubLike>();

/**
 * A stub kept past its request answers every call with the cross-request
 * error, which would fail open every request after the first. Instead the
 * first such error is logged (once per stub, in each isolate that hits it)
 * and this stub's calls go from then on to a JevState over isolate memory.
 * That state is per isolate, like a runtime's without a binding, and the
 * JevState takes one request at a time, as the Durable Object's input gate
 * would: an incr, a breaker record or a half-open probe claim is atomic
 * within the isolate, though no longer across isolates. Any other error,
 * including one thrown inside the object, is the caller's, as before.
 */
function guarded(stub: DOStubLike): DOStubLike {
  const known = guards.get(stub);
  if (known) return known;
  let local: ((req: Request) => Promise<Response>) | undefined;
  const g: DOStubLike = {
    fetch: async (input, init) => {
      if (local) return local(new Request(input, init));
      try {
        return await stub.fetch(input, init);
      } catch (e) {
        if (!isCrossRequest(e)) throw e;
        if (!local) {
          console.error(STALE_STUB);
          local = isolateState();
        }
        return local(new Request(input, init));
      }
    },
  };
  guards.set(stub, g);
  resolved.add(g);
  return g;
}

/** A JevState over this isolate's memory, one request at a time. */
function isolateState(): (req: Request) => Promise<Response> {
  const m = new Map<string, unknown>();
  const d = new JevState({ storage: { get: async (k) => m.get(k), put: async (k, v) => { m.set(k, v); }, delete: async (k) => m.delete(k) } });
  let queue: Promise<unknown> = Promise.resolve();
  return (req) => {
    const p = queue.then(() => d.fetch(req));
    queue = p.catch(() => {});
    return p;
  };
}

/**
 * What the durable* helpers call: for a namespace, a stub made per call
 * (`idFromName(STATE_OBJECT)`, or the name given with it); for a stub, the
 * stub guarded against use past its request. Idempotent. Throws on anything
 * else, and on a `{ namespace, name }` whose namespace is not one (a binding
 * missing from this environment) or whose name is not a non-empty string.
 */
export function stateStub(target: StateTarget): DOStubLike {
  if (resolved.has(target)) return target as DOStubLike;
  if (isStub(target)) return guarded(target);
  let ns: DONamespaceLike;
  let name = STATE_OBJECT;
  if (isNamespace(target)) {
    ns = target;
  } else if (isNamed(target)) {
    if (!isNamespace(target.namespace)) {
      throw new TypeError("jev-edge: { namespace, name }: namespace is not a Durable Object namespace (idFromName and get); is the binding configured?");
    }
    if (target.name !== undefined && (typeof target.name !== "string" || target.name === "")) {
      throw new TypeError("jev-edge: { namespace, name }: name must be a non-empty string");
    }
    ns = target.namespace;
    name = target.name ?? STATE_OBJECT;
  } else {
    throw new TypeError("jev-edge: not a Durable Object namespace, { namespace, name } or stub");
  }
  const s: DOStubLike = { fetch: (input, init) => ns.get(ns.idFromName(name)).fetch(input, init) };
  resolved.add(s);
  return s;
}

function caller(target: StateTarget) {
  const stub = stateStub(target);
  return async (path: string, payload: unknown): Promise<{ value?: unknown; ok?: boolean }> => {
    const res = await stub.fetch("https://jev-state" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`jev-state ${path}: http ${res.status}`);
    return (await res.json()) as { value?: unknown; ok?: boolean };
  };
}

/** The plain Store interface over JevState (a namespace, `{ namespace, name }` or a stub): two hops per read-modify-write, one (atomic) per incr. */
export function durableStore(target: StateTarget): Store {
  const call = caller(target);
  return {
    get: async (k) => (await call("/get", { key: k })).value ?? undefined,
    set: async (k, v, ttl) => {
      await call("/set", { key: k, value: v ?? null, ttl });
    },
    incr: async (k, by, ttl) => Number((await call("/incr", { key: k, by, ttl })).value),
    expire: async (k, ttl) => {
      await call("/expire", { key: k, ttl });
    },
  };
}

/** A breaker whose every operation is one fetch, executed inside the Durable Object. */
export function durableBreaker(target: StateTarget, cfg: BreakerConfig = {}): BreakerLike {
  const call = caller(target);
  const op = (o: BreakerOp["op"], extra: Record<string, unknown> = {}) => call("/breaker", { op: o, cfg, ...extra });
  return {
    state: async () => (await op("state")).value as State,
    allow: async () => (await op("allow")).value === true,
    trip: async (now?: number) => { await op("trip", now === undefined ? {} : { now }); },
    success: async () => { await op("success"); },
    failure: async () => { await op("failure"); },
    release: async () => { await op("release"); },
  };
}

/** Adaptive timeout whose observe() runs inside the Durable Object: one fetch, atomic. */
export function durableAdaptive(target: StateTarget, cfg: JevConfig): AdaptiveLike {
  const call = caller(target);
  const t = tuning(cfg);
  const op = (o: AdaptiveOp["op"], extra: Record<string, unknown> = {}) => call("/adaptive", { op: o, cfg, ...extra });
  return {
    current: async () => (t.enabled ? Number((await op("current")).value) || t.floor : t.floor),
    success: async (ms) => { if (t.enabled && ms > 0) await op("success", { ms }); },
    timeout: async (firedMs) => { if (t.enabled) await op("timeout", firedMs === undefined ? {} : { ms: firedMs }); },
  };
}
