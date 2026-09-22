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

import { Breaker, type Store, type BreakerLike, type BreakerConfig, type State } from "../core/breaker";
import { Adaptive, tuning, type AdaptiveLike } from "./adaptive";
import type { JevConfig } from "../core/defaults";

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
  };
}

interface Entry { v: unknown; exp: number }

export function memoryStore(clock: () => number = () => Date.now() / 1000): Store {
  const m = new Map<string, Entry>();
  return {
    get: (k) => {
      const e = m.get(k);
      if (!e) return undefined;
      if (e.exp && e.exp <= clock()) {
        m.delete(k);
        return undefined;
      }
      return e.v;
    },
    set: (k, v, ttl) => {
      if (v === null || v === undefined) m.delete(k);
      else m.set(k, { v, exp: ttl > 0 ? clock() + ttl : 0 });
    },
  };
}

/**
 * A Durable Object holding breaker and adaptive state for every isolate. One
 * instance per deployment (`idFromName("jev-edge")`). Export it from your
 * Worker and bind it as JEV_STATE.
 *
 * Two kinds of endpoint:
 *   /get, /set                  the plain Store interface (durableStore)
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
  };
}

interface BreakerOp { op: "allow" | "state" | "trip" | "success" | "failure"; cfg?: BreakerConfig; now?: number }
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
    const body = (await request.json()) as { key?: string; value?: unknown; ttl?: number; op?: string; cfg?: unknown; now?: number; ms?: number };
    if (url.pathname === "/get") {
      const v = await this.store.get(String(body.key));
      return Response.json({ value: v ?? null });
    }
    if (url.pathname === "/set") {
      await this.store.set(String(body.key), body.value ?? null, body.ttl ?? 0);
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

function caller(stub: DOStubLike) {
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

/** The plain Store interface over a JevState stub: two hops per read-modify-write. */
export function durableStore(stub: DOStubLike): Store {
  const call = caller(stub);
  return {
    get: async (k) => (await call("/get", { key: k })).value ?? undefined,
    set: async (k, v, ttl) => {
      await call("/set", { key: k, value: v ?? null, ttl });
    },
  };
}

/** A breaker whose every operation is one fetch, executed inside the Durable Object. */
export function durableBreaker(stub: DOStubLike, cfg: BreakerConfig = {}): BreakerLike {
  const call = caller(stub);
  const op = (o: BreakerOp["op"], extra: Record<string, unknown> = {}) => call("/breaker", { op: o, cfg, ...extra });
  return {
    state: async () => (await op("state")).value as State,
    allow: async () => (await op("allow")).value === true,
    trip: async (now?: number) => { await op("trip", now === undefined ? {} : { now }); },
    success: async () => { await op("success"); },
    failure: async () => { await op("failure"); },
  };
}

/** Adaptive timeout whose observe() runs inside the Durable Object: one fetch, atomic. */
export function durableAdaptive(stub: DOStubLike, cfg: JevConfig): AdaptiveLike {
  const call = caller(stub);
  const t = tuning(cfg);
  const op = (o: AdaptiveOp["op"], extra: Record<string, unknown> = {}) => call("/adaptive", { op: o, cfg, ...extra });
  return {
    current: async () => (t.enabled ? Number((await op("current")).value) || t.floor : t.floor),
    success: async (ms) => { if (t.enabled && ms > 0) await op("success", { ms }); },
    timeout: async (firedMs) => { if (t.enabled) await op("timeout", firedMs === undefined ? {} : { ms: firedMs }); },
  };
}
