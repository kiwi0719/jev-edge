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

import type { Store } from "../core/breaker";

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
 * A Durable Object exposing the store interface over fetch. One instance per
 * deployment (`idFromName("jev-edge")`) holds breaker and adaptive state for
 * every isolate. Export it from your Worker and bind it as JEV_STATE.
 */
export interface DOStateLike {
  storage: {
    get(key: string): Promise<unknown>;
    put(key: string, value: unknown): Promise<void>;
    delete(key: string): Promise<boolean>;
  };
}

export class JevState {
  constructor(private state: DOStateLike) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    const body = (await request.json()) as { key: string; value?: unknown; ttl?: number };
    const now = Date.now() / 1000;
    if (url.pathname === "/get") {
      const e = (await this.state.storage.get(body.key)) as Entry | undefined;
      if (!e || (e.exp && e.exp <= now)) return Response.json({ value: null });
      return Response.json({ value: e.v });
    }
    if (url.pathname === "/set") {
      if (body.value === null || body.value === undefined) await this.state.storage.delete(body.key);
      else await this.state.storage.put(body.key, { v: body.value, exp: body.ttl && body.ttl > 0 ? now + body.ttl : 0 } satisfies Entry);
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  }
}

export interface DOStubLike {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}

export function durableStore(stub: DOStubLike): Store {
  const call = async (path: string, payload: unknown): Promise<unknown> => {
    const res = await stub.fetch("https://jev-state" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return (await res.json()) as unknown;
  };
  return {
    get: async (k) => {
      const r = (await call("/get", { key: k })) as { value: unknown };
      return r.value ?? undefined;
    },
    set: async (k, v, ttl) => {
      await call("/set", { key: k, value: v ?? null, ttl });
    },
  };
}
