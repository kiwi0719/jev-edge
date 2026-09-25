// Port of core/breaker.lua: a circuit breaker over tumbling windows of
// `window_s` seconds. Same store keys ("brk:state", "brk:w:<bucket>",
// "brk:probe") so a store shared with another implementation would agree.
import type { CacheLike } from "./rules.js";

export const CLOSED = 0;
export const OPEN = 1;
export const HALF_OPEN = 2;
export type State = typeof CLOSED | typeof OPEN | typeof HALF_OPEN;

export interface BreakerConfig {
  window_s?: number;
  min_samples?: number;
  fail_ratio?: number;
  open_s?: number;
  key_prefix?: string;
}

export const DEFAULTS: Required<BreakerConfig> = {
  window_s: 60,
  min_samples: 20,
  fail_ratio: 0.5,
  open_s: 30,
  key_prefix: "brk:",
};

export interface Store {
  get(key: string): unknown | Promise<unknown>;
  set(key: string, value: unknown, ttl: number): void | Promise<void>;
  /** Optional: add `by` to a numeric key and return the new value, creating
   *  it (with `ttl`) when absent. Atomic in the memory and Durable Object
   *  stores; the subject ring (core/subject.ts) uses it and falls back to a
   *  read-modify-write list on a store without it. */
  incr?(key: string, by: number, ttl: number): number | Promise<number>;
  /** Optional: reset a key's ttl without rewriting it. */
  expire?(key: string, ttl: number): void | Promise<void>;
}

interface StateRec { state?: number; until_ts?: number }
interface Counters { ok: number; fail: number }

/** What core and the runtime need from a breaker; `Breaker` is the in-process
 *  implementation, `durableBreaker` (cf/stores.ts) the one that runs it inside
 *  a Durable Object. */
export interface BreakerLike {
  state(): Promise<State>;
  allow(): Promise<boolean>;
  trip(now?: number): Promise<void>;
  success(): Promise<void>;
  failure(): Promise<void>;
  /** The admitted request said nothing about the provider's health: count
   *  nothing, and in half-open give the probe back. Optional for breakers
   *  written before it; without it the probe claim runs out after open_s. */
  release?(): Promise<void>;
}

export class Breaker implements BreakerLike {
  constructor(private store: Store, private clock: () => number, private cfg: BreakerConfig = {}) {}

  private c<K extends keyof Required<BreakerConfig>>(k: K): Required<BreakerConfig>[K] {
    return (this.cfg[k] ?? DEFAULTS[k]) as Required<BreakerConfig>[K];
  }

  private bucket(now: number): number {
    return Math.floor(now / this.c("window_s"));
  }

  private async counters(now: number): Promise<[string, Counters]> {
    const key = this.c("key_prefix") + "w:" + this.bucket(now);
    const c = (await this.store.get(key)) as Counters | undefined;
    if (!c || typeof c !== "object") return [key, { ok: 0, fail: 0 }];
    return [key, c];
  }

  async state(): Promise<State> {
    const s = (await this.store.get(this.c("key_prefix") + "state")) as StateRec | undefined;
    if (!s || typeof s !== "object") return CLOSED;
    const now = this.clock();
    if (s.state === OPEN) {
      if (now >= (s.until_ts ?? 0)) return HALF_OPEN;
      return OPEN;
    }
    return (s.state as State | undefined) ?? CLOSED;
  }

  /** Should a request try L2 right now? In HALF_OPEN one probe per open period. */
  async allow(): Promise<boolean> {
    const st = await this.state();
    if (st === CLOSED) return true;
    if (st === OPEN) return false;
    const key = this.c("key_prefix") + "probe";
    if (await this.store.get(key)) return false;
    await this.store.set(key, true, this.c("open_s"));
    return true;
  }

  private async record(ok: boolean): Promise<void> {
    const now = this.clock();
    const [key, c] = await this.counters(now);
    if (ok) c.ok += 1;
    else c.fail += 1;
    await this.store.set(key, c, this.c("window_s") * 2);

    const st = await this.state();
    if (st === HALF_OPEN) {
      if (ok) {
        await this.store.set(this.c("key_prefix") + "state", { state: CLOSED }, 0);
        await this.store.set(this.c("key_prefix") + "probe", null, 0);
        // The window that tripped us is still full of failures; start the
        // closed period from a clean count or the next success re-trips.
        await this.store.set(key, { ok: 1, fail: 0 }, this.c("window_s") * 2);
      } else {
        await this.trip(now);
      }
      return;
    }
    const total = c.ok + c.fail;
    if (st === CLOSED && total >= this.c("min_samples") && c.fail / total >= this.c("fail_ratio")) {
      await this.trip(now);
    }
  }

  async trip(now?: number): Promise<void> {
    const t = now ?? this.clock();
    await this.store.set(this.c("key_prefix") + "state", { state: OPEN, until_ts: t + this.c("open_s") }, 0);
    await this.store.set(this.c("key_prefix") + "probe", null, 0);
  }

  success(): Promise<void> {
    return this.record(true);
  }

  failure(): Promise<void> {
    return this.record(false);
  }

  /** Port of breaker.release: in half-open the next request probes instead
   *  of L2 staying off until the claim expires, and nothing re-trips. */
  async release(): Promise<void> {
    if ((await this.state()) === HALF_OPEN) await this.store.set(this.c("key_prefix") + "probe", null, 0);
  }
}

/** In-memory store for tests and for the per-isolate fallback. */
export function memoryStore(): Store & { dump(): Map<string, unknown> } {
  const m = new Map<string, unknown>();
  return {
    get: (k) => m.get(k),
    set: (k, v) => {
      if (v === null || v === undefined) m.delete(k);
      else m.set(k, v);
    },
    // synchronous, so atomic within the process; no ttl here, as for set
    incr: (k, by) => {
      const n = (Number(m.get(k)) || 0) + by;
      m.set(k, n);
      return n;
    },
    dump: () => m,
  };
}

export type { CacheLike };
