// Port of core/breaker.lua. Same store keys ("brk:state", "brk:w:<bucket>",
// "brk:probe") so a store shared with another implementation would agree.
import type { CacheLike } from "./rules";

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
}

interface StateRec { state?: number; until_ts?: number }
interface Counters { ok: number; fail: number }

export class Breaker {
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
    dump: () => m,
  };
}

export type { CacheLike };
