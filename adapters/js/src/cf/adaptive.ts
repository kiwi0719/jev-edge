// Port of adapters/openresty/lib/resty/jev/adaptive.lua. Same EWMA, so the
// estimate is comparable across adapters even though the numeric value is
// explicitly outside the parity contract. The three samples (n, mean, var)
// live in ONE document under "adapt" so an observation is one read and one
// write; inside a Durable Object (cf/stores.ts) that pair is atomic.
import type { Store } from "../core/breaker";
import type { JevConfig } from "../core/defaults";

export const KEY = "adapt";

export interface Stats { n: number; mean: number; var: number }

/** What the runtime needs from an adaptive-timeout estimator. */
export interface AdaptiveLike {
  current(): Promise<number>;
  success(ms: number): Promise<void>;
  timeout(firedMs?: number): Promise<void>;
}

/** Pure EWMA step, shared by the in-process class and the Durable Object. */
export function step(s: Stats, ms: number, alpha: number): Stats {
  if (s.n === 0) return { n: 1, mean: ms, var: 0 };
  const diff = ms - s.mean;
  return { n: s.n + 1, mean: s.mean + alpha * diff, var: (1 - alpha) * (s.var + alpha * diff * diff) };
}

export function readStats(v: unknown): Stats {
  const o = (v && typeof v === "object" ? v : {}) as Partial<Stats>;
  return { n: Number(o.n) || 0, mean: Number(o.mean) || 0, var: Number(o.var) || 0 };
}

export interface Tuning { enabled: boolean; floor: number; ceil: number; headroom: number; alpha: number; warmup: number }

export function tuning(cfg: JevConfig): Tuning {
  const floor = Number(cfg.timeout_ms) || 400;
  let ceil = Number(cfg.timeout_max_ms) || 2.5 * floor;
  if (ceil < floor) ceil = floor;
  return {
    enabled: cfg.timeout_adaptive !== false,
    floor,
    ceil,
    headroom: Number(cfg.timeout_headroom) || 1.5,
    alpha: Number(cfg.timeout_alpha) || 0.1,
    warmup: Number(cfg.timeout_warmup) || 20,
  };
}

/** Timeout for the next L2 call, in ms, from a snapshot of the stats. */
export function estimate(t: Tuning, s: Stats): number {
  if (!t.enabled || s.n < t.warmup) return t.floor;
  const est = t.headroom * (s.mean + 2 * Math.sqrt(Math.max(s.var, 0)));
  if (est < t.floor) return t.floor;
  if (est > t.ceil) return t.ceil;
  return Math.floor(est);
}

export class Adaptive implements AdaptiveLike {
  private t: Tuning;

  constructor(private store: Store | undefined, cfg: JevConfig) {
    this.t = tuning(cfg);
  }

  async stats(): Promise<[number, number, number]> {
    if (!this.store) return [0, 0, 0];
    const s = readStats(await this.store.get(KEY));
    return [s.n, s.mean, s.var];
  }

  async current(): Promise<number> {
    if (!this.t.enabled || !this.store) return this.t.floor;
    return estimate(this.t, readStats(await this.store.get(KEY)));
  }

  /**
   * One read, one write. Over a plain Store two isolates can interleave and
   * one observation is lost; that only nudges an estimate that is already
   * a heuristic. Through a JevState stub the runtime uses durableAdaptive()
   * instead, which runs this inside the Durable Object.
   */
  private async observe(ms: number): Promise<void> {
    if (!this.store) return;
    const next = step(readStats(await this.store.get(KEY)), ms, this.t.alpha);
    await this.store.set(KEY, next, 0);
  }

  async success(ms: number): Promise<void> {
    if (this.t.enabled && this.store && ms > 0) await this.observe(ms);
  }

  async timeout(firedMs?: number): Promise<void> {
    if (!this.t.enabled || !this.store) return;
    await this.observe(Math.min((firedMs ?? this.t.floor) * 1.2, this.t.ceil));
  }
}
