// Port of adapters/openresty/lib/resty/jev/adaptive.lua. Same keys, same
// EWMA, so the estimate is comparable across adapters even though the
// numeric value is explicitly outside the parity contract.
import type { Store } from "../core/breaker";
import type { JevConfig } from "../core/defaults";

const KEY_N = "adapt:n";
const KEY_MEAN = "adapt:mean";
const KEY_VAR = "adapt:var";

export class Adaptive {
  private enabled: boolean;
  private floor: number;
  private ceil: number;
  private headroom: number;
  private alpha: number;
  private warmup: number;

  constructor(private store: Store | undefined, cfg: JevConfig) {
    this.enabled = cfg.timeout_adaptive !== false;
    this.floor = Number(cfg.timeout_ms) || 400;
    this.ceil = Number(cfg.timeout_max_ms) || 2.5 * this.floor;
    if (this.ceil < this.floor) this.ceil = this.floor;
    this.headroom = Number(cfg.timeout_headroom) || 1.5;
    this.alpha = Number(cfg.timeout_alpha) || 0.1;
    this.warmup = Number(cfg.timeout_warmup) || 20;
  }

  async stats(): Promise<[number, number, number]> {
    if (!this.store) return [0, 0, 0];
    const n = Number(await this.store.get(KEY_N)) || 0;
    const mean = Number(await this.store.get(KEY_MEAN)) || 0;
    const v = Number(await this.store.get(KEY_VAR)) || 0;
    return [n, mean, v];
  }

  /** Timeout for the next L2 call, in ms. */
  async current(): Promise<number> {
    if (!this.enabled || !this.store) return this.floor;
    const [n, mean, v] = await this.stats();
    if (n < this.warmup) return this.floor;
    const est = this.headroom * (mean + 2 * Math.sqrt(Math.max(v, 0)));
    if (est < this.floor) return this.floor;
    if (est > this.ceil) return this.ceil;
    return Math.floor(est);
  }

  private async observe(ms: number): Promise<void> {
    if (!this.store) return;
    let [n, mean, v] = await this.stats();
    if (n === 0) {
      mean = ms;
      v = 0;
    } else {
      const diff = ms - mean;
      mean = mean + this.alpha * diff;
      v = (1 - this.alpha) * (v + this.alpha * diff * diff);
    }
    await this.store.set(KEY_N, n + 1, 0);
    await this.store.set(KEY_MEAN, mean, 0);
    await this.store.set(KEY_VAR, v, 0);
  }

  async success(ms: number): Promise<void> {
    if (this.enabled && this.store && ms > 0) await this.observe(ms);
  }

  async timeout(firedMs?: number): Promise<void> {
    if (!this.enabled || !this.store) return;
    await this.observe(Math.min((firedMs ?? this.floor) * 1.2, this.ceil));
  }
}
