// Port of core/defaults.lua: default configuration and deep merge.
import type { Policy } from "./policy";
import type { BreakerConfig } from "./breaker";
import type { FeedbackConfig } from "./trust";

export interface JevConfig {
  provider?: string;
  endpoint?: string;
  model?: string;
  api_key?: string;
  deployment_context?: string;
  timeout_ms: number;
  timeout_max_ms?: number;
  timeout_headroom?: number;
  timeout_adaptive?: boolean;
  timeout_alpha?: number;
  timeout_warmup?: number;
  max_inflight?: number;
  [k: string]: unknown;
}

export interface Config {
  jev: JevConfig;
  rules: string[];
  policy: Policy;
  cache: { fp_ttl: number; rep_ttl: number; fp_prefix_bytes: number };
  async: { enabled: boolean; max_async: number; rep_block_after: number; rep_block_ttl: number };
  sampling: { enabled: boolean; rate: number; min_verdict: "safe" | "suspicious" | "malicious"; max_samples: number; ttl: number; text_bytes: number; log: boolean };
  feedback: FeedbackConfig;
  breaker: BreakerConfig;
}

export const config: Config = {
  jev: {
    provider: "jev",
    model: "jev-latest",
    timeout_ms: 400,
    timeout_max_ms: 1000,
    timeout_headroom: 1.5,
    timeout_adaptive: true,
    max_inflight: 64,
  },
  rules: ["llm-endpoints"],
  policy: {
    mode: "monitor",
    block_threshold: 0.7,
    suspect_threshold: 0.5,
    block_status: 403,
    block_body: '{"error":"request rejected"}',
  },
  cache: { fp_ttl: 300, rep_ttl: 600, fp_prefix_bytes: 2048 },
  async: { enabled: true, max_async: 32, rep_block_after: 0, rep_block_ttl: 600 },
  sampling: { enabled: false, rate: 0.05, min_verdict: "suspicious", max_samples: 1000, ttl: 86400, text_bytes: 512, log: false },
  feedback: { enabled: false, trust_ttl: 604800, max_renewals: 4, token: null },
  breaker: { window_s: 60, min_samples: 20, fail_ratio: 0.5, open_s: 30 },
};

type Plain = Record<string, unknown>;

function isPlain(v: unknown): v is Plain {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Deep-merge `over` onto a copy of `base`. Lists are replaced, not merged. */
export function merge<T extends object>(base: T, over?: object | null): T {
  const out: Plain = {};
  for (const [k, v] of Object.entries(base ?? {})) out[k] = isPlain(v) ? merge(v, null) : v;
  for (const [k, v] of Object.entries(over ?? {})) {
    if (isPlain(v) && isPlain(out[k])) out[k] = merge(out[k] as Plain, v);
    else out[k] = v;
  }
  return out as T;
}

export function validate(c: Config): [true, null] | [null, string] {
  const p = c.policy ?? {};
  if (p.mode !== "monitor" && p.mode !== "enforce") return [null, "policy.mode must be monitor|enforce"];
  if (typeof p.block_threshold !== "number" || typeof p.suspect_threshold !== "number") return [null, "policy thresholds must be numbers"];
  if (p.suspect_threshold > p.block_threshold) return [null, "policy.suspect_threshold must be <= block_threshold"];
  if (typeof c.jev.timeout_ms !== "number" || c.jev.timeout_ms <= 0) return [null, "jev.timeout_ms must be > 0"];
  const fb = c.feedback ?? {};
  if (fb.trust_ttl !== undefined && (typeof fb.trust_ttl !== "number" || fb.trust_ttl <= 0)) return [null, "feedback.trust_ttl must be > 0"];
  if (fb.max_renewals !== undefined && (typeof fb.max_renewals !== "number" || fb.max_renewals < 0)) return [null, "feedback.max_renewals must be >= 0"];
  if (fb.enabled === true && !fb.token) return [null, "feedback.enabled needs feedback.token set"];
  const sm = c.sampling ?? {};
  if (sm.rate !== undefined && (typeof sm.rate !== "number" || sm.rate < 0 || sm.rate > 1)) return [null, "sampling.rate must be in [0,1]"];
  if (sm.min_verdict !== undefined && !["safe", "suspicious", "malicious"].includes(sm.min_verdict)) return [null, "sampling.min_verdict must be safe|suspicious|malicious"];
  const max = c.jev.timeout_max_ms;
  if (max !== undefined && (typeof max !== "number" || max < c.jev.timeout_ms)) return [null, "jev.timeout_max_ms must be >= timeout_ms"];
  return [true, null];
}
