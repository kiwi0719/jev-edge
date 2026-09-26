// Port of core/defaults.lua: default configuration and deep merge.
import type { Policy } from "./policy.js";
import type { BreakerConfig } from "./breaker.js";
import type { FeedbackConfig } from "./trust.js";
import { pathError } from "./normalize.js";
import { get as getTemplate } from "./judge.js";

export interface QuestionWording {
  instructions?: string;
  instructions_ctx?: string;
  criteria?: { true?: string; false?: string };
  criteria_ctx?: { true?: string; false?: string };
}

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
  /** Per-provider question wording: fields here replace the bundled template's for jev / laya requests. */
  questions?: Record<string, QuestionWording>;
  [k: string]: unknown;
}

export interface Config {
  jev: JevConfig;
  rules: string[];
  policy: Policy;
  /** fp_prefix_bytes: since 0.3.1 only bounds sampled/logged text; the fingerprint always covers the whole normalized text. */
  cache: { fp_ttl: number; rep_ttl: number; fp_prefix_bytes: number };
  /**
   * How adapters that sit behind another proxy find the client address in
   * X-Forwarded-For. Proxies APPEND to the header, so the client's own value
   * is on the left and the one your proxy added is on the right:
   * `trusted_hops: 1` takes the last element, 2 the one before it (a load
   * balancer in front of the gateway), and so on. Never the first element:
   * that is whatever the client typed.
   */
  client_ip: { trusted_hops: number };
  async: { enabled: boolean; max_async: number; rep_block_after: number; rep_block_ttl: number };
  subject: {
    enabled: boolean; from: "ip" | "header" | "cookie"; name: string | null; salt: string | null; hashed: boolean;
    history_ttl: number; max_entries: number;
    /** see core/defaults.lua subject.reputation; block_at 0 is off */
    reputation: { block_at: number; window_s: number; block_ttl: number; suspicious: number; malicious: number };
  };
  sampling: { enabled: boolean; rate: number; min_verdict: "safe" | "suspicious" | "malicious"; max_samples: number; ttl: number; text_bytes: number; log: boolean };
  feedback: FeedbackConfig;
  breaker: BreakerConfig;
  /** see core/defaults.lua `untrusted`: retrieved content judged on its own, off by default */
  untrusted: UntrustedConfig;
}

export interface UntrustedConfig {
  enabled: boolean;
  /** OpenAI role "tool"/"function" messages, Anthropic tool_result blocks, Responses function_call_output */
  tool_results: boolean;
  /** JSON paths (text_fields syntax) holding retrieved content outside a tool message */
  fields: string[];
  templates: string[];
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
  client_ip: { trusted_hops: 1 },
  policy: {
    mode: "monitor",
    block_threshold: 0.7,
    suspect_threshold: 0.5,
    block_status: 403,
    block_body: '{"error":"request rejected"}',
    unjudgeable: "pass",
    partial: "judge",
  },
  cache: { fp_ttl: 300, rep_ttl: 600, fp_prefix_bytes: 2048 }, // fp_prefix_bytes: sampled/logged text only since 0.3.1
  async: { enabled: true, max_async: 32, rep_block_after: 0, rep_block_ttl: 600 },
  subject: {
    enabled: false, from: "ip", name: null, salt: null, hashed: false, history_ttl: 3600, max_entries: 20,
    reputation: { block_at: 0, window_s: 600, block_ttl: 600, suspicious: 1, malicious: 3 },
  },
  sampling: { enabled: false, rate: 0.05, min_verdict: "suspicious", max_samples: 1000, ttl: 86400, text_bytes: 512, log: false },
  feedback: { enabled: false, trust_ttl: 604800, max_renewals: 4, token: null },
  breaker: { window_s: 60, min_samples: 20, fail_ratio: 0.5, open_s: 30 },
  untrusted: { enabled: false, tool_results: true, fields: [], templates: ["untrusted"] },
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
  if (p.unjudgeable !== undefined && p.unjudgeable !== "pass" && p.unjudgeable !== "block") {
    return [null, "policy.unjudgeable must be pass|block"];
  }
  if (p.partial !== undefined && p.partial !== "judge" && p.partial !== "unjudgeable") {
    return [null, "policy.partial must be judge|unjudgeable"];
  }
  if (typeof p.block_threshold !== "number" || typeof p.suspect_threshold !== "number") return [null, "policy thresholds must be numbers"];
  if (p.suspect_threshold > p.block_threshold) return [null, "policy.suspect_threshold must be <= block_threshold"];
  if (p.block_threshold > 1 || p.suspect_threshold < 0) return [null, "policy thresholds must be in [0,1]"];
  const bs = p.block_status as unknown;
  if (bs !== undefined && bs !== null && (typeof bs !== "number" || bs < 200 || bs > 599 || !Number.isInteger(bs))) {
    return [null, "policy.block_status must be an HTTP status code"];
  }
  const ca: Partial<Config["cache"]> = c.cache ?? {};
  if (ca.fp_ttl !== undefined && (typeof ca.fp_ttl !== "number" || ca.fp_ttl <= 0)) return [null, "cache.fp_ttl must be > 0"];
  if (ca.rep_ttl !== undefined && (typeof ca.rep_ttl !== "number" || ca.rep_ttl <= 0)) return [null, "cache.rep_ttl must be > 0"];
  const br: BreakerConfig = c.breaker ?? {};
  for (const k of ["window_s", "open_s"] as const) {
    if (br[k] !== undefined && (typeof br[k] !== "number" || (br[k] as number) <= 0)) return [null, `breaker.${k} must be > 0`];
  }
  if (br.min_samples !== undefined && (typeof br.min_samples !== "number" || br.min_samples < 1)) return [null, "breaker.min_samples must be >= 1"];
  if (br.fail_ratio !== undefined && (typeof br.fail_ratio !== "number" || br.fail_ratio <= 0 || br.fail_ratio > 1)) return [null, "breaker.fail_ratio must be in (0,1]"];
  const ci: Partial<Config["client_ip"]> = c.client_ip ?? {};
  if (ci.trusted_hops !== undefined && (typeof ci.trusted_hops !== "number" || ci.trusted_hops < 1 || !Number.isInteger(ci.trusted_hops))) {
    return [null, "client_ip.trusted_hops must be an integer >= 1"];
  }
  const as: Partial<Config["async"]> = c.async ?? {};
  if (as.max_async !== undefined && (typeof as.max_async !== "number" || as.max_async < 0)) return [null, "async.max_async must be >= 0"];
  if (typeof c.jev.timeout_ms !== "number" || c.jev.timeout_ms <= 0) return [null, "jev.timeout_ms must be > 0"];
  const fb = c.feedback ?? {};
  if (fb.trust_ttl !== undefined && (typeof fb.trust_ttl !== "number" || fb.trust_ttl <= 0)) return [null, "feedback.trust_ttl must be > 0"];
  if (fb.max_renewals !== undefined && (typeof fb.max_renewals !== "number" || fb.max_renewals < 0)) return [null, "feedback.max_renewals must be >= 0"];
  if (fb.enabled === true && !fb.token) return [null, "feedback.enabled needs feedback.token set"];
  const sj = c.subject ?? {};
  if (sj.from !== undefined && !["ip", "header", "cookie"].includes(sj.from)) return [null, "subject.from must be ip|header|cookie"];
  if (sj.enabled === true) {
    if ((sj.from === "header" || sj.from === "cookie") && !sj.name) return [null, `subject.from = ${sj.from} needs subject.name`];
    if (!sj.hashed && !sj.salt) return [null, "subject.enabled needs subject.salt (or hashed = true)"];
  }
  if (sj.max_entries !== undefined && (typeof sj.max_entries !== "number" || sj.max_entries < 1)) return [null, "subject.max_entries must be >= 1"];
  const sr: Partial<Config["subject"]["reputation"]> = sj.reputation ?? {};
  for (const k of ["block_at", "suspicious", "malicious"] as const) {
    if (sr[k] !== undefined && (typeof sr[k] !== "number" || sr[k]! < 0)) return [null, `subject.reputation.${k} must be a number >= 0`];
  }
  for (const k of ["window_s", "block_ttl"] as const) {
    if (sr[k] !== undefined && (typeof sr[k] !== "number" || sr[k]! <= 0)) return [null, `subject.reputation.${k} must be > 0`];
  }
  if ((sr.block_at ?? 0) > 0 && !sj.enabled) return [null, "subject.reputation.block_at needs subject.enabled"];
  if (sj.history_ttl !== undefined && (typeof sj.history_ttl !== "number" || sj.history_ttl <= 0)) return [null, "subject.history_ttl must be > 0"];
  const sm = c.sampling ?? {};
  if (sm.rate !== undefined && (typeof sm.rate !== "number" || sm.rate < 0 || sm.rate > 1)) return [null, "sampling.rate must be in [0,1]"];
  if (sm.max_samples !== undefined && (typeof sm.max_samples !== "number" || sm.max_samples < 1)) return [null, "sampling.max_samples must be >= 1"];
  if (sm.min_verdict !== undefined && !["safe", "suspicious", "malicious"].includes(sm.min_verdict)) return [null, "sampling.min_verdict must be safe|suspicious|malicious"];
  // per-provider question wording (providers/index.ts): { [template]: { instructions, ... } }
  const qs = c.jev.questions;
  if (qs !== undefined) {
    if (typeof qs !== "object" || qs === null || Array.isArray(qs)) return [null, "jev.questions must be a table"];
    for (const [name, q] of Object.entries(qs as Record<string, unknown>)) {
      if (typeof q !== "object" || q === null || Array.isArray(q)) return [null, "jev.questions must map template names to tables"];
      const o = q as Record<string, unknown>;
      for (const k of ["instructions", "instructions_ctx"]) {
        if (o[k] !== undefined && (typeof o[k] !== "string" || o[k] === "")) return [null, `jev.questions.${name}.${k} must be a non-empty string`];
      }
      for (const k of ["criteria", "criteria_ctx"]) {
        if (o[k] !== undefined && (typeof o[k] !== "object" || o[k] === null)) return [null, `jev.questions.${name}.${k} must be a table`];
      }
    }
  }
  const max = c.jev.timeout_max_ms;
  if (max !== undefined && (typeof max !== "number" || max < c.jev.timeout_ms)) return [null, "jev.timeout_max_ms must be >= timeout_ms"];
  const [uok, uerr] = validateUntrusted(c.untrusted, "untrusted");
  if (!uok) return [null, uerr];
  return [true, null];
}

/** Port of defaults.untrusted_spec: config.untrusted with the rule's own `untrusted` over it. */
export function untrustedSpec(cfg: { untrusted?: UntrustedConfig } | undefined, rule?: { untrusted?: Partial<UntrustedConfig> }): UntrustedConfig {
  const base = cfg?.untrusted ?? config.untrusted;
  const over = rule?.untrusted;
  if (!over || typeof over !== "object") return base;
  return { ...base, ...over };
}

/** Port of defaults.string_list_error: why `v` is not a list of non-empty strings (`nonempty`: with one at least), or null. */
export function stringListError(v: unknown, what: string, nonempty = false): string | null {
  if (!Array.isArray(v)) return `${what} must be a list of strings`;
  if (nonempty && v.length === 0) return `${what} must not be empty`;
  for (let i = 0; i < v.length; i++) {
    if (typeof v[i] !== "string" || v[i] === "") return `${what}[${i + 1}] must be a non-empty string`;
  }
  return null;
}

/** Port of defaults.templates_error: why `v` is not a list of template names judge knows, or null. */
export function templatesError(v: unknown, what: string): string | null {
  const err = stringListError(v, what, true);
  if (err) return err;
  const names = v as string[];
  for (let i = 0; i < names.length; i++) {
    if (!getTemplate(names[i])) return `${what}[${i + 1}] ${names[i]} is not a template`;
  }
  return null;
}

/** Port of defaults.validate_untrusted: type check for the config section or a rule's override (JSON null is not one). */
export function validateUntrusted(u: unknown, where: string): [true, null] | [null, string] {
  if (u === undefined) return [true, null];
  if (typeof u !== "object" || u === null || Array.isArray(u)) return [null, `${where} must be a table`];
  const t = u as Record<string, unknown>;
  for (const k of ["enabled", "tool_results"]) {
    if (t[k] !== undefined && typeof t[k] !== "boolean") return [null, `${where}.${k} must be true|false`];
  }
  if (t.fields !== undefined) {
    const err = stringListError(t.fields, `${where}.fields`);
    if (err) return [null, err];
    // a field path is checked the way a rule's text_fields are
    const fields = t.fields as string[];
    for (let i = 0; i < fields.length; i++) {
      const perr = pathError(fields[i]);
      if (perr) return [null, `${where}.fields[${i + 1}] ${perr}`];
    }
  }
  // a name judge does not know makes every request with retrieved content an
  // L2 error, the whole-text judgment included
  if (t.templates !== undefined) {
    const err = templatesError(t.templates, `${where}.templates`);
    if (err) return [null, err];
  }
  return [true, null];
}
