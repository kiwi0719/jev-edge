// Port of core/sampling.lua: decide and build. Storage is the host's job
// (KV, a log line, an analytics binding), through Options.onSample.
import * as normalize from "./core/normalize.js";
import { MALICIOUS, SRC_L1, type Verdict } from "./core/verdict.js";
import type { Config } from "./core/defaults.js";
import { contentType, pathMatches, type Req, type Rule } from "./core/rules.js";

const RANK: Record<string, number> = { skipped: -1, error: 0, safe: 1, suspicious: 2, malicious: 3 };

export interface Sample {
  ts: number; rid: string; path: string; ip: string; method: string;
  fp: string; score: number; verdict: string; action: string; source: string; reason: string; l2_ms: number;
  text: string;
}

export function shouldSample(cfg: Config, v: Verdict, rand: () => number = Math.random): boolean {
  const sm = cfg.sampling;
  if (!sm?.enabled) return false;
  if (v.source === SRC_L1 && v.verdict !== MALICIOUS) return false;
  const min = RANK[sm.min_verdict ?? "suspicious"] ?? 2;
  if ((RANK[v.verdict] ?? -1) < min) return false;
  const rate = Number(sm.rate) || 0;
  if (rate <= 0) return false;
  if (rate >= 1) return true;
  return rand() < rate;
}

export function buildSample(cfg: Config, v: Verdict, req: Req, rules: Rule[], rid: string, ts = Date.now() / 1000): Sample {
  const rule = rules.find((r) => pathMatches(req.path ?? "", r.watch_paths, r.paths_case_sensitive) !== null); // watch_paths are Lua patterns
  let text = "";
  if (rule && typeof req.body === "string") {
    const ct = contentType(req.headers);
    const [extracted] = normalize.extract(req.body, ct, rule.text_fields);
    text = normalize.normalize(extracted, { prefix_bytes: cfg.sampling.text_bytes ?? 512 });
  }
  return {
    ts, rid, path: req.path ?? "", ip: req.client_ip ?? "", method: req.method ?? "",
    fp: v.fingerprint, score: v.score, verdict: v.verdict, action: v.action, source: v.source, reason: v.reason, l2_ms: v.l2_ms,
    text,
  };
}
