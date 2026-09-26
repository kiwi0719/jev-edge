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
  /** the tool definitions (rule.tool_fields), normalized like `text`; absent when there are none */
  tools?: string;
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
  let tools: string | undefined;
  if (rule && typeof req.body === "string") {
    const ct = contentType(req.headers);
    const n = cfg.sampling.text_bytes ?? 512;
    const [extracted, kind, , decoded] = normalize.extract(req.body, ct, rule.text_fields);
    text = normalize.normalize(extracted, { prefix_bytes: n });
    // the tool definitions are judged as a part of their own and may be what
    // scored it; JSON the decoder refused is scanned for them, as L1 scans it
    if (rule.tool_fields && rule.tool_fields.length > 0) {
      let values: string[] = [];
      if (decoded !== undefined) [values] = normalize.extractTools(decoded, rule.tool_fields, (s) => JSON.parse(s) as normalize.JsonValue);
      else if (kind === "scan") values = normalize.scanTools(req.body, normalize.fieldKeys(rule.tool_fields), []);
      if (values.length > 0) tools = normalize.normalize(values.join("\n"), { prefix_bytes: n });
    }
  }
  return {
    ts, rid, path: req.path ?? "", ip: req.client_ip ?? "", method: req.method ?? "",
    fp: v.fingerprint, score: v.score, verdict: v.verdict, action: v.action, source: v.source, reason: v.reason, l2_ms: v.l2_ms,
    text, ...(tools !== undefined ? { tools } : {}),
  };
}
