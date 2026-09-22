// Port of core/init.lua: evaluate(req, ctx) -> verdict. Async because every
// Cloudflare store is; the order of operations is the one the golden vectors pin.
import * as rulesMod from "./rules.js";
import * as normalize from "./normalize.js";
import * as judge from "./judge.js";
import * as policy from "./policy.js";
import * as verdict from "./verdict.js";
import * as trust from "./trust.js";
import * as subject from "./subject.js";
import type { Config } from "./defaults.js";
import type { BreakerLike } from "./breaker.js";
import type { Req, Rule, CacheLike, RulesCtx } from "./rules.js";
import type { JsonValue } from "./normalize.js";

export const VERSION = "0.4.0";

export type JudgeResult = [judge.Answers, null] | [null, string];

export interface Judge {
  call(prompt: judge.Prompt, timeoutMs: number): Promise<JudgeResult> | JudgeResult;
  /** Optional: several prompts at once (in parallel), for text judged in chunks. */
  call_many?(prompts: judge.Prompt[], timeoutMs: number): Promise<JudgeResult[]>;
}

export interface Ctx {
  config: Config;
  rules: Rule[];
  cache?: CacheLike & { set(key: string, value: unknown, ttl: number): void | Promise<void> };
  /** Fingerprint trust only; defaults to `cache`. Split it out to put trust
   *  somewhere shared or durable without moving the hot verdict cache too. */
  trust?: trust.TrustStore;
  judge: Judge;
  breaker?: BreakerLike;
  /** Per-subject trajectory (see ./subject). Absent, or absent id, means the
   *  behaviour this core had before it existed. `history` is IGNORED in this
   *  version; `record` is a sink that is never awaited. */
  subject?: subject.SubjectCtx;
  clock?: () => number;
  hash: (s: string) => string;
  json_decode?: (s: string) => JsonValue;
  re_find?: RulesCtx["re_find"];
  log?: (level: string, msg: string) => void;
}

function log(ctx: Ctx, level: string, msg: string): void {
  if (ctx.log) ctx.log(level, msg);
}

function nowMs(ctx: Ctx): number {
  return (ctx.clock ? ctx.clock() : 0) * 1000;
}

// Every exit that produced a decision goes through here, so a trajectory has no
// holes: a cache hit and a breaker skip are as much a step in an attack as an
// L2 call is. The one exit that does not is L1 PASS -- the request was never a
// candidate, and that is the hot path.
async function finish(ctx: Ctx, v: verdict.Verdict): Promise<verdict.Verdict> {
  subject.record(ctx, v);
  await subject.repRecord(ctx, v);
  return v;
}

/** Port of core.cache_key: the verdict-cache key for a fingerprint judged under
 *  `rule`. A score is only valid for the prompt that produced it, so the key is
 *  scoped to the rule's templates and deployment context and to the provider
 *  and model; trust stays keyed by fingerprint alone. */
export function cacheKey(fp: string, rule: Rule | undefined, cfg: Config, hash: (s: string) => string): string {
  const jev = cfg?.jev ?? {};
  const scope = [
    String(rule?.id ?? ""),
    (rule?.templates ?? []).join(","),
    String(rule?.deployment_context ?? jev.deployment_context ?? ""),
    String(jev.provider ?? ""),
    String(jev.model ?? ""),
  ].join("\n");
  return "fp:" + String(hash(scope)).slice(0, 16) + ":" + fp;
}

// Port of judge_chunks in core/init.lua: each chunk its own cache entry, the
// misses judged together, the highest chunk score wins; a failed chunk makes
// the request an error unless another chunk already blocks.
async function judgeChunks(
  req: Req, ctx: Ctx, rule: Rule, chunks: string[], capped: boolean, fp: string, ckey: string | undefined, reason: string,
): Promise<verdict.Verdict> {
  const cfg = ctx.config;
  const scores: (number | undefined)[] = [];
  const tops: string[] = [];
  const pending: { i: number; prompt: judge.Prompt; ck?: string }[] = [];
  const context = {
    path: req.path ?? "", method: req.method ?? "",
    deployment: rule.deployment_context ?? cfg.jev.deployment_context ?? "",
  };
  for (let i = 0; i < chunks.length; i++) {
    const cfp = normalize.fingerprint(chunks[i], { prefix_bytes: cfg.cache.fp_prefix_bytes }, ctx.hash);
    const ck = cfp !== "" ? cacheKey(cfp, rule, cfg, ctx.hash) : undefined;
    const hit = ck && ctx.cache ? ((await ctx.cache.get(ck)) as { score?: unknown; reason?: string } | undefined) : undefined;
    if (hit && typeof hit === "object" && typeof hit.score === "number") {
      scores[i] = hit.score;
      tops[i] = /^(\S+)/.exec(String(hit.reason ?? ""))?.[1] ?? "";
    } else {
      const [prompt, perr] = judge.build(rule.templates, chunks[i], context);
      if (!prompt) {
        log(ctx, "error", "jev-edge: " + perr);
        const [action, label, async] = policy.onError();
        return finish(ctx, verdict.newVerdict({ action, verdict: label, async, source: verdict.SRC_L2, reason: perr, fingerprint: fp }));
      }
      pending.push({ i, prompt, ck });
    }
  }

  const t0 = nowMs(ctx);
  let results: JudgeResult[];
  if (pending.length > 1 && ctx.judge.call_many) {
    results = await ctx.judge.call_many(pending.map((p) => p.prompt), cfg.jev.timeout_ms);
  } else {
    results = [];
    for (const p of pending) results.push(await ctx.judge.call(p.prompt, cfg.jev.timeout_ms));
  }
  const elapsed = nowMs(ctx) - t0;

  let err: string | undefined;
  for (let k = 0; k < pending.length; k++) {
    const p = pending[k];
    const [a, e] = results[k] ?? [null, "error"];
    let s = 0, t = "", n = 0;
    if (a) [s, t, n] = judge.reduce(a);
    if (!a || n === 0) {
      err ??= String(e ?? (a ? "no scores in answer" : "error"));
    } else {
      scores[p.i] = s;
      tops[p.i] = t;
      if (p.ck && ctx.cache) await ctx.cache.set(p.ck, { score: s, reason: `${t} ${verdict.format2(s)}` }, cfg.cache.fp_ttl);
    }
  }
  if (ctx.breaker && pending.length > 0) {
    if (err) await ctx.breaker.failure();
    else await ctx.breaker.success();
  }

  let best: number | undefined;
  let top = "";
  for (let i = 0; i < chunks.length; i++) {
    const s = scores[i];
    if (s !== undefined && (best === undefined || s > best)) {
      best = s;
      top = tops[i];
    }
  }
  if (err && !(best !== undefined && best >= (cfg.policy.block_threshold ?? 0.7))) {
    log(ctx, "warn", "jev-edge: L2 failed on a chunk: " + err);
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({
      action, verdict: label, async, source: verdict.SRC_L2, reason: err, fingerprint: fp, l2_ms: elapsed,
    }));
  }
  const score = best ?? 0;
  const [action, label, async] = policy.decide(score, cfg.policy);
  let why = top !== "" ? `${top} ${verdict.format2(score)}` : reason;
  if (top !== "") why += capped ? " (window)" : ` (${chunks.length} chunks)`;
  if (ckey && ctx.cache) await ctx.cache.set(ckey, { score, reason: why }, cfg.cache.fp_ttl);
  return finish(ctx, verdict.newVerdict({
    action, verdict: label, score, async, source: verdict.SRC_L2, reason: why, fingerprint: fp, l2_ms: elapsed,
  }));
}

export async function evaluate(req: Req, ctx: Ctx): Promise<verdict.Verdict> {
  const cfg = ctx.config;

  // L1 --------------------------------------------------------------------
  const [r, text, reason, rule, windowed, chunks, capped] = await rulesMod.evaluateAll(req, ctx.rules, ctx);

  if (r === rulesMod.PASS) {
    return verdict.newVerdict({ verdict: verdict.SKIPPED, source: verdict.SRC_L1, reason });
  }
  if (r === rulesMod.UNJUDGEABLE) {
    // A watched request nobody read: `skipped`, blocked only when the operator
    // chose that and the gateway enforces.
    const block = cfg.policy.mode === "enforce" && cfg.policy.unjudgeable === "block";
    return finish(ctx, verdict.newVerdict({
      action: block ? verdict.ACTION_BLOCK : verdict.ACTION_PASS,
      verdict: verdict.SKIPPED, source: verdict.SRC_L1, reason,
    }));
  }
  if (r === rulesMod.BLOCK) {
    const action = cfg.policy.mode === "enforce" ? verdict.ACTION_BLOCK : verdict.ACTION_PASS;
    return finish(ctx, verdict.newVerdict({ action, verdict: verdict.MALICIOUS, score: 1, source: verdict.SRC_L1, reason }));
  }

  const fp = normalize.fingerprint(text, { prefix_bytes: cfg.cache.fp_prefix_bytes }, ctx.hash);

  // trust -----------------------------------------------------------------
  // An operator called this exact text a false positive. Checked before the
  // verdict cache so it wins over a stale malicious score for the same text.
  if (fp !== "" && trust.enabled(cfg.feedback)) {
    const store = ctx.trust ?? ctx.cache;
    const now = ctx.clock ? ctx.clock() : 0;
    const rec = await trust.get(store, fp, now);
    if (rec && store) {
      await trust.touch(store, fp, rec, now, cfg.feedback);
      return finish(ctx, verdict.newVerdict({
        action: verdict.ACTION_PASS, verdict: verdict.SAFE, score: 0,
        source: verdict.SRC_TRUST, fingerprint: fp,
        // Lua: `rec.by and (...)`; "" is truthy there, so an empty `by` still reads "trusted by "
        reason: rec.by !== undefined && rec.by !== null ? "fingerprint trusted by " + rec.by : "fingerprint trusted",
      }));
    }
  }

  // cache -----------------------------------------------------------------
  const ckey = fp !== "" ? cacheKey(fp, rule, cfg, ctx.hash) : undefined;
  if (ckey && ctx.cache) {
    const hit = (await ctx.cache.get(ckey)) as { score?: unknown; reason?: string } | undefined;
    if (hit && typeof hit === "object" && typeof hit.score === "number") {
      const [action, label] = policy.decide(hit.score, cfg.policy);
      // Never async on a hit: the cached score already is the judge's
      // answer, and a re-judge per hit would turn the cache into an
      // amplifier (one suspicious prompt repeated N times = N L3 calls).
      return finish(ctx, verdict.newVerdict({
        action, verdict: label, score: hit.score, async: false,
        source: verdict.SRC_CACHE, reason: hit.reason ?? reason, fingerprint: fp,
      }));
    }
  }

  // breaker ---------------------------------------------------------------
  if (ctx.breaker && !(await ctx.breaker.allow())) {
    const [action, label, async] = policy.onSkipped();
    return finish(ctx, verdict.newVerdict({ action, verdict: label, async, source: verdict.SRC_BREAKER, reason: "breaker open", fingerprint: fp }));
  }

  // L2 --------------------------------------------------------------------
  if (chunks && chunks.length > 1) {
    // max_judge_chunks > 1: what still did not fit is unjudgeable
    if (capped && cfg.policy.unjudgeable === "block" && cfg.policy.mode === "enforce") {
      return finish(ctx, verdict.newVerdict({
        action: verdict.ACTION_BLOCK, verdict: verdict.SKIPPED, source: verdict.SRC_L1,
        reason: "unjudgeable: text over max_judge_chunks", fingerprint: fp,
      }));
    }
    return judgeChunks(req, ctx, rule!, chunks, capped === true, fp, ckey, reason);
  }
  const [prompt, perr] = judge.build(rule!.templates, text, {
    path: req.path ?? "",
    method: req.method ?? "",
    deployment: rule!.deployment_context ?? cfg.jev.deployment_context ?? "",
  });
  if (!prompt) {
    log(ctx, "error", "jev-edge: " + perr);
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({ action, verdict: label, async, source: verdict.SRC_L2, reason: perr, fingerprint: fp }));
  }

  const t0 = nowMs(ctx);
  const [answers, jerr] = await ctx.judge.call(prompt, cfg.jev.timeout_ms);
  const elapsed = nowMs(ctx) - t0;

  if (!answers) {
    if (ctx.breaker) await ctx.breaker.failure();
    log(ctx, "warn", "jev-edge: L2 failed: " + String(jerr));
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({
      action, verdict: label, async, source: verdict.SRC_L2,
      reason: String(jerr ?? "error"), fingerprint: fp, l2_ms: elapsed,
    }));
  }

  const [score, top, n] = judge.reduce(answers);
  if (n === 0) {
    // An answer with no score in it is a provider fault, not a SAFE verdict:
    // caching score 0 would wave the same text through for fp_ttl.
    if (ctx.breaker) await ctx.breaker.failure();
    log(ctx, "warn", "jev-edge: L2 answer has no scores");
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({
      action, verdict: label, async, source: verdict.SRC_L2,
      reason: "no scores in answer", fingerprint: fp, l2_ms: elapsed,
    }));
  }
  if (ctx.breaker) await ctx.breaker.success();
  const [action, label, async] = policy.decide(score, cfg.policy);
  // the score is for the window, not the whole text; say so
  const why = top !== "" ? `${top} ${verdict.format2(score)}${windowed ? " (window)" : ""}` : reason;

  if (ckey && ctx.cache) {
    await ctx.cache.set(ckey, { score, reason: why }, cfg.cache.fp_ttl);
  }

  return finish(ctx, verdict.newVerdict({
    action, verdict: label, score, async, source: verdict.SRC_L2, reason: why, fingerprint: fp, l2_ms: elapsed,
  }));
}

export { rulesMod as rules, normalize, judge, policy, verdict, trust, subject };
export { sha256Hex } from "./sha256.js";
export * as defaults from "./defaults.js";
export * as breaker from "./breaker.js";
export type { Req, Rule, CacheLike } from "./rules.js";
export type { Verdict } from "./verdict.js";
export type { Config } from "./defaults.js";
export type { Prompt, Answers } from "./judge.js";
export type { Entry as SubjectEntry, SubjectCtx } from "./subject.js";
