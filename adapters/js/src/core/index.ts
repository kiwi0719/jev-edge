// Port of core/init.lua: evaluate(req, ctx) -> verdict. Async because every
// Cloudflare store is; the order of operations is the one the golden vectors pin.
import * as rulesMod from "./rules";
import * as normalize from "./normalize";
import * as judge from "./judge";
import * as policy from "./policy";
import * as verdict from "./verdict";
import * as trust from "./trust";
import * as subject from "./subject";
import type { Config } from "./defaults";
import type { Breaker } from "./breaker";
import type { Req, Rule, CacheLike } from "./rules";
import type { JsonValue } from "./normalize";

export const VERSION = "0.3.0";

export interface Judge {
  call(prompt: judge.Prompt, timeoutMs: number): Promise<[judge.Answers, null] | [null, string]> | [judge.Answers, null] | [null, string];
}

export interface Ctx {
  config: Config;
  rules: Rule[];
  cache?: CacheLike & { set(key: string, value: unknown, ttl: number): void | Promise<void> };
  /** Fingerprint trust only; defaults to `cache`. Split it out to put trust
   *  somewhere shared or durable without moving the hot verdict cache too. */
  trust?: trust.TrustStore;
  judge: Judge;
  breaker?: Breaker;
  /** Per-subject trajectory (see ./subject). Absent, or absent id, means the
   *  behaviour this core had before it existed. `history` is IGNORED in this
   *  version; `record` is a sink that is never awaited. */
  subject?: subject.SubjectCtx;
  clock?: () => number;
  hash: (s: string) => string;
  json_decode?: (s: string) => JsonValue;
  re_find?: (subject: string, pattern: string) => boolean;
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
function finish(ctx: Ctx, v: verdict.Verdict): verdict.Verdict {
  subject.record(ctx, v);
  return v;
}

export async function evaluate(req: Req, ctx: Ctx): Promise<verdict.Verdict> {
  const cfg = ctx.config;

  // L1 --------------------------------------------------------------------
  const [r, text, reason, rule] = await rulesMod.evaluateAll(req, ctx.rules, ctx);

  if (r === rulesMod.PASS) {
    return verdict.newVerdict({ verdict: verdict.SKIPPED, source: verdict.SRC_L1, reason });
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
        reason: rec.by ? "fingerprint trusted by " + rec.by : "fingerprint trusted",
      }));
    }
  }

  // cache -----------------------------------------------------------------
  if (fp !== "" && ctx.cache) {
    const hit = (await ctx.cache.get("fp:" + fp)) as { score?: unknown; reason?: string } | undefined;
    if (hit && typeof hit === "object" && typeof hit.score === "number") {
      const [action, label, async] = policy.decide(hit.score, cfg.policy);
      return finish(ctx, verdict.newVerdict({
        action, verdict: label, score: hit.score, async,
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

  if (ctx.breaker) await ctx.breaker.success();
  const [score, top] = judge.reduce(answers);
  const [action, label, async] = policy.decide(score, cfg.policy);
  const why = top !== "" ? `${top} ${verdict.format2(score)}` : reason;

  if (fp !== "" && ctx.cache) {
    await ctx.cache.set("fp:" + fp, { score, reason: why }, cfg.cache.fp_ttl);
  }

  return finish(ctx, verdict.newVerdict({
    action, verdict: label, score, async, source: verdict.SRC_L2, reason: why, fingerprint: fp, l2_ms: elapsed,
  }));
}

export { rulesMod as rules, normalize, judge, policy, verdict, trust, subject };
export * as defaults from "./defaults";
export * as breaker from "./breaker";
export type { Req, Rule, CacheLike } from "./rules";
export type { Verdict } from "./verdict";
export type { Config } from "./defaults";
export type { Prompt, Answers } from "./judge";
export type { Entry as SubjectEntry, SubjectCtx } from "./subject";
