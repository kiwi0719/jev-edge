// Port of core/init.lua: evaluate(req, ctx) -> verdict. Async because every
// Cloudflare store is; the order of operations is the one the golden vectors pin.
import * as rulesMod from "./rules.js";
import * as normalize from "./normalize.js";
import * as judge from "./judge.js";
import * as policy from "./policy.js";
import * as verdict from "./verdict.js";
import * as trust from "./trust.js";
import * as subject from "./subject.js";
import { untrustedSpec, type Config } from "./defaults.js";
import type { BreakerLike } from "./breaker.js";
import type { Req, Rule, CacheLike, RulesCtx } from "./rules.js";
import type { JsonValue } from "./normalize.js";

export const VERSION = "0.6.1";

/** A failed call may say what it ran into (judge.ErrorKind); only a
 *  transport error, a timeout, a 5xx or a 429 is a breaker failure, and a
 *  result with no kind is counted as before. */
export type JudgeResult = [judge.Answers, null] | [null, string] | [null, string, judge.ErrorKind | undefined];

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
  /** Optional: keeps a promise alive past the response (the host's
   *  waitUntil). With it, the writes made once the verdict is decided (the
   *  verdict cache, reputation points, breaker success, the trust renewal)
   *  run past the response instead of on the request path, and a rejection
   *  is logged, never raised. Without it they are awaited, in the order the
   *  golden vectors pin. The price: a later request in the same isolate may
   *  miss an entry still being written. */
  defer?: (p: Promise<unknown>) => void;
}

function log(ctx: Ctx, level: string, msg: string): void {
  if (ctx.log) ctx.log(level, msg);
}

// A write made once the verdict is decided: handed to ctx.defer when the
// host has one, awaited otherwise (and when the host refuses the promise).
async function after(ctx: Ctx, write: () => unknown): Promise<void> {
  if (!ctx.defer) {
    await write();
    return;
  }
  const p = Promise.resolve()
    .then(write)
    .then(
      () => undefined,
      (e) => log(ctx, "warn", "jev-edge: deferred write failed: " + (e instanceof Error ? e.message : String(e))),
    );
  try {
    ctx.defer(p);
  } catch {
    await p;
  }
}

function nowMs(ctx: Ctx): number {
  return (ctx.clock ? ctx.clock() : 0) * 1000;
}

// Port of rep_of in core/init.lua: what subject reputation charges for a
// request judged in parts, the max score over the subject's own parts; never
// retrieved content or tool definitions, which come from elsewhere, nor, with
// untrusted judging on, a text that holds retrieved content (L1's
// `retrieved`). undefined: the verdict's own label; a number: the subject's
// own text scored lower than a part it is not charged for; false: none of its
// own text was judged.
type Rep = number | false | undefined;
function repOf(best: number | undefined, own: number | undefined): Rep {
  if (own === undefined) return false;
  if (own === best) return undefined;
  return own;
}

// Every exit that produced a decision goes through here, so a trajectory has no
// holes: a cache hit and a breaker skip are as much a step in an attack as an
// L2 call is. The one exit that does not is L1 PASS -- the request was never a
// candidate, and that is the hot path.
async function finish(ctx: Ctx, v: verdict.Verdict, rep?: Rep): Promise<verdict.Verdict> {
  subject.record(ctx, v);
  const charge = rep === false ? false : typeof rep === "number" ? policy.decide(rep, ctx.config.policy)[1] : undefined;
  if (ctx.subject) await after(ctx, () => subject.repRecord(ctx, v, charge));
  return v;
}

// Port of settle in core/init.lua: tell the breaker how a request it admitted
// went. Only calls that reached the provider and found it failing count
// against it (judge.counts); a request that says nothing about its health
// releases a half-open probe.
async function settle(ctx: Ctx, failed = false, answered = false): Promise<void> {
  const b = ctx.breaker;
  if (!b) return;
  if (failed) await b.failure();
  else if (answered) await after(ctx, () => b.success());
  else if (b.release) await b.release();
}

/** Port of core.cache_key: the verdict-cache key for a fingerprint judged under
 *  `rule`. A score is only valid for the prompt that produced it, so the key is
 *  scoped to the rule's templates and deployment context and to the provider
 *  and model; trust stays keyed by fingerprint alone. */
export function cacheKey(
  fp: string, rule: Rule | undefined, cfg: Config, hash: (s: string) => string,
  over?: { templates?: string[]; deployment?: string },
): string {
  const jev = cfg?.jev ?? {};
  const templates = over?.templates ?? rule?.templates ?? [];
  const deployment = over?.deployment ?? rule?.deployment_context ?? jev.deployment_context ?? "";
  const scope = [
    String(rule?.id ?? ""),
    templates.join(","),
    String(deployment),
    String(jev.provider ?? ""),
    String(jev.model ?? ""),
  ].join("\n");
  return "fp:" + String(hash(scope)).slice(0, 16) + ":" + fp;
}

// Port of UNTRUSTED_SEP and TOOLS_SEP in core/init.lua: what the request's
// fingerprint covers when it carries retrieved content or tool definitions.
const UNTRUSTED_SEP = "\n<untrusted content>\n";
const TOOLS_SEP = "\n<tool definitions>\n";

// Names the tool-definitions part in the reason when its score decides.
const TOOLS_LABEL = "tools+";

interface Part {
  text: string;
  templates: string[];
  context: judge.PromptContext;
  over?: { templates?: string[]; deployment?: string };
  /** put before the template name in the reason when this part's score decides */
  label?: string;
  /** false: not the subject's own text (retrieved content, tool definitions, a text that holds retrieved content), its score is not charged to it */
  rep?: false;
}

// Port of judge_parts in core/init.lua: each part (a chunk, the retrieved
// content, the tool definitions) its own cache entry, the misses judged
// together, the highest part score wins; a failed part makes the request an
// error unless another part already blocks. A part whose prompt cannot be
// built is logged and left out (an error only when no part is left), and
// the whole request's entry is then not written.
async function judgeParts(
  ctx: Ctx, rule: Rule, parts: Part[], suffix: string, fp: string, ckey: string | undefined, reason: string,
): Promise<verdict.Verdict> {
  const cfg = ctx.config;
  const scores: (number | undefined)[] = [];
  const tops: string[] = [];
  const pending: { i: number; prompt: judge.Prompt; ck?: string }[] = [];
  let leftOut: string | undefined;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const cfp = normalize.fingerprint(part.text, { prefix_bytes: cfg.cache.fp_prefix_bytes }, ctx.hash);
    const ck = cfp !== "" ? cacheKey(cfp, rule, cfg, ctx.hash, part.over) : undefined;
    const hit = ck && ctx.cache ? ((await ctx.cache.get(ck)) as { score?: unknown; reason?: string } | undefined) : undefined;
    if (hit && typeof hit === "object" && typeof hit.score === "number") {
      scores[i] = hit.score;
      tops[i] = /^(\S+)/.exec(String(hit.reason ?? ""))?.[1] ?? "";
    } else {
      const [prompt, perr] = judge.build(part.templates, part.text, part.context);
      if (prompt) {
        pending.push({ i, prompt, ck });
      } else {
        log(ctx, "error", "jev-edge: " + perr + " (that part is not judged)");
        leftOut ??= perr;
      }
    }
  }
  if (pending.length === 0 && !scores.some((s) => s !== undefined)) {
    // no part left to judge
    await settle(ctx);
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({ action, verdict: label, async, source: verdict.SRC_L2, reason: leftOut!, fingerprint: fp }));
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
  let failed = false, answered = false;
  for (let k = 0; k < pending.length; k++) {
    const p = pending[k];
    const r: JudgeResult = results[k] ?? [null, "error"];
    const a = r[0];
    let e: string | null = r[1];
    let kind = r[2];
    let s = 0, t = "", n = 0;
    if (a) [s, t, n] = judge.reduce(a);
    if (!a || n === 0) {
      if (a) [e, kind] = ["no scores in answer", judge.UNUSABLE];
      err ??= judge.reason(e, kind);
      if (judge.counts(e, kind)) failed = true;
    } else {
      answered = true;
      scores[p.i] = s;
      tops[p.i] = t;
      const { ck } = p, cache = ctx.cache;
      if (ck && cache) await after(ctx, () => cache.set(ck, { score: s, reason: `${t} ${verdict.format2(s)}` }, cfg.cache.fp_ttl));
    }
  }
  // only calls that reached the provider say anything about its health
  await settle(ctx, failed, answered);

  let best: number | undefined;
  let own: number | undefined;
  let top = "";
  for (let i = 0; i < parts.length; i++) {
    const s = scores[i];
    if (s !== undefined && (best === undefined || s > best)) {
      best = s;
      top = tops[i];
      if (top !== "" && parts[i].label) top = parts[i].label + top;
    }
    if (s !== undefined && parts[i].rep !== false && (own === undefined || s > own)) own = s;
  }
  const rep = repOf(best, own);
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
  if (top !== "") why += suffix;
  const cache = ctx.cache;
  if (ckey && cache && leftOut === undefined) {
    await after(ctx, () => cache.set(ckey, { score, reason: why, ...(rep !== undefined ? { rep } : {}) }, cfg.cache.fp_ttl));
  }
  return finish(ctx, verdict.newVerdict({
    action, verdict: label, score, async, source: verdict.SRC_L2, reason: why, fingerprint: fp, l2_ms: elapsed,
  }), rep);
}

export async function evaluate(req: Req, ctx: Ctx): Promise<verdict.Verdict> {
  const cfg = ctx.config;

  // L1 --------------------------------------------------------------------
  const [r, text, reason, rule, windowed, chunks, capped, untrusted, tools, retrieved] = await rulesMod.evaluateAll(req, ctx.rules, ctx);

  if (r === rulesMod.PASS) {
    return verdict.newVerdict({ verdict: verdict.SKIPPED, source: verdict.SRC_L1, reason });
  }
  if (r === rulesMod.UNJUDGEABLE) {
    // A watched request nobody read: `skipped`, blocked only when the operator
    // chose that and the gateway enforces. For a prompt given as token ids the
    // rule's token_prompts chooses, when it has one.
    const choice = reason === rulesMod.TOKEN_REASON ? rulesMod.tokenPrompts(rule, cfg.policy) : cfg.policy.unjudgeable;
    const block = cfg.policy.mode === "enforce" && choice === "block";
    return finish(ctx, verdict.newVerdict({
      action: block ? verdict.ACTION_BLOCK : verdict.ACTION_PASS,
      verdict: verdict.SKIPPED, source: verdict.SRC_L1, reason,
    }));
  }
  if (r === rulesMod.BLOCK) {
    const action = cfg.policy.mode === "enforce" ? verdict.ACTION_BLOCK : verdict.ACTION_PASS;
    return finish(ctx, verdict.newVerdict({ action, verdict: verdict.MALICIOUS, score: 1, source: verdict.SRC_L1, reason }));
  }

  let whole = text;
  if (untrusted) whole += UNTRUSTED_SEP + untrusted.text;
  if (tools) whole += TOOLS_SEP + tools.text;
  const fp = normalize.fingerprint(whole, { prefix_bytes: cfg.cache.fp_prefix_bytes }, ctx.hash);
  const uspec = untrusted ? untrustedSpec(cfg, rule) : undefined;
  // the text only stands aside when it alone would have passed
  const only = !!(untrusted?.only || tools?.only);
  // the text holds retrieved content: not the subject's own (repOf)
  const textRep: false | undefined = retrieved ? false : undefined;

  // trust -----------------------------------------------------------------
  // An operator called this exact text a false positive. Checked before the
  // verdict cache so it wins over a stale malicious score for the same text.
  if (fp !== "" && trust.enabled(cfg.feedback)) {
    const store = ctx.trust ?? ctx.cache;
    const now = ctx.clock ? ctx.clock() : 0;
    const rec = await trust.get(store, fp, now);
    if (rec && store) {
      await after(ctx, () => trust.touch(store, fp, rec, now, cfg.feedback));
      return finish(ctx, verdict.newVerdict({
        action: verdict.ACTION_PASS, verdict: verdict.SAFE, score: 0,
        source: verdict.SRC_TRUST, fingerprint: fp,
        // Lua: `rec.by and (...)`; "" is truthy there, so an empty `by` still reads "trusted by "
        reason: rec.by !== undefined && rec.by !== null ? "fingerprint trusted by " + rec.by : "fingerprint trusted",
      }));
    }
  }

  // cache -----------------------------------------------------------------
  // The whole request's entry. Judged in parts, it names the parts in its
  // scope, so it never answers for the same text judged in one piece.
  let over: { templates: string[] } | undefined;
  if (uspec || tools) {
    const names = [(rule?.templates ?? []).join(",")];
    if (uspec) names.push("+" + uspec.templates.join(","));
    if (tools) names.push("+tools");
    over = { templates: names };
  }
  const ckey = fp !== "" ? cacheKey(fp, rule, cfg, ctx.hash, over) : undefined;
  if (ckey && ctx.cache) {
    const hit = (await ctx.cache.get(ckey)) as { score?: unknown; reason?: string; rep?: unknown } | undefined;
    if (hit && typeof hit === "object" && typeof hit.score === "number") {
      const [action, label] = policy.decide(hit.score, cfg.policy);
      // Never async on a hit: the cached score already is the judge's
      // answer, and a re-judge per hit would turn the cache into an
      // amplifier (one suspicious prompt repeated N times = N L3 calls).
      // none of this request's own text was judged alone: whatever the entry says
      const rep: Rep = textRep === false ? false : hit.rep === false || typeof hit.rep === "number" ? hit.rep : undefined;
      return finish(ctx, verdict.newVerdict({
        action, verdict: label, score: hit.score, async: false,
        source: verdict.SRC_CACHE, reason: hit.reason ?? reason, fingerprint: fp,
      }), rep);
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
      await settle(ctx);
      return finish(ctx, verdict.newVerdict({
        action: verdict.ACTION_BLOCK, verdict: verdict.SKIPPED, source: verdict.SRC_L1,
        reason: "unjudgeable: text over max_judge_chunks", fingerprint: fp,
      }));
    }
  }
  if ((chunks && chunks.length > 1) || untrusted || tools) {
    const context = {
      path: req.path ?? "", method: req.method ?? "",
      deployment: rule!.deployment_context ?? cfg.jev.deployment_context ?? "",
    };
    const parts: Part[] = [];
    if (!only) {
      for (const c of chunks && chunks.length > 1 ? chunks : [text]) {
        parts.push({ text: c, templates: rule!.templates, context, ...(textRep === false ? { rep: false as const } : {}) });
      }
    }
    let suffix = "";
    if (chunks && chunks.length > 1) suffix = capped ? " (window)" : ` (${chunks.length} chunks${windowed ? ", window" : ""})`;
    else if (windowed || untrusted?.windowed || tools?.windowed) suffix = " (window)";
    if (untrusted && uspec) {
      // asked without the deployment context, the way the question was
      // measured. Not the subject's own text: not charged to it (repOf).
      parts.push({
        text: untrusted.text, templates: uspec.templates,
        context: { path: req.path ?? "", method: req.method ?? "", deployment: "" },
        over: { templates: uspec.templates, deployment: "" }, rep: false,
      });
    }
    if (tools) {
      // the client sent them: the same question and scope as its own text,
      // so the entry is the one any text like it gets. Their score decides
      // the request; not charged either (repOf).
      parts.push({ text: tools.text, templates: rule!.templates, context, label: TOOLS_LABEL, rep: false });
    }
    return judgeParts(ctx, rule!, parts, suffix, fp, ckey, reason);
  }
  const [prompt, perr] = judge.build(rule!.templates, text, {
    path: req.path ?? "",
    method: req.method ?? "",
    deployment: rule!.deployment_context ?? cfg.jev.deployment_context ?? "",
  });
  if (!prompt) {
    log(ctx, "error", "jev-edge: " + perr);
    await settle(ctx);
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({ action, verdict: label, async, source: verdict.SRC_L2, reason: perr, fingerprint: fp }));
  }

  const t0 = nowMs(ctx);
  const [answers, jerr, jkind] = await ctx.judge.call(prompt, cfg.jev.timeout_ms);
  const elapsed = nowMs(ctx) - t0;

  if (!answers) {
    const why = judge.reason(jerr, jkind);
    await settle(ctx, judge.counts(jerr, jkind));
    log(ctx, "warn", "jev-edge: L2 failed: " + why);
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({
      action, verdict: label, async, source: verdict.SRC_L2,
      reason: why, fingerprint: fp, l2_ms: elapsed,
    }));
  }

  const [score, top, n] = judge.reduce(answers);
  if (n === 0) {
    // An answer with no score in it is an error, not a SAFE verdict: caching
    // score 0 would wave the same text through for fp_ttl. Nor is it the
    // provider failing: the judged text can make a judge answer that way.
    const why = judge.reason("no scores in answer", judge.UNUSABLE);
    await settle(ctx);
    log(ctx, "warn", "jev-edge: L2 answer has no scores");
    const [action, label, async] = policy.onError();
    return finish(ctx, verdict.newVerdict({
      action, verdict: label, async, source: verdict.SRC_L2,
      reason: why, fingerprint: fp, l2_ms: elapsed,
    }));
  }
  await settle(ctx, false, true);
  const [action, label, async] = policy.decide(score, cfg.policy);
  // the score is for the window, not the whole text; say so
  const why = top !== "" ? `${top} ${verdict.format2(score)}${windowed ? " (window)" : ""}` : reason;

  const cache = ctx.cache;
  if (ckey && cache) {
    await after(ctx, () => cache.set(ckey, { score, reason: why, ...(textRep === false ? { rep: false } : {}) }, cfg.cache.fp_ttl));
  }

  return finish(ctx, verdict.newVerdict({
    action, verdict: label, score, async, source: verdict.SRC_L2, reason: why, fingerprint: fp, l2_ms: elapsed,
  }), textRep);
}

export { rulesMod as rules, normalize, judge, policy, verdict, trust, subject };
export { sha256Hex } from "./sha256.js";
export * as defaults from "./defaults.js";
export * as breaker from "./breaker.js";
export type { Req, Rule, CacheLike, ToolsPart, UntrustedPart } from "./rules.js";
export type { Verdict } from "./verdict.js";
export type { Config } from "./defaults.js";
export type { Prompt, Answers } from "./judge.js";
export type { Entry as SubjectEntry, SubjectCtx } from "./subject.js";
