// Port of core/judge.lua: prompt building and answer reduction.
import { TEMPLATES, type Template } from "./templates.js";
import { wellFormed } from "./normalize.js";

export interface PromptContext {
  path: string;
  method: string;
  deployment: string;
}

export interface Prompt {
  text: string;
  context: PromptContext;
  questions: Record<string, Template>;
}

export type Answers = Record<string, unknown>;

const registry: Record<string, Template> = { ...TEMPLATES };

/**
 * The error a judge returns when it refused a call because the gateway's own
 * concurrency cap was full. The call never reached the provider, so it says
 * nothing about the provider's health: core does not count it as a breaker
 * failure (a burst of concurrent requests must not be able to trip the
 * breaker and switch L2 off for everyone). Same string as core/judge.lua.
 */
export const BUSY = "max_inflight exceeded";

/**
 * What a failed call ran into: the third element of a judge result with no
 * answers (`[null, err, kind]`). The breaker measures the provider's health,
 * and the judged text is the client's: a 200 whose answer the text made
 * unusable, or a 4xx the text provoked (a content filter, a strict parser),
 * would let a client switch L2 off for every tenant. So only the first
 * three kinds count (counts()). Same strings as core/judge.lua.
 */
export const TRANSPORT = "transport"; // no HTTP answer: connect, DNS, TLS, reset
export const TIMEOUT = "timeout";
export const UNAVAILABLE = "unavailable"; // HTTP 5xx, 429, 401, 404 or 405
export const REJECTED = "rejected"; // any other non-2xx status: this call was refused
export const UNUSABLE = "unusable"; // 2xx, but no answer core can use
export type ErrorKind = typeof TRANSPORT | typeof TIMEOUT | typeof UNAVAILABLE | typeof REJECTED | typeof UNUSABLE;

/** 401 (the key), 404 (the endpoint or the model) and 405 (the route): the
 *  gateway's configuration, which no judged text can provoke. They count, so
 *  a provider misconfigured for good opens the breaker and its alerts fire.
 *  A 400, 403, 413 or 422 stays REJECTED: a content filter, a WAF or a strict
 *  parser answers those to the text. Same set as core/judge.lua. */
const CONFIG_STATUS = new Set([401, 404, 405]);

/** The kind of a failed call the provider answered with this HTTP status. */
export function statusKind(status: number): ErrorKind {
  if (status >= 500 || status === 429 || CONFIG_STATUS.has(status)) return UNAVAILABLE;
  if (status >= 200 && status < 300) return UNUSABLE;
  return REJECTED;
}

/** The kinds an L2 error verdict names (Verdict.error_kind): the five above,
 *  "busy" for BUSY and "other" for a judge that gives no kind or an unknown
 *  one, or a prompt that could not be built. A fixed set (it labels a
 *  metric). Same strings as core/judge.lua. */
export const KIND_BUSY = "busy";
export const KIND_OTHER = "other";
export type VerdictErrorKind = ErrorKind | typeof KIND_BUSY | typeof KIND_OTHER;
const KINDS = new Set<string>([TRANSPORT, TIMEOUT, UNAVAILABLE, REJECTED, UNUSABLE]);

/** Port of judge.error_kind: the error kind an L2 error verdict carries. */
export function errorKind(err: unknown, kind?: ErrorKind | null): VerdictErrorKind {
  if (err === BUSY) return KIND_BUSY;
  if (typeof kind === "string" && KINDS.has(kind)) return kind;
  return KIND_OTHER;
}

/** Does a failed call count against the provider (a breaker failure)? A
 *  judge that gives no kind is counted, as every error was before kinds. */
export function counts(err: unknown, kind?: ErrorKind | null): boolean {
  if (err === BUSY) return false;
  if (kind === undefined || kind === null) return true;
  return kind === TRANSPORT || kind === TIMEOUT || kind === UNAVAILABLE;
}

/** The verdict reason for a failed call: the error, led by its kind when the
 *  breaker did not count it, so the reason says why it did not. */
export function reason(err: unknown, kind?: ErrorKind | null): string {
  const e = String(err ?? "error");
  return kind === REJECTED || kind === UNUSABLE ? kind + ": " + e : e;
}

export function register(name: string, t: Template): void {
  registry[name] = t;
}

export function get(name: string): Template | undefined {
  return registry[name];
}

/**
 * Port of judge.build. A lone surrogate in `text` is sent as U+FFFD
 * (wellFormed), the text Lua sends for the same body: a strict judge server
 * refuses the call otherwise, and an L2 error passes the request.
 */
export function build(names: string[] | undefined, text: string, context: PromptContext): [Prompt, null] | [null, string] {
  const qs: Record<string, Template> = {};
  let n = 0;
  for (const name of names ?? []) {
    const t = registry[name];
    if (t) {
      qs[name] = t;
      n++;
    }
  }
  if (n === 0) return [null, "no templates registered for: " + (names ?? []).join(",")];
  return [{ text: typeof text === "string" ? wellFormed(text) : text, context, questions: qs }, null];
}

/**
 * Highest answer wins. Lua iterates `pairs` in undefined order, so on an exact
 * tie the winning template name is unspecified on both implementations; the
 * score is not.
 */
/** Returns [score, top template, count of numeric answers]; a count of 0 means
 *  the provider answered nothing usable -- an error, not a safe score. */
export function reduce(answers: Answers | null | undefined): [number, string, number] {
  let best = 0;
  let bestName = "";
  let n = 0;
  for (const [name, raw] of Object.entries(answers ?? {})) {
    if (typeof raw !== "number" && typeof raw !== "string") continue; // Lua tonumber(table/bool) -> nil
    if (typeof raw === "string" && raw.trim() === "") continue; // Lua tonumber("") -> nil; Number("") is 0
    const p = typeof raw === "number" ? raw : Number(raw);
    if (Number.isNaN(p)) continue;
    n++;
    if (p > best) {
      best = p;
      bestName = name;
    }
  }
  if (best > 1) best = 1;
  return [best, bestName, n];
}
