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
