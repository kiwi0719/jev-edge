// Port of core/judge.lua: prompt building and answer reduction.
import { TEMPLATES, type Template } from "./templates";

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

export function register(name: string, t: Template): void {
  registry[name] = t;
}

export function get(name: string): Template | undefined {
  return registry[name];
}

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
  return [{ text, context, questions: qs }, null];
}

/**
 * Highest answer wins. Lua iterates `pairs` in undefined order, so on an exact
 * tie the winning template name is unspecified on both implementations; the
 * score is not.
 */
export function reduce(answers: Answers | null | undefined): [number, string] {
  let best = 0;
  let bestName = "";
  for (const [name, raw] of Object.entries(answers ?? {})) {
    const p = typeof raw === "number" ? raw : Number(raw);
    if (typeof raw !== "number" && typeof raw !== "string") continue; // Lua tonumber(table/bool) -> nil
    if (Number.isNaN(p)) continue;
    if (p > best) {
      best = p;
      bestName = name;
    }
  }
  if (best > 1) best = 1;
  return [best, bestName];
}
