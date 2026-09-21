// Ports of rules/*.lua. Keep the pattern lists identical to the Lua files;
// core/golden/rules.json has one positive per always_suspect pattern and
// fails a named case when the two drift.
import type { Rule } from "../core/rules";

export const llmEndpoints: Rule = {
  id: "llm-endpoints",
  watch_paths: ["^/v1/chat", "^/v1/completions", "^/api/chat", "^/api/completions"],
  methods: { POST: true, PUT: true, PATCH: true },
  content_types: ["application/json", "text/plain", "application/x-www-form-urlencoded"],
  min_body_bytes: 8,
  max_body_bytes: 65536,
  text_fields: ["messages[*].content", "prompt", "input", "query", "text"],
  min_text_chars: 20,
  always_suspect: [
    String.raw`\b(ignore|disregard|forget)\b.{0,20}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b`,
    String.raw`\byou are now\b`,
    String.raw`\b(system|hidden|secret|initial)\s+prompt\b`,
    String.raw`<\|?(system|im_start)\|?>`,
    String.raw`\[/?INST\]`,
    String.raw`\bdeveloper mode\b`,
    String.raw`\b(DAN|do anything now)\b`,
    String.raw`\b(reveal|print|repeat|show)\b.{0,30}\b(instructions|system prompt|rules)\b`,
    String.raw`(?:[A-Za-z0-9+/]{4}){40,}={0,2}`,
  ],
  templates: ["injection"],
};

export const defaultRule: Rule = {
  id: "default",
  watch_paths: [],
  methods: { POST: true },
  content_types: ["application/json"],
  text_fields: ["prompt", "input", "text"],
  templates: ["injection"],
};

export const RULES: Record<string, Rule> = { "llm-endpoints": llmEndpoints, default: defaultRule };

export function load(id: string): Rule {
  const r = RULES[id];
  if (!r) throw new Error(`unknown rule set: ${id}`);
  return r;
}

/** Inline rule spec: a complete Rule, or a partial one with `extends: "<id>"`. Mirrors core/rules.lua resolve(). */
export type RuleSpec = string | (Partial<Rule> & { id: string; extends?: string });

export function resolve(spec: RuleSpec): Rule {
  if (typeof spec === "string") return load(spec);
  const base: Partial<Rule> = spec.extends ? load(spec.extends) : {};
  const { extends: _ext, ...over } = spec;
  const out = { ...base, ...over } as Rule;
  if (!out.id) throw new Error("rule needs an id");
  if (!Array.isArray(out.watch_paths)) throw new Error(`rule ${out.id} needs watch_paths`);
  out.text_fields ??= ["messages[*].content", "prompt", "input", "query", "text"];
  out.templates ??= ["injection"];
  return out;
}
