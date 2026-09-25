// Ports of rules/*.lua. Keep the pattern lists identical to the Lua files;
// core/golden/rules.json has one positive per always_suspect pattern and
// fails a named case when the two drift.
import { patternError, type Rule } from "../core/rules.js";
import { validateUntrusted } from "../core/defaults.js";
import { pathError } from "../core/normalize.js";

export const llmEndpoints: Rule = {
  id: "llm-endpoints",
  // generation routes and the aliases servers accept for them (see rules/llm-endpoints.lua)
  watch_paths: [
    "^/v1/chat", "^/v1/completions", "^/v1/responses", "^/v1/messages",
    "^/api/chat", "^/api/completions?", "^/api/generate/?$",
    "^/chat/completions", "^/completions?/?$", "^/infill/?$",
    "^/engines/[^/]+/chat/completions", "^/engines/[^/]+/completions",
    "^/openai/deployments/[^/]+/chat/completions", "^/openai/deployments/[^/]+/completions",
    "^/openai/v1/chat", "^/openai/v1/completions", "^/openai/v1/responses",
  ],
  methods: { POST: true, PUT: true, PATCH: true },
  skip_content_types: ["image/", "audio/", "video/", "font/", "application/pdf", "application/zip", "application/gzip"],
  min_body_bytes: 8,
  max_body_bytes: 1048576,
  max_judge_bytes: 32768,
  max_judge_chunks: 1,
  // oldest first: the judging window keeps the last ones first. The paths
  // are walked together, in document order (each message's content and tool
  // calls together); ".**": every key and string below, a string of JSON
  // read decoded.
  text_fields: [
    "system", "template",
    "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
    "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
    "messages[*].content[*].input.**", "messages[*].parts", "prompt",
    "input", "input[*].arguments.**", "input[*].input", "input[*].output",
    "query", "text", "suffix", "input_prefix", "input_suffix", "input_extra[*].text",
  ],
  // tool definitions and output schemas, judged as a part of their own with
  // their own verdict-cache entry (see rules/llm-endpoints.lua)
  tool_fields: ["tools", "functions", "response_format.json_schema", "text.format"],
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
    // Judge-directed text: the input talks to the classifier judging it.
    String.raw`\b(rate|classify|mark|label|score|flag|treat|judge)\b.{0,30}\b(this|it|me|the (above|following|message|request|input|prompt|text))\b.{0,30}\bas\s+(a\s+)?(safe|benign|harmless|clean|legitimate|non-?malicious|0(\.0+)?)\b(?!\s+(to|for)\b)`,
    String.raw`\b(classifier|moderator|guardrail|safety (filter|model|system|check)|content filter|judge model)\b.{0,40}\b(output|return|respond|answer|reply|say|print)\b.{0,20}\b(0(\.0+)?|safe|benign|harmless|false)\b`,
    String.raw`\b(to|for)\s+(the|any)\s+(ai|model|llm|classifier|moderator|reviewer|filter)\s+(reviewing|checking|scanning|screening|evaluating|analy[sz]ing|reading|judging)\s+(this|these|the)\b`,
    String.raw`[\x7b,]\s*"(injection|abuse|noul|jailbreak|prompt_injection)"\s*:\s*(\x7b|\[|"?(0(\.\d+)?|false|safe|benign)\b)`,
    String.raw`(={3,}|-{3,}|#{2,}|\*{3,}|\[|</?)\s*end[ _-]+(of[ _-]+)?(the[ _-]+)?(user[ _-]+)?(input|message|prompt|text|data|query)\b`,
    String.raw`\b(real|actual|true|correct|final)\s+(verdict|rating|classification)(\s+(is|should be)|\s*[=:])\s*"?(safe|benign|harmless|clean|0(\.0+)?|not (malicious|an? (injection|attack)))\b`,
  ],
  templates: ["injection"],
};

export const defaultRule: Rule = {
  id: "default",
  watch_paths: [],
  methods: { POST: true },
  text_fields: ["prompt", "input", "input[*].output", "text"],
  tool_fields: [],
  templates: ["injection"],
};

export const RULES: Record<string, Rule> = { "llm-endpoints": llmEndpoints, default: defaultRule };

export function load(id: string): Rule {
  const r = RULES[id];
  if (!r) throw new Error(`unknown rule set: ${id}`);
  return r;
}

/** Inline rule spec: a complete Rule, or a partial one with `extends: "<id>"`. Mirrors core/rules.lua resolve(). */
export type RuleSpec = string | (Partial<Rule> & { id?: string; extends?: string });

export function resolve(spec: RuleSpec): Rule {
  // A string is the same as `{ extends: "<id>" }`: the loaded module is
  // copied, never handed back, so callers cannot mutate the shared table,
  // and the same defaults apply to both forms.
  if (typeof spec === "string") spec = { extends: spec } as RuleSpec & object;
  if (typeof spec !== "object" || spec === null) throw new Error("rule spec must be a string or a table");
  const base: Partial<Rule> = spec.extends ? load(spec.extends) : {};
  const { extends: _ext, ...over } = spec;
  const out = { ...base, ...over } as Rule;
  if (!out.id) throw new Error("rule needs an id");
  if (!Array.isArray(out.watch_paths)) throw new Error(`rule ${out.id} needs watch_paths`);
  // watch_paths are Lua patterns; a malformed one raises on every request.
  out.watch_paths.forEach((p, i) => {
    if (typeof p !== "string") throw new Error(`rule ${out.id}: watch_paths[${i + 1}] must be a string`);
    const perr = patternError(p);
    if (perr) throw new Error(`rule ${out.id}: watch_paths[${i + 1}] ${perr}`);
  });
  const [uok, uerr] = validateUntrusted(out.untrusted, `rule ${out.id}: untrusted`);
  if (!uok) throw new Error(uerr);
  out.text_fields ??= [
    "system", "template",
    "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
    "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
    "messages[*].content[*].input.**", "messages[*].parts", "prompt",
    "input", "input[*].arguments.**", "input[*].input", "input[*].output",
    "query", "text", "suffix", "input_prefix", "input_suffix", "input_extra[*].text",
  ];
  out.tool_fields ??= ["tools", "functions", "response_format.json_schema", "text.format"];
  for (const k of ["text_fields", "tool_fields"] as const) {
    const paths = out[k];
    if (!Array.isArray(paths)) throw new Error(`rule ${out.id}: ${k} must be a list of paths`);
    paths.forEach((p, i) => {
      const perr = pathError(p);
      if (perr) throw new Error(`rule ${out.id}: ${k}[${i + 1}] ${perr}`);
    });
  }
  out.templates ??= ["injection"];
  return out;
}
