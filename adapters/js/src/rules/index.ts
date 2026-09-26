// Ports of rules/*.lua. Keep the pattern lists identical to the Lua files;
// core/golden/rules.json has one positive per always_suspect pattern and
// fails a named case when the two drift.
import { patternError, pathPatternError, type Rule } from "../core/rules.js";
import { validateUntrusted, stringListError, templatesError } from "../core/defaults.js";
import { pathError } from "../core/normalize.js";

export const llmEndpoints: Rule = {
  id: "llm-endpoints",
  // generation routes and the aliases servers accept for them (see rules/llm-endpoints.lua)
  watch_paths: [
    "^/v1/chat", "^/v1/completions", "^/v1/responses", "^/v1/messages",
    "^/api/chat", "^/api/completions?", "^/api/generate/?$",
    "^/chat/completions", "^/completions?/?$", "^/responses/?$", "^/infill/?$",
    "^/engines/[^/]+/chat/completions", "^/engines/[^/]+/completions",
    "^/openai/deployments/[^/]+/chat/completions", "^/openai/deployments/[^/]+/completions",
    "^/openai/v1/chat", "^/openai/v1/completions", "^/openai/v1/responses",
    // Gemini generateContent and streamGenerateContent (the Gemini API, Vertex AI, LiteLLM), Gemini's OpenAI route
    "^/v1%w*/.+:%a*[Gg]enerate[Cc]ontent/?$", "^/models/.+:%a*[Gg]enerate[Cc]ontent/?$",
    "^/v1beta/openai/chat/completions",
    // inference servers' native routes: SGLang, TGI (root POST, JSON only), vLLM and SageMaker-style /invocations
    "^/$", "^/generate/?$", "^/generate_stream/?$", "^/vertex/?$", "^/invocations/?$",
    // Open WebUI: /api/v1 aliases, Anthropic Messages routes, Ollama and OpenAI proxies
    "^/api/v1/chat/completions", "^/api/v1/messages/?$", "^/api/message/?$",
    "^/ollama/api/chat", "^/ollama/api/generate", "^/ollama/v1/chat", "^/ollama/v1/completions",
    "^/ollama/v1/messages", "^/ollama/v1/responses",
    "^/openai/chat/completions", "^/openai/completions", "^/openai/responses", "^/openai/messages",
    // LM Studio REST API; Cohere v2 chat and v1 generate
    "^/api/v0/chat/completions", "^/api/v0/completions", "^/api/v1/chat/?$",
    "^/v2/chat/?$", "^/v1/generate/?$",
  ],
  // watched only for a JSON body: TGI's root (see rules/llm-endpoints.lua)
  json_only_paths: ["^/$"],
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
    "system", "instructions", "preamble", "system_prompt", "systemInstruction.parts",
    "system_instruction.parts", "documents", "template",
    "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
    "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
    "messages[*].content[*].input.**", "messages[*].parts",
    "messages[*].parts[*].input.**", "messages[*].parts[*].output.**",
    "contents[*].parts", "contents.parts", "chat_history[*].message", "message",
    "prompt", "prompt.prompt_string", "prompt[*].prompt_string", "prompt.variables.**",
    "input", "input[*].arguments.**", "input[*].input", "input[*].output",
    "inputs", "instances[*].inputs", "instances[*].messages[*].content",
    "query", "text", "input_ids", "suffix", "input_prefix", "input_suffix", "input_extra[*].filename",
    "input_extra[*].text",
  ],
  // tool definitions and output schemas (Gemini's functionDeclarations are
  // under tools), judged as a part of their own with their own verdict-cache
  // entry (see rules/llm-endpoints.lua)
  tool_fields: ["tools", "functions", "response_format.json_schema", "text.format"],
  min_text_chars: 20,
  // a prompt sent as token ids: "unjudgeable" (policy.unjudgeable decides) or
  // "block" (refused in enforce mode); see rules/llm-endpoints.lua
  token_prompts: "unjudgeable",
  always_suspect: [
    String.raw`\b(ignore|disregard|forget)\b.{0,20}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b`,
    String.raw`\byou are now\b`,
    String.raw`\b(system|hidden|secret|initial)\s+prompt\b`,
    String.raw`<\|?(system|im_start)\|?>`,
    String.raw`\[/?INST\]`,
    String.raw`\bdeveloper mode\b`,
    String.raw`\b(DAN|do anything now)\b`,
    String.raw`\b(reveal|print|repeat|show)\b.{0,30}\b(instructions|system prompt|rules)\b`,
    // a long base64 blob, as one class run (see rules/llm-endpoints.lua)
    String.raw`[A-Za-z0-9+/]{160,}={0,2}`,
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
  text_fields: ["prompt", "instructions", "input", "input[*].output", "text"],
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
export type RuleSpec = string | (Omit<Partial<Rule>, "methods"> & {
  id?: string; extends?: string;
  /** a map { POST: true } or a list ["POST"]; resolve() makes it an uppercase map */
  methods?: Record<string, boolean> | string[];
});

// Port of methods_of() in core/rules.lua: a rule's methods as the uppercase
// map evaluate() looks methods up in, from a map { POST: true } (false leaves
// the method out) or a list ["POST"]; undefined when neither, or none.
function methodsOf(v: unknown): Record<string, boolean> | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const out: Record<string, boolean> = {};
  let any = false;
  if (Array.isArray(v) && v.length > 0) {
    for (const m of v) {
      if (typeof m !== "string" || m === "") return undefined;
      out[m.toUpperCase()] = true;
      any = true;
    }
  } else {
    for (const [k, on] of Object.entries(v)) {
      if (k === "" || typeof on !== "boolean") return undefined;
      if (on) {
        out[k.toUpperCase()] = true;
        any = true;
      }
    }
  }
  return any ? out : undefined;
}

const asciiLower = (s: string): string => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());

// Port of check_fields() in core/rules.lua: type checks for the fields
// resolve() does not fill in, which would otherwise turn judging off for the
// rule or fail open; methods become an uppercase map, content types lowercase.
function checkFields(out: Rule): void {
  const id = out.id;
  const r = out as unknown as Record<string, unknown>;
  if (r.methods !== undefined) {
    const m = methodsOf(r.methods);
    if (!m) throw new Error(`rule ${id}: methods must be a list of method names, or a map of them to true`);
    out.methods = m;
  }
  for (const k of ["always_suspect", "skip_content_types", "content_types"] as const) {
    if (r[k] === undefined) continue;
    const err = stringListError(r[k], `rule ${id}: ${k}`);
    if (err) throw new Error(err);
  }
  for (const k of ["skip_content_types", "content_types"] as const) {
    const v = out[k];
    if (v !== undefined) out[k] = v.map(asciiLower);
  }
  for (const k of ["max_body_bytes", "max_judge_bytes"] as const) {
    const v = r[k];
    if (v !== undefined && !(typeof v === "number" && v > 0)) throw new Error(`rule ${id}: ${k} must be a number > 0`);
  }
  // 0 is no minimum; NaN, which every comparison fails, is not a number here
  for (const k of ["min_body_bytes", "min_text_chars"] as const) {
    const v = r[k];
    if (v !== undefined && !(typeof v === "number" && v >= 0)) throw new Error(`rule ${id}: ${k} must be a number >= 0`);
  }
  const c = r.max_judge_chunks;
  if (c !== undefined && !(typeof c === "number" && c >= 1 && c % 1 === 0)) {
    throw new Error(`rule ${id}: max_judge_chunks must be an integer >= 1`);
  }
  if (r.deployment_context !== undefined && typeof r.deployment_context !== "string") {
    throw new Error(`rule ${id}: deployment_context must be a string`);
  }
  if (r.token_prompts !== undefined && r.token_prompts !== "unjudgeable" && r.token_prompts !== "block") {
    throw new Error(`rule ${id}: token_prompts must be unjudgeable|block`);
  }
}

export function resolve(spec: RuleSpec): Rule {
  // A string is the same as `{ extends: "<id>" }`: the loaded module is
  // copied, never handed back, so callers cannot mutate the shared table,
  // and the same defaults apply to both forms.
  if (typeof spec === "string") spec = { extends: spec } as RuleSpec & object;
  if (typeof spec !== "object" || spec === null) throw new Error("rule spec must be a string or a table");
  const ext: unknown = spec.extends;
  if (ext !== undefined && (typeof ext !== "string" || ext === "")) {
    throw new Error("rule extends must be the id of a rule set (a non-empty string)");
  }
  const base: Partial<Rule> = ext !== undefined ? load(ext) : {};
  const { extends: _ext, ...over } = spec;
  const out = { ...base, ...over } as Rule;
  if (out.id === undefined) throw new Error("rule needs an id");
  if (typeof out.id !== "string" || out.id === "") throw new Error("rule id must be a non-empty string");
  if (!Array.isArray(out.watch_paths)) throw new Error(`rule ${out.id} needs watch_paths`);
  if (out.json_only_paths !== undefined && !Array.isArray(out.json_only_paths)) {
    throw new Error(`rule ${out.id}: json_only_paths must be a list of patterns`);
  }
  // watch_paths and json_only_paths are Lua patterns; a malformed one raises
  // on every request, and so does one this adapter cannot translate (%b, a
  // back-reference), which OpenResty would match: refused here, at load.
  for (const k of ["watch_paths", "json_only_paths"] as const) {
    (out[k] ?? []).forEach((p, i) => {
      if (typeof p !== "string") throw new Error(`rule ${out.id}: ${k}[${i + 1}] must be a string`);
      const perr = patternError(p) ?? pathPatternError(p, out.paths_case_sensitive);
      if (perr) throw new Error(`rule ${out.id}: ${k}[${i + 1}] ${perr}`);
    });
  }
  const [uok, uerr] = validateUntrusted(out.untrusted, `rule ${out.id}: untrusted`);
  if (!uok) throw new Error(uerr);
  // a prompt sent as token ids: "unjudgeable" leaves it to policy.unjudgeable,
  // "block" refuses it in enforce mode whatever that says (checkFields)
  if (out.token_prompts === undefined) out.token_prompts = "unjudgeable";
  checkFields(out);
  // JSON null is a wrong type, as in Lua (cjson.null), not a field left out
  for (const k of ["text_fields", "tool_fields"] as const) {
    if (out[k] === null) throw new Error(`rule ${out.id}: ${k} must be a list of paths`);
  }
  if (out.templates === null) throw new Error(`rule ${out.id}: templates must be a list of strings`);
  out.text_fields ??= [
    "system", "instructions", "preamble", "system_prompt", "systemInstruction.parts",
    "system_instruction.parts", "documents", "template",
    "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
    "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
    "messages[*].content[*].input.**", "messages[*].parts",
    "messages[*].parts[*].input.**", "messages[*].parts[*].output.**",
    "contents[*].parts", "contents.parts", "chat_history[*].message", "message",
    "prompt", "prompt.prompt_string", "prompt[*].prompt_string", "prompt.variables.**",
    "input", "input[*].arguments.**", "input[*].input", "input[*].output",
    "inputs", "instances[*].inputs", "instances[*].messages[*].content",
    "query", "text", "input_ids", "suffix", "input_prefix", "input_suffix", "input_extra[*].filename",
    "input_extra[*].text",
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
  const terr = templatesError(out.templates, `rule ${out.id}: templates`);
  if (terr) throw new Error(terr);
  return out;
}
