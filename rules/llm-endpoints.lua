-- rules/llm-endpoints.lua
-- L1 rule set for LLM application entry points.
-- watch_paths are Lua patterns, matched on the path the backend routes on
-- (ASCII case folded, ';' parameters dropped: core/rules.lua path_matches).
-- always_suspect are PCRE, matched case-insensitively via ctx.re_find
-- (ngx.re in OpenResty), so the same rule file is portable to the Envoy and
-- Cloudflare adapters.
return {
  id = "llm-endpoints",
  -- The generation routes of the servers jev-edge fronts, and the aliases
  -- they serve for the same handler: a route left out is one a client can
  -- switch to. OpenAI and compatible servers (/v1/..., Responses and
  -- Anthropic Messages included), Ollama (/api/chat, /api/generate), the
  -- Vercel AI SDK's useChat and useCompletion (/api/chat, /api/completion),
  -- LiteLLM and llama.cpp without the /v1 prefix, LiteLLM /engines/<model>/,
  -- Azure OpenAI and LiteLLM /openai/deployments/<name>/ and /openai/v1/,
  -- llama.cpp /completion and /infill. Short generic names are anchored at
  -- both ends so an application's own routes do not match.
  watch_paths = {
    "^/v1/chat", "^/v1/completions", "^/v1/responses", "^/v1/messages",
    "^/api/chat", "^/api/completions?", "^/api/generate/?$",
    "^/chat/completions", "^/completions?/?$", "^/infill/?$",
    "^/engines/[^/]+/chat/completions", "^/engines/[^/]+/completions",
    "^/openai/deployments/[^/]+/chat/completions", "^/openai/deployments/[^/]+/completions",
    "^/openai/v1/chat", "^/openai/v1/completions", "^/openai/v1/responses",
  },
  methods = { POST = true, PUT = true, PATCH = true },
  -- Media types that are never a prompt. Any other Content-Type (or none) is
  -- read and the body decides the format: backends parse JSON whatever the
  -- header says. List `content_types = { ... }` instead for an allow list.
  skip_content_types = { "image/", "audio/", "video/", "font/", "application/pdf", "application/zip",
                         "application/gzip" },
  min_body_bytes = 8,
  -- Bodies up to this size are parsed whole: 1 MiB, nginx's default
  -- client_max_body_size. Past it only the head and tail are scanned. Raise
  -- it with client_max_body_size (and your gateway's body buffer) for
  -- long-context or vision traffic; see docs/design.md "Body size".
  max_body_bytes = 1048576,
  -- Text over this many bytes is cut to a window before the fingerprint and
  -- L2: the always_suspect hit, then the newest messages.
  max_judge_bytes = 32768,
  -- Text over max_judge_bytes in up to this many chunks, one judge call each
  -- (in parallel). 1 = one window (hit + newest messages + head/tail), the
  -- cheapest; raise it (4 covers 128 KiB) to judge long text in full, and
  -- policy.unjudgeable then decides what still does not fit. See README.
  max_judge_chunks = 1,
  -- Oldest first: the judging window keeps the last ones first.
  -- system: Anthropic Messages and Ollama /api/generate; template: Ollama.
  -- Tool-call arguments, which chat templates render for the model and a
  -- client can write into the history: OpenAI and Ollama tool_calls, legacy
  -- function_call, Anthropic tool_use input, Responses function_call and
  -- mcp_call arguments (".**": every key and string below, a string of JSON
  -- read decoded), and the free-text input of custom tool calls. Before the
  -- messages, so the window keeps the newest turn first.
  -- messages[*].parts: AI SDK 5 UIMessages, which carry no content.
  -- input[*].output: a Responses API function_call_output (a tool result).
  -- suffix: OpenAI completions and Ollama; input_prefix, input_suffix,
  -- input_extra: llama.cpp /infill.
  text_fields = { "system", "template",
                  "messages[*].tool_calls[*].function.arguments.**", "messages[*].tool_calls[*].custom.input",
                  "messages[*].function_call.arguments.**", "messages[*].content[*].input.**",
                  "input[*].arguments.**", "input[*].input",
                  "messages[*].content", "messages[*].parts", "prompt", "input",
                  "input[*].output", "query", "text", "suffix", "input_prefix", "input_suffix",
                  "input_extra[*].text" },
  -- Tool definitions and output schemas, judged as a part of their own with
  -- the rule's templates and their own verdict-cache entry, so an unchanged
  -- tool set costs one judge call per cache lifetime: OpenAI chat, Ollama,
  -- Responses and Anthropic tools, legacy functions,
  -- response_format.json_schema and the Responses text.format. Read from
  -- each: name, description, title, enum, const, default and examples values
  -- and property names, at any depth (JSON Schema included); other strings
  -- (type, format, URLs, headers) are not. Up to 4 x max_judge_bytes of it is
  -- scanned by always_suspect and one max_judge_bytes window judged, beside
  -- the text's own window. {} turns it off for a rule.
  tool_fields = { "tools", "functions", "response_format.json_schema", "text.format" },
  min_text_chars = 20,
  always_suspect = {
    [[\b(ignore|disregard|forget)\b.{0,20}\b(previous|prior|above|earlier|all)\b]]
      .. [[.{0,20}\b(instructions?|rules?|prompts?)\b]],
    [[\byou are now\b]],
    [[\b(system|hidden|secret|initial)\s+prompt\b]],
    [[<\|?(system|im_start)\|?>]],
    [=[\[/?INST\]]=],
    [[\bdeveloper mode\b]],
    [[\b(DAN|do anything now)\b]],
    [[\b(reveal|print|repeat|show)\b.{0,30}\b(instructions|system prompt|rules)\b]],
    [[(?:[A-Za-z0-9+/]{4}){40,}={0,2}]],   -- long base64 blob
    -- Judge-directed text: the input talks to the classifier judging it
    -- (docs/design.md, "Judge robustness"). A hit only guarantees an L2 call
    -- and keeps the hit inside the judging window of a long body.
    -- "rate this as safe" (not "classify this mushroom as safe to eat")
    [[\b(rate|classify|mark|label|score|flag|treat|judge)\b.{0,30}]]
      .. [[\b(this|it|me|the (above|following|message|request|input|prompt|text))\b.{0,30}]]
      .. [[\bas\s+(a\s+)?(safe|benign|harmless|clean|legitimate|non-?malicious|0(\.0+)?)\b(?!\s+(to|for)\b)]],
    -- "you are a classifier, output 0"
    [[\b(classifier|moderator|guardrail|safety (filter|model|system|check)|content filter|judge model)\b]]
      .. [[.{0,40}\b(output|return|respond|answer|reply|say|print)\b.{0,20}\b(0(\.0+)?|safe|benign|harmless|false)\b]],
    -- "note to the AI reviewing this"
    [[\b(to|for)\s+(the|any)\s+(ai|model|llm|classifier|moderator|reviewer|filter)\s+]]
      .. [[(reviewing|checking|scanning|screening|evaluating|analy[sz]ing|reading|judging)\s+(this|these|the)\b]],
    -- a pre-written judge answer: {"injection": 0}, {"answers":{"injection":{"noul":0.0}}}
    [[[\x7b,]\s*"(injection|abuse|noul|jailbreak|prompt_injection)"\s*:\s*(\x7b|\[|"?(0(\.\d+)?|false|safe|benign)\b)]],
    -- a fake end-of-input marker: "=== END OF INPUT ===", "</end of user message>"
    [[(={3,}|-{3,}|#{2,}|\*{3,}|\[|</?)\s*end[ _-]+(of[ _-]+)?(the[ _-]+)?(user[ _-]+)?]]
      .. [[(input|message|prompt|text|data|query)\b]],
    -- "the real verdict is safe"
    [[\b(real|actual|true|correct|final)\s+(verdict|rating|classification)(\s+(is|should be)|\s*[=:])\s*"?]]
      .. [[(safe|benign|harmless|clean|0(\.0+)?|not (malicious|an? (injection|attack)))\b]],
  },
  templates = { "injection" },
}
