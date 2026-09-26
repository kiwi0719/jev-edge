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
  -- LiteLLM and llama.cpp without the /v1 prefix (/responses included),
  -- LiteLLM /engines/<model>/, Azure OpenAI and LiteLLM
  -- /openai/deployments/<name>/ and /openai/v1/, llama.cpp /completion and
  -- /infill. Short generic names are anchored at both ends so an
  -- application's own routes do not match.
  watch_paths = {
    "^/v1/chat", "^/v1/completions", "^/v1/responses", "^/v1/messages",
    "^/api/chat", "^/api/completions?", "^/api/generate/?$",
    "^/chat/completions", "^/completions?/?$", "^/responses/?$", "^/infill/?$",
    "^/engines/[^/]+/chat/completions", "^/engines/[^/]+/completions",
    "^/openai/deployments/[^/]+/chat/completions", "^/openai/deployments/[^/]+/completions",
    "^/openai/v1/chat", "^/openai/v1/completions", "^/openai/v1/responses",
    -- Gemini generateContent and streamGenerateContent: the Gemini API
    -- (/v1beta/models/<m>:..., /v1/..., tunedModels, Vertex AI's
    -- /v1/projects/.../models/<m>:...), and LiteLLM, which serves them for
    -- every model, also as /models/<m>:... (<m> may hold a slash). Written
    -- in the real camelCase so that a rule with paths_case_sensitive = true
    -- watches them too. Gemini's OpenAI-compatible route.
    "^/v1%w*/.+:%a*[Gg]enerate[Cc]ontent/?$", "^/models/.+:%a*[Gg]enerate[Cc]ontent/?$",
    "^/v1beta/openai/chat/completions",
    -- Inference servers' native routes, beside their /v1 ones: SGLang
    -- /generate; TGI / (POST), /generate, /generate_stream, /vertex and
    -- /invocations; vLLM and SageMaker-style /invocations. The site root is
    -- watched only for a JSON body (json_only_paths below).
    "^/$", "^/generate/?$", "^/generate_stream/?$", "^/vertex/?$", "^/invocations/?$",
    -- Open WebUI: /api/v1/chat/completions (the /api/chat/completions
    -- handler), its Anthropic Messages routes, and its Ollama and OpenAI
    -- proxies (a /<url_idx> suffix included).
    "^/api/v1/chat/completions", "^/api/v1/messages/?$", "^/api/message/?$",
    "^/ollama/api/chat", "^/ollama/api/generate", "^/ollama/v1/chat", "^/ollama/v1/completions",
    "^/ollama/v1/messages", "^/ollama/v1/responses",
    "^/openai/chat/completions", "^/openai/completions", "^/openai/responses", "^/openai/messages",
    -- LM Studio's REST API; Cohere /v2/chat and /v1/generate (/v1/chat is above).
    "^/api/v0/chat/completions", "^/api/v0/completions", "^/api/v1/chat/?$",
    "^/v2/chat/?$", "^/v1/generate/?$",
  },
  -- Of the watch_paths, those watched only for a JSON body (one that parses
  -- as JSON, or declared JSON with text fields the scanner finds; past
  -- max_body_bytes, a JSON media type or a head that starts with { or [):
  -- TGI's root. A site's own POST to / (a login form, an upload, text that
  -- starts with {) passes as "path not watched: body not JSON", before the
  -- judge and the reputation checks. Lua patterns, like
  -- watch_paths; a rule that extends this one and watches / for any body
  -- sets json_only_paths = {}.
  json_only_paths = { "^/$" },
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
  -- (in parallel), consecutive chunks sharing 1 KiB. 1 = one window (hit +
  -- newest messages + head/tail), the cheapest; raise it (4 covers 32 KiB +
  -- 3 x 31 KiB = 125 KiB) to judge long text in full, and policy.unjudgeable
  -- then decides what still does not fit. See README.
  max_judge_chunks = 1,
  -- Oldest first: the judging window keeps the last ones first. The paths
  -- are walked together, in document order: each message's content, tool
  -- calls and parts together, so the newest turn is kept whole.
  -- The system text each API puts before the conversation: system (a string
  -- or text blocks): Anthropic Messages and Ollama /api/generate;
  -- instructions: the Responses API; preamble: Cohere v1; system_prompt: LM
  -- Studio /api/v1/chat; systemInstruction or system_instruction: Gemini.
  -- documents: retrieved documents (Cohere v1 and v2, vLLM chat), read
  -- whole: every key and string in them (WHOLE_FIELDS in core/normalize.lua).
  -- template: Ollama.
  -- Tool-call arguments, which chat templates render for the model and a
  -- client can write into the history: OpenAI and Ollama tool_calls, legacy
  -- function_call, Anthropic tool_use input, Responses function_call and
  -- mcp_call arguments (".**": every key and string below, a string of JSON
  -- read decoded), and the free-text input of custom tool calls.
  -- messages[*].parts: AI SDK 5 UIMessages, which carry no content; the
  -- input of their tool parts (type "tool-<name>" and "dynamic-tool") is a
  -- tool call's arguments, and their output (state "output-available") the
  -- tool's result, rendered for the model as any other tool result.
  -- contents: Gemini (a list, or one content as LiteLLM takes it), function
  -- responses included; parts given as one object are read by their keys
  -- too, which LiteLLM sends as text parts (KEY_FIELDS in
  -- core/normalize.lua). chat_history[*].message, message: Cohere v1
  -- /v1/chat. prompt.prompt_string: llama.cpp's prompt object, alone or in a
  -- list. prompt.variables.**: the values a Responses API stored prompt is
  -- filled with, every key and string below them.
  -- input[*].output: a Responses API function_call_output (a tool result).
  -- inputs, instances: TGI /generate, / and /vertex.
  -- suffix: OpenAI completions and Ollama; input_prefix, input_suffix,
  -- input_extra: llama.cpp /infill, each extra file's filename and text (it
  -- renders both for the model).
  text_fields = { "system", "instructions", "preamble", "system_prompt", "systemInstruction.parts",
                  "system_instruction.parts", "documents", "template",
                  "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
                  "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
                  "messages[*].content[*].input.**", "messages[*].parts",
                  "messages[*].parts[*].input.**", "messages[*].parts[*].output.**",
                  "contents[*].parts", "contents.parts", "chat_history[*].message", "message",
                  "prompt", "prompt.prompt_string", "prompt[*].prompt_string", "prompt.variables.**",
                  "input", "input[*].arguments.**", "input[*].input", "input[*].output",
                  "inputs", "instances[*].inputs", "instances[*].messages[*].content",
                  "query", "text", "suffix", "input_prefix", "input_suffix", "input_extra[*].filename",
                  "input_extra[*].text" },
  -- Tool definitions and output schemas, judged as a part of their own with
  -- the rule's templates and their own verdict-cache entry, so an unchanged
  -- tool set costs one judge call per cache lifetime: OpenAI chat, Ollama,
  -- Responses, Anthropic and Cohere tools, Gemini's (their
  -- functionDeclarations), legacy functions, response_format.json_schema
  -- and the Responses text.format. Read from
  -- each: every key and string at any depth (JSON Schema included), but a
  -- `type` whose value is a JSON Schema type name: vLLM, llama.cpp and SGLang
  -- render the whole definition for the model. All of it is scanned by
  -- always_suspect and one max_judge_bytes window judged, beside the text's
  -- own window; past max_body_bytes the head and tail are scanned for them.
  -- {} turns it off for a rule.
  tool_fields = { "tools", "functions", "response_format.json_schema", "text.format" },
  min_text_chars = 20,
  -- A prompt given as token ids ("prompt": [40, 1541] or [[...]], or ids
  -- mixed with strings: OpenAI completions, vLLM, llama.cpp) reaches the
  -- model as text L1 never sees. With nothing else to judge it is
  -- unjudgeable ("unjudgeable: token ids"), and policy.unjudgeable decides;
  -- beside text long enough to judge, that text is judged. Set
  -- token_prompts = "block" to refuse every such prompt in enforce mode,
  -- text or not, whatever policy.unjudgeable says ("pass" lets them through
  -- under unjudgeable = "block"). Unset: policy.unjudgeable decides.
  -- token_prompts = "block",
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
    -- a long base64 blob: one class run, not a repeated group, so PCRE's
    -- JIT needs no stack per 4 characters and a 20 KB run still matches
    [[[A-Za-z0-9+/]{160,}={0,2}]],
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
