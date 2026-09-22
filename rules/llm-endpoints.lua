-- rules/llm-endpoints.lua
-- L1 rule set for LLM application entry points.
-- watch_paths are Lua patterns (anchored prefixes). always_suspect are PCRE,
-- matched case-insensitively via ctx.re_find (ngx.re in OpenResty), so the
-- same rule file is portable to the Envoy and Cloudflare adapters.
return {
  id = "llm-endpoints",
  watch_paths = { "^/v1/chat", "^/v1/completions", "^/api/chat", "^/api/completions" },
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
  -- long-context or vision traffic; see README "Body size".
  max_body_bytes = 1048576,
  -- Text over this many bytes is cut to a window before the fingerprint and
  -- L2: the always_suspect hit, then the newest messages.
  max_judge_bytes = 32768,
  text_fields = { "messages[*].content", "prompt", "input", "query", "text" },
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
