-- rules/llm-endpoints.lua
-- L1 rule set for LLM application entry points.
-- watch_paths are Lua patterns (anchored prefixes). always_suspect are PCRE,
-- matched case-insensitively via ctx.re_find (ngx.re in OpenResty), so the
-- same rule file is portable to the Envoy and Cloudflare adapters.
return {
  id = "llm-endpoints",
  watch_paths = { "^/v1/chat", "^/v1/completions", "^/api/chat", "^/api/completions" },
  methods = { POST = true, PUT = true, PATCH = true },
  content_types = { "application/json", "text/plain", "application/x-www-form-urlencoded" },
  min_body_bytes = 8,
  max_body_bytes = 65536,
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
  },
  templates = { "injection" },
}
