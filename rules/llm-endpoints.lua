-- rules/llm-endpoints.lua
-- L1 rule set for LLM application entry points.
-- Patterns are Lua patterns matched against the lowercased extracted text.
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
    "ignore %a* ?%a*instructions",
    "disregard %a* ?%a*instructions",
    "you are now",
    "system prompt",
    "<|?system|?>",
    "%[inst%]",
    "developer mode",
    "do anything now",
  },
  templates = { "injection" },
}
