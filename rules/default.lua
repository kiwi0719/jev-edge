-- rules/default.lua
-- Empty watch list: jev-edge does nothing until a path is explicitly watched.
return {
  id = "default",
  watch_paths = {},
  methods = { POST = true },
  content_types = { "application/json" },
  text_fields = { "prompt", "input", "text" },
  templates = { "injection" },
}
