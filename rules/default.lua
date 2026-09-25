-- rules/default.lua
-- Empty watch list: jev-edge does nothing until a path is explicitly watched.
return {
  id = "default",
  watch_paths = {},
  methods = { POST = true },
  text_fields = { "prompt", "instructions", "input", "input[*].output", "text" },
  templates = { "injection" },
}
