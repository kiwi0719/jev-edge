-- A rule set only the hybrid e2e's control plane has on its Lua path
-- (docker-compose.yml): the data plane lacks the file.
local r = {}
for k, v in pairs(require("jev.rules.llm-endpoints")) do r[k] = v end
r.id = "cp-only"
r.watch_paths = { "^/b/", "^/d/" }
return r
