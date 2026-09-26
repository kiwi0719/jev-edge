-- scripts/require-all.lua
-- Loads every module of an installed tree, from that tree alone:
--
--   resty scripts/require-all.lua <rockspec> <tree> [--no-kong]
--
-- <tree> is a LuaRocks tree's share/lua/5.1 or the lib/ of `make dist`.
-- Every build.modules key of the rockspec must resolve to a file under <tree>
-- and load; each provider must load through resty.jev.http.load_provider and
-- each rule set through jev.rules.<id> with that id. kong.* modules need the
-- Kong PDK, so they are only compiled; --no-kong skips them (`make dist`
-- leaves the Kong plugin out). A misnamed key installs a file no require
-- finds, which the invariants and `luarocks lint` cannot see. Run by
-- scripts/package-smoke.sh (`make package-check`).

local rockspec, tree = arg[1], arg[2]
if not rockspec or not tree then
  io.stderr:write("usage: resty require-all.lua <rockspec> <tree> [--no-kong]\n")
  os.exit(2)
end
local no_kong = arg[3] == "--no-kong"

local spec = {}
local chunk = assert(loadfile(rockspec))
setfenv(chunk, spec)
chunk()

tree = tree:gsub("/$", "")
package.path = tree .. "/?.lua;" .. tree .. "/?/init.lua;" .. package.path

local bad, loaded = 0, 0
local function fail(what, msg)
  bad = bad + 1
  io.stderr:write("FAIL ", what, ": ", tostring(msg):match("^[^\n]*"), "\n")   -- not the searched paths
end

local names = {}
for name in pairs(spec.build.modules) do names[#names + 1] = name end
table.sort(names)

for _, name in ipairs(names) do
  local kong = name:find("^kong%.") ~= nil
  if not (kong and no_kong) then
    local path = package.searchpath(name, package.path)
    if not path or path:sub(1, #tree + 1) ~= tree .. "/" then
      fail(name, "not installed under " .. tree .. (path and (" (found " .. path .. ")") or ""))
    else
      local ok, err
      if kong then
        ok, err = loadfile(path)
      else
        ok, err = pcall(require, name)
      end
      if ok then loaded = loaded + 1 else fail(name, err) end
    end
  end
end

local http = require "resty.jev.http"
for _, name in ipairs(names) do
  local provider = name:match("^resty%.jev%.providers%.(.+)$")
  if provider then
    provider = provider:gsub("_", "-")   -- the name a config uses: openai-compat
    local p, err = http.load_provider(provider)
    if not p then fail("provider " .. provider, err) end
  end
  local id = name:match("^jev%.rules%.(.+)$")
  if id then
    local ok, r = pcall(require, "jev.rules." .. id)
    if not ok then
      fail("rules " .. id, r)
    elseif type(r) ~= "table" or r.id ~= id then
      fail("rules " .. id, "id is " .. tostring(type(r) == "table" and r.id or r))
    end
  end
end

print(("require-all: %d modules from %s, %d failures"):format(loaded, tree, bad))
os.exit(bad == 0 and 0 or 1)
