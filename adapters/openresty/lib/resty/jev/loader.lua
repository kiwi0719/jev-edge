-- resty/jev/loader.lua
-- Resolves `jev.core.*` and `jev.rules.*` when the repo (or an install) puts
-- core/ and rules/ directly on lua_package_path instead of under jev/.
-- Harmless if the modules already resolve normally.

local searchpath = package.searchpath

local function searcher(name)
  local mapped = name:gsub("^jev%.core$", "core.init")
                     :gsub("^jev%.core%.", "core.")
                     :gsub("^jev%.rules%.", "rules.")
  if mapped == name then return nil end
  local path = searchpath(mapped, package.path)
  if not path then return nil end
  local chunk, err = loadfile(path)
  if not chunk then return err end
  return chunk, path
end

local searchers = package.searchers or package.loaders -- luacheck: ignore 143
local installed = false

return function()
  if installed then return end
  installed = true
  table.insert(searchers, 2, searcher)
end
