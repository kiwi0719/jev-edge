-- resty/jev/loader.lua
-- Resolves `jev.core.*` and `jev.rules.*` when the repo puts core/ and rules/
-- directly on lua_package_path instead of under jev/. It only fills in: when
-- `jev.core.x` / `jev.rules.x` already resolves on package.path (a rock, opm
-- or `make install` layout), it steps aside and the installed module loads,
-- so an unrelated core/x.lua or rules/x.lua elsewhere on the path, or in
-- nginx's working directory through ./?.lua, cannot stand in for it.
--
--   require("resty.jev.loader")()        installs the searcher (once)
--   require("resty.jev.loader").searcher the searcher itself, for tests

local searchpath = package.searchpath

local function searcher(name)
  local mapped = name:gsub("^jev%.core$", "core.init")
                     :gsub("^jev%.core%.", "core.")
                     :gsub("^jev%.rules%.", "rules.")
  if mapped == name then return nil end
  -- Installed layout: the standard file searcher finds the real module.
  if searchpath(name, package.path) then return nil end
  local path = searchpath(mapped, package.path)
  if not path then return nil end
  local chunk, err = loadfile(path)
  if not chunk then return err end
  return chunk, path
end

local searchers = package.searchers or package.loaders -- luacheck: ignore 143
local installed = false

local function install()
  if installed then return end
  installed = true
  table.insert(searchers, 2, searcher)
end

return setmetatable({ searcher = searcher }, { __call = install })
