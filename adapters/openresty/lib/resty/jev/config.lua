-- resty/jev/config.lua
-- Layers: core defaults < config file < runtime override (shared dict).
-- Each worker keeps a plain table for the current config; reload is driven by
-- a timer that watches the file mtime and the override dict's version key.

local defaults = require "jev.core.defaults"
local cjson = require "cjson.safe"

local _M = {}

local state = {
  path = nil,
  file_cfg = {},
  file_mtime = 0,
  file_env_unset = {},
  override_version = 0,
  current = defaults.merge(defaults.config),
  rules = {},
  dict_name = "jev_config",
}

local rules_mod = require "jev.core.rules"

-- rules entries are rule set ids or inline tables (with optional `extends`),
-- see core/rules.lua resolve(). A bad entry is logged and skipped so one
-- tenant's typo does not take the gateway down.
local function load_rule_set(id)
  local ok, r = pcall(require, "jev.rules." .. id)
  if ok then return r end
  return nil, tostring(r)
end

local function load_rules(specs)
  local out = {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, load_rule_set)
    if rule then
      out[#out + 1] = rule
    else
      ngx.log(ngx.ERR, "jev-edge: rules[", i, "] failed to load: ", tostring(err))
    end
  end
  return out
end

local function read_api_key(cfg)
  local env = cfg.jev and cfg.jev.api_key_env
  if env and not cfg.jev.api_key and cfg.jev.provider ~= "mock" then
    cfg.jev.api_key = os.getenv(env)
    if not cfg.jev.api_key then
      ngx.log(ngx.WARN, "jev-edge: env ", env, " is empty (did you add `env ", env, ";` to nginx.conf?)")
    end
  end
end

-- The variables the last loaded file read with os.getenv and got nothing
-- for, as a hint on the error line: a worker only has the variables
-- nginx.conf declares with `env NAME;`, and the file runs again in every
-- worker on each reload, so a salt or token that was there at startup (in
-- the master) is empty after the first edit and the reload is refused.
local function env_hint()
  local names = state.file_env_unset
  if not names or #names == 0 then return "" end
  local decl = {}
  for i, name in ipairs(names) do decl[i] = "`env " .. name .. ";`" end
  return "; the config file read " .. table.concat(names, ", ") .. " from the environment and got nothing:"
    .. " did you add " .. table.concat(decl, " ") .. " to nginx.conf?"
    .. " workers do not inherit undeclared variables"
end

local function rebuild()
  local override = {}
  local dict = ngx.shared[state.dict_name]
  if dict then
    local raw = dict:get("override")
    if raw then override = cjson.decode(raw) or {} end
  end
  local merged = defaults.merge(defaults.merge(defaults.config, state.file_cfg), override)
  local ok, err = defaults.validate(merged)
  if not ok then
    ngx.log(ngx.ERR, "jev-edge: config invalid, keeping previous: ", err, env_hint())
    return false
  end
  read_api_key(merged)
  state.current = merged
  state.rules = load_rules(merged.rules)
  return true
end

local function file_mtime(path)
  local lfs_ok, lfs = pcall(require, "lfs")
  if lfs_ok then
    local attr = lfs.attributes(path)
    return attr and attr.modification or 0
  end
  -- no lfs: fall back to content hash as a change signal
  local f = io.open(path, "rb")
  if not f then return 0 end
  local data = f:read("*a")
  f:close()
  return ngx.crc32_long(data)
end

local function load_file(path)
  local chunk, err = loadfile(path)
  if not chunk then return nil, err end
  -- os.getenv is wrapped while the file runs to note what came back empty
  -- (env_hint), and put back even when the file fails. A config file has no
  -- reason to yield, so no request runs while the wrapper is in place.
  local getenv, unset, seen = os.getenv, {}, {}
  os.getenv = function(name)  -- luacheck: ignore 122
    local v = getenv(name)
    if v == nil and not seen[name] then
      seen[name] = true
      unset[#unset + 1] = tostring(name)
    end
    return v
  end
  local ok, cfg = pcall(chunk)
  os.getenv = getenv  -- luacheck: ignore 122
  if not ok then return nil, cfg end
  if type(cfg) ~= "table" then return nil, "config must return a table" end
  state.file_env_unset = unset
  return cfg
end

--- init_by_lua: load the file once.
function _M.init(path, opts)
  opts = opts or {}
  state.dict_name = opts.dict or state.dict_name
  state.path = path
  if path then
    local cfg, err = load_file(path)
    if cfg then
      state.file_cfg = cfg
      state.file_mtime = file_mtime(path)
    else
      ngx.log(ngx.ERR, "jev-edge: cannot load ", path, ": ", tostring(err), "; using defaults")
    end
  end
  rebuild()
end

--- Called by the reload timer. Returns true if anything changed.
function _M.reload()
  local changed = false
  if state.path then
    local m = file_mtime(state.path)
    if m ~= state.file_mtime then
      local cfg, err = load_file(state.path)
      if cfg then
        state.file_cfg = cfg
        state.file_mtime = m
        changed = true
        ngx.log(ngx.NOTICE, "jev-edge: config file reloaded")
      else
        ngx.log(ngx.ERR, "jev-edge: config reload failed, keeping previous: ", tostring(err))
        state.file_mtime = m
      end
    end
  end
  local dict = ngx.shared[state.dict_name]
  if dict then
    local v = dict:get("override_version") or 0
    if v ~= state.override_version then
      state.override_version = v
      changed = true
    end
  end
  if changed then rebuild() end
  return changed
end

function _M.current() return state.current end
function _M.rules() return state.rules end

--- Runtime override API (used by /_jev/config).
function _M.set_override(tbl)
  local dict = ngx.shared[state.dict_name]
  if not dict then return nil, "lua_shared_dict " .. state.dict_name .. " not defined" end
  local merged = defaults.merge(defaults.merge(defaults.config, state.file_cfg), tbl or {})
  local ok, err = defaults.validate(merged)
  if not ok then return nil, err end
  -- An override is refused, not logged-and-skipped, when a rule in it is
  -- broken: the caller is right there to read the error.
  local _, rerr = rules_mod.resolve_all(merged.rules, load_rule_set)
  if rerr then return nil, rerr end
  if tbl == nil then
    dict:delete("override")
  else
    dict:set("override", cjson.encode(tbl))
  end
  dict:incr("override_version", 1, 0)
  _M.reload()
  return true
end

function _M.get_override()
  local dict = ngx.shared[state.dict_name]
  if not dict then return nil end
  local raw = dict:get("override")
  return raw and cjson.decode(raw) or nil
end

return _M
