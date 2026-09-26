-- resty/jev/config.lua
-- Layers: core defaults < config file < runtime override (shared dict).
-- Each worker keeps a plain table for the current config; reload is driven by
-- a timer that watches the file mtime and the override dict's version key.

local defaults = require "jev.core.defaults"
local cjson = require "cjson.safe"

local _M = {}

local state = {
  path = nil,
  -- the file config in force: the last one that passed validation ({}, the
  -- defaults, before any did). set_override validates against it.
  file_cfg = {},
  -- a file read but not in force because it was refused; tried again, with
  -- the override, whenever the override changes, and replaced by the next
  -- edit of the file
  file_pending = nil,
  file_mtime = 0,
  file_env = nil,
  override_version = 0,
  current = defaults.merge(defaults.config),
  rules = {},
  dict_name = "jev_config",
  -- false until a config was put in force; then a refused one keeps it
  applied = false,
  -- why the config in force is not the one asked for: the last validation
  -- failure of the file asked for (the pending one, else the one in force)
  -- with the override, cleared when that passes, and the last time the file
  -- could not be loaded (cleared when it loads)
  error = nil,
  file_error = nil,
}

local rules_mod = require "jev.core.rules"

-- rules entries are rule set ids or inline tables (with optional `extends`),
-- see core/rules.lua resolve(). At startup a bad entry is logged, skipped and
-- reported (config.error()), so one tenant's typo does not leave the other
-- rules off; once a config is in force, a file edit or override with one is
-- refused whole and the previous config stays, as for any invalid key.
local function load_rule_set(id)
  local ok, r = pcall(require, "jev.rules." .. id)
  if ok then return r end
  return nil, tostring(r)
end

-- the rules that load, their specs, and one "rules[i]: why" per one that
-- does not
local function load_rules(specs)
  local out, good, errs = {}, {}, {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, load_rule_set)
    if rule then
      out[#out + 1], good[#good + 1] = rule, spec
    else
      errs[#errs + 1] = "rules[" .. i .. "]: " .. tostring(err)
      ngx.log(ngx.ERR, "jev-edge: rules[", i, "] failed to load: ", tostring(err))
    end
  end
  return out, good, errs
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

-- A hint for the error line when validation fails on a key the config file
-- fills from a variable it read with os.getenv and got nothing for. A worker
-- only has the variables nginx.conf declares with `env NAME;`, and the file
-- runs again in every worker on each reload, so a salt or token that was there
-- at startup can read as empty after the first edit and the reload is refused.
-- The stock file always reads optional variables (the feedback token even with
-- feedback off), so an empty variable alone says nothing: the hint names one
-- only when the error names a key its value would have filled.
--
-- Which keys those are is found by running the file once more with each empty
-- variable returning a marker string and looking for the markers in the table
-- it returns: on the first error that needs it, once per loaded file, never
-- for a file that validates.
local function env_feeds(probe)
  if probe.feeds then return probe.feeds end
  local marks = {}
  for _, name in ipairs(probe.unset) do marks[name] = "\1jev-env-probe:" .. name .. "\1" end
  local getenv = os.getenv
  os.getenv = function(name)  -- luacheck: ignore 122
    local v = getenv(name)
    if v == nil then return marks[name] end
    return v
  end
  local ok, cfg = pcall(probe.chunk)
  os.getenv = getenv  -- luacheck: ignore 122
  local feeds, seen = {}, {}
  local function walk(t, prefix)
    if seen[t] then return end
    seen[t] = true
    for k, v in pairs(t) do
      local path = prefix .. tostring(k)
      if type(v) == "string" then
        for _, name in ipairs(probe.unset) do
          if v:find(marks[name], 1, true) then feeds[#feeds + 1] = { path = path, name = name } end
        end
      elseif type(v) == "table" then
        walk(v, path .. ".")
      end
    end
  end
  if ok and type(cfg) == "table" then walk(cfg, "") end
  probe.feeds, probe.chunk = feeds, nil
  return feeds
end

-- `path` appears in `err` as a whole key: "subject.salt" in "subject.enabled
-- needs subject.salt", not "jev.timeout_ms" in "jev.timeout_ms_x".
local function names_key(err, path)
  local init = 1
  while true do
    local s, e = err:find(path, init, true)
    if not s then return false end
    local before, after = err:sub(s - 1, s - 1), err:sub(e + 1, e + 1)
    if not before:find("^[%w_.]") and not after:find("^[%w_]") then return true end
    init = s + 1
  end
end

local function env_hint(err)
  local probe = state.file_env
  if not probe or type(err) ~= "string" then return "" end
  local fills, decl, named = {}, {}, {}
  for _, f in ipairs(env_feeds(probe)) do
    if names_key(err, f.path) then
      fills[#fills + 1] = f.path .. " from " .. f.name
      if not named[f.name] then
        named[f.name] = true
        decl[#decl + 1] = "`env " .. f.name .. ";`"
      end
    end
  end
  if #fills == 0 then return "" end
  return "; the config file sets " .. table.concat(fills, ", ") .. ", unset when it ran:"
    .. " if that is set for nginx, add " .. table.concat(decl, " ") .. " to nginx.conf"
    .. " (workers only see the variables nginx.conf declares)"
end

local function read_override()
  local dict = ngx.shared[state.dict_name]
  local raw = dict and dict:get("override")
  return raw and cjson.decode(raw) or {}
end

-- defaults < file < override, validated and with its rules loaded; nothing in
-- `state` changes. Returns what commit() puts in force, or nil, err. A rule
-- that does not load refuses the config, unless `lenient` (startup): then it
-- is skipped and named in `skipped`, and what goes in force is the file
-- without it, which GET /_jev/config shows and set_override checks against.
local function build(file_cfg, override, lenient)
  local merged = defaults.merge(defaults.merge(defaults.config, file_cfg), override)
  local ok, err = defaults.validate(merged)
  if not ok then return nil, tostring(err) end
  if not lenient then
    local rules, rerr = rules_mod.resolve_all(merged.rules, load_rule_set)
    if not rules then return nil, rerr end
    return { cfg = merged, rules = rules, file = file_cfg }
  end
  local rules, good, errs = load_rules(merged.rules)
  local b = { cfg = merged, rules = rules, file = file_cfg }
  if #errs > 0 then
    b.skipped = table.concat(errs, "; ")
    if override.rules == nil then
      local f = {}
      for k, v in pairs(file_cfg) do f[k] = v end
      f.rules = good
      b.file = f
      b.cfg = defaults.merge(defaults.merge(defaults.config, f), override)
    end
  end
  return b
end

local function commit(b)
  read_api_key(b.cfg)
  state.current, state.rules, state.file_cfg = b.cfg, b.rules, b.file
  state.applied = true
end

-- Puts in force the file asked for (the pending one, else the one in force)
-- with the override. When that is refused, the file in force (the defaults
-- before any passed) goes on with the override, which set_override checked
-- against it; when even that is refused, the previous config stays, or, when
-- nothing was ever in force (the init call), the defaults run, rules
-- included, so what runs is what GET /_jev/config shows (monitor mode, the
-- stock rules) and not the defaults' table with no rules loaded, where every
-- request passes as "no rules". /_jev/config and /_jev/health report the
-- error (config.error()) until the file asked for passes.
local function rebuild(reloaded)
  local override = read_override()
  local was_applied = state.applied
  local lenient = not was_applied
  local pending, perr = state.file_pending, nil
  if pending then
    local b, err = build(pending, override, lenient)
    if b then
      commit(b)
      -- in force without the rules it skipped at startup, the file stays
      -- pending: reported until an edit fixes it, and tried again (whole)
      -- when the override changes
      state.file_pending = b.skipped and pending or nil
      state.error = b.skipped
      if reloaded then ngx.log(ngx.NOTICE, "jev-edge: config file reloaded") end
      return b.skipped == nil
    end
    perr = err
  end
  local b, err = build(state.file_cfg, override, lenient)
  local why = perr or err
  if b then
    commit(b)
    state.error = perr or b.skipped
  else
    state.error = why
  end
  if not why then return b.skipped == nil end
  if was_applied then
    ngx.log(ngx.ERR, "jev-edge: config invalid, keeping previous: ", why, env_hint(why))
    return false
  end
  if b then
    ngx.log(ngx.ERR, "jev-edge: config invalid, using the defaults",
      next(override) == nil and " (monitor mode)" or " and the override", ": ", why, env_hint(why))
    return false
  end
  ngx.log(ngx.ERR, "jev-edge: config invalid, using the defaults (monitor mode): ", why, env_hint(why))
  local fallback = build({}, {}, true)
  if fallback then commit(fallback) end
  return false
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
      unset[#unset + 1] = name
    end
    return v
  end
  local ok, cfg = pcall(chunk)
  os.getenv = getenv  -- luacheck: ignore 122
  if not ok then return nil, cfg end
  if type(cfg) ~= "table" then return nil, "config must return a table" end
  state.file_env = #unset > 0 and { chunk = chunk, unset = unset } or nil
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
      state.file_pending = cfg
      state.file_mtime = file_mtime(path)
    else
      state.file_error = "cannot load " .. tostring(path) .. ": " .. tostring(err)
      ngx.log(ngx.ERR, "jev-edge: cannot load ", path, ": ", tostring(err), "; using defaults")
    end
  end
  rebuild()
end

--- Called by the reload timer. Returns true if anything changed.
function _M.reload()
  local changed, reloaded = false, false
  if state.path then
    local m = file_mtime(state.path)
    if m ~= state.file_mtime then
      -- advanced whatever the file holds, so a bad one is not read and
      -- refused again every 2 s
      state.file_mtime = m
      local cfg, err = load_file(state.path)
      if cfg then
        -- in force only once rebuild() has validated it: until then
        -- state.file_cfg, which set_override checks against, is the last
        -- file that passed
        state.file_pending = cfg
        state.file_error = nil
        changed, reloaded = true, true
      else
        state.file_error = "cannot load " .. tostring(state.path) .. ": " .. tostring(err)
        ngx.log(ngx.ERR, "jev-edge: config reload failed, keeping previous: ", tostring(err))
        -- what was pending is no longer what the file holds
        if state.file_pending then state.file_pending, state.error = nil, nil end
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
  if changed then rebuild(reloaded) end
  return changed
end

function _M.current() return state.current end
function _M.rules() return state.rules end

--- Why the config in force is not the one configured, or nil: the config
-- (file plus override) failed validation, or the file could not be loaded.
function _M.error() return state.error or state.file_error end

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
