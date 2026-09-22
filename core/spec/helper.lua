-- Maps `jev.core.<x>` to ./core/<x>.lua and `jev.rules.<x>` to ./rules/<x>.lua
-- so specs run from the repo root without an install step.
local function searcher(name)
  local rel = name:match("^jev%.core%.(.+)$")
  local file
  if rel then
    file = "core/" .. rel:gsub("%.", "/") .. ".lua"
  elseif name == "jev.core" then
    file = "core/init.lua"
  else
    rel = name:match("^jev%.rules%.(.+)$")
    if rel then file = "rules/" .. rel .. ".lua" end
  end
  if not file then return nil end
  local f = io.open(file, "r")
  if not f then return nil end
  f:close()
  return loadfile(file), file
end

local searchers = package.searchers or package.loaders -- luacheck: ignore 143
table.insert(searchers, 2, searcher)

-- Shared test doubles ---------------------------------------------------------

local H = {}

function H.store()
  local data = {}
  return {
    get = function(_, k) return data[k] end,
    set = function(_, k, v, _ttl) data[k] = v end,
    incr = function(_, k, by, _ttl) data[k] = (tonumber(data[k]) or 0) + (by or 1); return data[k] end,
    add = function(_, k, v, _ttl) if data[k] ~= nil then return false end; data[k] = v; return true end,
    expire = function(_, k, _ttl) return data[k] ~= nil end,
    dump = function() return data end,
  }
end

function H.clock(start)
  local t = start or 1000
  return {
    now = function() return t end,
    advance = function(d) t = t + d end,
  }
end

H.json = require "dkjson"
-- Request bodies decode JSON null to a non-nil value, as cjson (cjson.null)
-- does in production: `[null, {...}]` must not end the array at the hole
-- dkjson would otherwise leave.
function H.body_decode(s) return H.json.decode(s, 1, H.json.null) end

-- PCRE matcher with the same contract the OpenResty adapter gives core:
-- re_find(subject, pattern) -> truthy on a case-insensitive match.
do
  local rex = require "rex_pcre2"
  local CASELESS = rex.flags().CASELESS
  local compiled = {}
  function H.re_find(subject, pattern)
    local re = compiled[pattern]
    if not re then
      re = rex.new(pattern, CASELESS)
      compiled[pattern] = re
    end
    return re:find(subject) ~= nil
  end
end

function H.ctx(over)
  local defaults = require "jev.core.defaults"
  local normalize = require "jev.core.normalize"
  local clock = H.clock()
  local ctx = {
    config = defaults.merge(defaults.config, over and over.config),
    rules = { require "jev.rules.llm-endpoints" },
    cache = H.store(),
    clock = clock.now,
    _clock = clock,
    hash = normalize.djb2,
    json_decode = function(s) return H.body_decode(s) end,
    re_find = H.re_find,
    judge = { call = function() return { injection = 0.1 } end },
    logs = {},
  }
  ctx.log = function(level, msg) ctx.logs[#ctx.logs + 1] = level .. ": " .. msg end
  for k, v in pairs(over or {}) do
    if k ~= "config" then ctx[k] = v end
  end
  return ctx
end

function H.chat_req(text, over)
  local body = H.json.encode({ messages = { { role = "user", content = text } } })
  local req = {
    method = "POST",
    path = "/v1/chat/completions",
    headers = { ["content-type"] = "application/json" },
    body = body,
    body_size = #body,
    client_ip = "203.0.113.7",
  }
  for k, v in pairs(over or {}) do req[k] = v end
  return req
end

return H
