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

-- Deepest array/object nesting in JSON text, strings skipped.
local function json_depth(s)
  local depth, max, i = 0, 0, 1
  while true do
    local j, _, c = s:find('(["%[%]{}])', i)
    if not j then return max end
    if c == '"' then
      -- to the closing quote, past escapes
      local k = j + 1
      while true do
        local q = s:find('["\\]', k)
        if not q then return max end
        if s:sub(q, q) == '"' then j = q break end
        k = q + 2
      end
    elseif c == "[" or c == "{" then
      depth = depth + 1
      if depth > max then max = depth end
    else
      depth = depth - 1
    end
    i = j + 1
  end
end

-- True when JSON text has a \uD800-\uDFFF escape that is not half of a
-- pair (cjson refuses it; raw bytes of an encoded surrogate it passes on).
local function lone_surrogate_escape(s)
  local i = 1
  while true do
    local j = s:find("\\", i, true)
    if not j then return false end
    local hex = s:sub(j + 1, j + 1) == "u" and s:match("^%x%x%x%x", j + 2)
    if not hex then
      i = j + 2
    else
      local cp = tonumber(hex, 16)
      i = j + 6
      if cp >= 0xD800 and cp <= 0xDFFF then
        local lo = cp <= 0xDBFF and tonumber(s:match("^\\u(%x%x%x%x)", i) or "", 16)
        if not (lo and lo >= 0xDC00 and lo <= 0xDFFF) then return true end
        i = i + 6
      end
    end
  end
end

-- True when the commas and colons of JSON text are where RFC 8259 puts them.
-- dkjson reads `[1,2,]`, `{"a":1,}`, `[1 2]` and `{"a":1 "b":2}`; cjson and
-- JSON.parse refuse all four. Strings are skipped, scalars taken as a run of
-- the characters they are made of (dkjson has already checked them).
local function well_formed(s)
  -- what may come next: "v" a value, "v]" a value or "]", "k" a key,
  -- "k}" a key or "}", ":" a colon, "," a comma or the closer (after a value)
  local want, stack, i = "v", {}, 1
  while true do
    i = s:find("[^ \t\n\r]", i)
    if not i then return want == "," and #stack == 0 end
    local c = s:sub(i, i)
    local top = stack[#stack]
    if c == '"' then
      if want ~= "v" and want ~= "v]" and want ~= "k" and want ~= "k}" then return false end
      local k = i + 1
      while true do
        local q = s:find('["\\]', k)
        if not q then return false end
        if s:sub(q, q) == '"' then i = q break end
        k = q + 2
      end
      want = (want == "k" or want == "k}") and ":" or ","
    elseif c == "{" or c == "[" then
      if want ~= "v" and want ~= "v]" then return false end
      stack[#stack + 1] = c
      want = c == "{" and "k}" or "v]"
    elseif c == "}" or c == "]" then
      local open = c == "}" and "{" or "["
      if top ~= open or not (want == "," or want == (c == "}" and "k}" or "v]")) then return false end
      stack[#stack] = nil
      want = ","
    elseif c == ":" then
      if want ~= ":" then return false end
      want = "v"
    elseif c == "," then
      if want ~= "," or not top then return false end
      want = top == "{" and "k" or "v"
    else
      if want ~= "v" and want ~= "v]" then return false end
      i = (s:find("[^%w%.%+%-]", i) or #s + 1) - 1
      want = ","
    end
    if #stack == 0 and want == "," then
      -- the value is complete: only white space may follow
      return s:find("^[ \t\n\r]*$", i + 1) ~= nil
    end
    i = i + 1
  end
end
H.well_formed = well_formed

-- Request bodies are decoded the way cjson.safe decodes them in production:
-- JSON null is a non-nil value (cjson.null), so `[null, {...}]` does not end
-- the array at the hole dkjson would otherwise leave; and what cjson refuses
-- and dkjson accepts (anything after the value, nesting past 1000, a lone
-- surrogate escape, a trailing or missing comma) is refused, returning nil.
function H.body_decode(s)
  local v, pos = H.json.decode(s, 1, H.json.null)
  if v == nil or not s:find("^[ \t\n\r]*$", pos) or json_depth(s) > 1000 or lone_surrogate_escape(s)
     or not well_formed(s) then
    return nil
  end
  return v
end

-- PCRE matcher with the same contract the OpenResty adapter gives core:
-- re_find(subject, pattern, init) -> the byte span of the first
-- case-insensitive match at or after byte init (1 when nil), or nil.
do
  local rex = require "rex_pcre2"
  local CASELESS = rex.flags().CASELESS
  local compiled = {}
  function H.re_find(subject, pattern, init)
    local re = compiled[pattern]
    if not re then
      re = rex.new(pattern, CASELESS)
      compiled[pattern] = re
    end
    return re:find(subject, init)   -- from, to (1-based, inclusive) or nil
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
