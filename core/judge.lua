-- core/judge.lua
-- L2 abstraction. Builds a provider-neutral prompt table from templates and
-- reduces a provider's answers to a single score.

local normalize = require "jev.core.normalize"

local _M = {}

local templates = {}

--- The error a judge returns when it refused a call because the gateway's own
-- concurrency cap (jev.max_inflight) was full. The call never reached the
-- provider, so it says nothing about the provider's health: core does not
-- count it as a breaker failure. Counting it let a burst of concurrent
-- requests trip the breaker and switch L2 off for everyone for open_s.
_M.BUSY = "max_inflight exceeded"

--- Register a template. Ships with core/templates/*.lua.
-- @param name string
-- @param t { instructions = string, criteria = { [true]=..., [false]=... }|nil }
function _M.register(name, t)
  templates[name] = t
end

function _M.get(name)
  return templates[name]
end

--- Build the prompt table sent to a provider.
-- @param names  list of template names
-- @param text   extracted text; invalid UTF-8 in it is sent as U+FFFD
--               (normalize.valid_utf8): a strict judge server refuses the
--               call otherwise, and an L2 error passes the request
-- @param context { path, method } (flat strings)
-- @return { text = ..., context = ..., questions = { [name] = template } }
function _M.build(names, text, context)
  local qs = {}
  local n = 0
  for _, name in ipairs(names or {}) do
    local t = templates[name]
    if t then
      qs[name] = t
      n = n + 1
    end
  end
  if n == 0 then
    return nil, "no templates registered for: " .. table.concat(names or {}, ",")
  end
  return {
    text = type(text) == "string" and normalize.valid_utf8(text) or text,
    context = context or {},
    questions = qs,
  }
end

--- Reduce provider answers to one score.
-- @param answers { [name] = number in [0,1] }
-- @return score number, top template name, count of numeric answers (0 means
--         the provider answered nothing usable: an error, not a safe score)
function _M.reduce(answers)
  local best, best_name, n = 0, "", 0
  for name, p in pairs(answers or {}) do
    p = tonumber(p)
    if p and p == p then
      n = n + 1
      if p > best then best, best_name = p, name end
    end
  end
  if best > 1 then best = 1 end
  return best, best_name, n
end

-- Load bundled templates.
for _, name in ipairs({ "injection", "abuse", "untrusted" }) do
  local ok, t = pcall(require, "jev.core.templates." .. name)
  if ok and type(t) == "table" then _M.register(name, t) end
end

return _M
