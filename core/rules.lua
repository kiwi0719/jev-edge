-- core/rules.lua
-- L1: cheap, short-circuiting rule evaluation.
-- Returns "pass" | "block" | "suspect" plus the extracted text and a reason.

local normalize = require "jev.core.normalize"

local _M = {}

_M.PASS    = "pass"
_M.BLOCK   = "block"
_M.SUSPECT = "suspect"

-- Path patterns are Lua patterns (cheap, anchored, no alternation needed).
local function path_matches(s, patterns)
  for _, p in ipairs(patterns or {}) do
    if s:find(p) then return p end
  end
  return nil
end

-- always_suspect patterns are PCRE, matched through ctx.re_find so the same
-- rule files work under ngx.re (OpenResty), lrexlib (tests) or JS RegExp.
-- Without an injected matcher the prefilter is skipped (fail-open) and the
-- length check alone decides.
local warned = false
local function text_matches(s, patterns, ctx)
  if not patterns or #patterns == 0 then return nil end
  local re_find = ctx and ctx.re_find
  if not re_find then
    if not warned and ctx and ctx.log then
      warned = true
      ctx.log("warn", "jev-edge: ctx.re_find not provided; always_suspect prefilter disabled")
    end
    return nil
  end
  for _, p in ipairs(patterns) do
    local ok, hit = pcall(re_find, s, p)
    if ok and hit then return p end
  end
  return nil
end

local function ct_allowed(ct, allowed)
  if not allowed or #allowed == 0 then return true end
  ct = (ct or ""):lower()
  for _, a in ipairs(allowed) do
    if ct:find(a, 1, true) then return true end
  end
  return false
end

--- Evaluate one rule set against a request.
-- @param req  { method, path, headers, body, body_size, client_ip }
-- @param rule rule table (see rules/*.lua)
-- @param ctx  { cache = {get=fn}, json_decode = fn, clock = fn,
--               re_find = fn(subject, pcre) -> truthy on match (case-insensitive) }
-- @return result, text, reason
function _M.evaluate(req, rule, ctx)
  -- 1. path watch list
  if not path_matches(req.path or "", rule.watch_paths) then
    return _M.PASS, "", "path not watched"
  end

  -- 2. method + content type
  if rule.methods and not rule.methods[(req.method or ""):upper()] then
    return _M.PASS, "", "method not watched"
  end
  local ct = req.headers and (req.headers["content-type"] or req.headers["Content-Type"]) or ""
  if not ct_allowed(ct, rule.content_types) then
    return _M.PASS, "", "content-type not watched"
  end

  -- 3. body size
  local size = tonumber(req.body_size) or (req.body and #req.body) or 0
  if size < (rule.min_body_bytes or 8) then
    return _M.PASS, "", "body too small"
  end
  if size > (rule.max_body_bytes or 65536) then
    return _M.PASS, "", "body too large"
  end

  -- 4. reputation
  if ctx and ctx.cache and req.client_ip then
    local rep = ctx.cache:get("rep:" .. req.client_ip)
    if type(rep) == "table" then
      local now = ctx.clock and ctx.clock() or 0
      if rep.blocked_until and rep.blocked_until > now then
        return _M.BLOCK, "", "ip reputation"
      end
      if rep.trusted_until and rep.trusted_until > now then
        return _M.PASS, "", "ip trusted"
      end
    end
  end

  -- 5+6. extract text, regex prefilter, natural-language length
  local text = normalize.extract(req.body, ct, rule.text_fields, ctx and ctx.json_decode)
  if text == "" then
    return _M.PASS, "", "no text"
  end
  local hit = text_matches(text, rule.always_suspect, ctx)
  if hit then
    return _M.SUSPECT, text, "pattern: " .. hit
  end
  if #text >= (rule.min_text_chars or 20) then
    return _M.SUSPECT, text, "natural language"
  end
  return _M.PASS, "", "text too short"
end

--- Evaluate a list of rules; first non-pass result wins.
function _M.evaluate_all(req, rules, ctx)
  local last_reason = "no rules"
  for _, rule in ipairs(rules or {}) do
    local r, text, reason = _M.evaluate(req, rule, ctx)
    if r ~= _M.PASS then return r, text, reason, rule end
    last_reason = reason
  end
  return _M.PASS, "", last_reason, nil
end

return _M
