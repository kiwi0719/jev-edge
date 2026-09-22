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

--- The request's Content-Type as one string. A repeated header arrives as a
-- list (ngx.req.get_headers, APISIX); its values are joined so the content
-- type is watched when any of them is, since the backend may read any one.
function _M.content_type(headers)
  if type(headers) ~= "table" then return "" end
  local ct = headers["content-type"]
  if ct == nil then ct = headers["Content-Type"] end
  if type(ct) == "table" then
    local parts = {}
    for _, v in ipairs(ct) do
      if type(v) == "string" then parts[#parts + 1] = v end
    end
    ct = table.concat(parts, ", ")
  end
  if type(ct) ~= "string" then return "" end
  return ct
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

  -- 2. reputation: one dict lookup, before anything that needs a body, so a
  --    headers-only forward-auth request can still be rejected or trusted
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

  -- 3. method + content type
  if rule.methods and not rule.methods[(req.method or ""):upper()] then
    return _M.PASS, "", "method not watched"
  end
  local ct = _M.content_type(req.headers)
  if not ct_allowed(ct, rule.content_types) then
    return _M.PASS, "", "content-type not watched"
  end

  -- 4. body size: the larger of what the adapter declared and what it handed
  --    over, so a wrong or missing Content-Length cannot shrink the body.
  local size = math.max(tonumber(req.body_size) or 0, req.body and #req.body or 0)
  if size == 0 and req.body == nil then
    return _M.PASS, "", "no body"
  end
  if size < (rule.min_body_bytes or 8) then
    return _M.PASS, "", "body too small"
  end
  if size > (rule.max_body_bytes or 65536) then
    return _M.PASS, "", "body too large"
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

--- Syntax check for a Lua pattern. The runtime only parses a pattern as far
-- as the subject takes it, so `pcall(string.find, "", p)` proves nothing;
-- this walks the pattern the way lstrlib does and reports what it would
-- raise on some subject. Returns nil when the pattern is well formed.
function _M.pattern_error(p)
  local i, n = 1, #p
  -- captures in the order they open; true once closed. A back-reference
  -- (%1..%9) must name a closed one, `)` must close an open one, and none may
  -- be left open, or lstrlib raises when a subject reaches that point.
  local caps = {}
  while i <= n do
    local c = p:sub(i, i)
    if c == "(" then
      if #caps >= 32 then return "too many captures" end
      caps[#caps + 1] = false
      i = i + 1
    elseif c == ")" then
      local open
      for k = #caps, 1, -1 do
        if not caps[k] then open = k break end
      end
      if not open then return "invalid pattern capture" end
      caps[open] = true
      i = i + 1
    elseif c == "%" then
      local d = p:sub(i + 1, i + 1)
      if d == "" then return "malformed pattern (ends with '%')" end
      if d:match("%d") then
        local l = tonumber(d)
        if l == 0 or not caps[l] then return "invalid capture index %" .. d end
        i = i + 2
      elseif d == "b" then
        if i + 3 > n then return "malformed pattern (missing arguments to '%b')" end
        i = i + 4
      elseif d == "f" then
        if p:sub(i + 2, i + 2) ~= "[" then return "missing '[' after '%f' in pattern" end
        i = i + 2
      else
        i = i + 2
      end
    elseif c == "[" then
      local j = i + 1
      if p:sub(j, j) == "^" then j = j + 1 end
      -- the first ']' right after '[' or '[^' is literal
      if p:sub(j, j) == "]" then j = j + 1 end
      local closed = false
      while j <= n do
        local e = p:sub(j, j)
        if e == "%" then
          if j + 1 > n then return "malformed pattern (ends with '%')" end
          j = j + 2
        elseif e == "]" then
          closed = true
          break
        else
          j = j + 1
        end
      end
      if not closed then return "malformed pattern (missing ']')" end
      i = j + 1
    else
      i = i + 1
    end
  end
  for _, closed in ipairs(caps) do
    if not closed then return "unfinished capture" end
  end
  return nil
end

--- Resolve a rule spec into a rule table.
-- A spec is a rule set id (string, loaded through `load`), or a table. A
-- table with `extends = "<id>"` starts from that rule set and overrides the
-- fields it names (lists are replaced, not merged); a table without
-- `extends` is a complete rule. This is how one gateway fronts several
-- assistants: one rule per tenant with its own watch_paths and
-- deployment_context, listed before the general rule (first match wins).
-- @param spec string|table
-- @param load fn(id) -> rule|nil, err
-- @return rule|nil, err
function _M.resolve(spec, load)
  -- A string is the same as `{ extends = "<id>" }`: the loaded module is
  -- copied, never handed back, so callers cannot mutate the shared table,
  -- and the same defaults apply to both forms.
  if type(spec) == "string" then spec = { extends = spec } end
  if type(spec) ~= "table" then return nil, "rule spec must be a string or a table" end
  local base = {}
  if spec.extends then
    local b, err = load(spec.extends)
    if type(b) ~= "table" then return nil, err or ("rule set " .. tostring(spec.extends) .. " not found") end
    base = b
  end
  local out = {}
  for k, v in pairs(base) do out[k] = v end
  for k, v in pairs(spec) do if k ~= "extends" then out[k] = v end end
  if not out.id then return nil, "rule needs an id" end
  if type(out.watch_paths) ~= "table" then return nil, "rule " .. out.id .. " needs watch_paths" end
  -- watch_paths are Lua patterns; a malformed one raises on every request.
  for i, p in ipairs(out.watch_paths) do
    if type(p) ~= "string" then return nil, "rule " .. out.id .. ": watch_paths[" .. i .. "] must be a string" end
    local perr = _M.pattern_error(p)
    if perr then return nil, "rule " .. out.id .. ": watch_paths[" .. i .. "] " .. perr end
  end
  if not out.text_fields then out.text_fields = { "messages[*].content", "prompt", "input", "query", "text" } end
  if not out.templates then out.templates = { "injection" } end
  return out
end

--- Resolve a list of specs; stops at the first error.
function _M.resolve_all(specs, load)
  local out = {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = _M.resolve(spec, load)
    if not rule then return nil, "rules[" .. i .. "]: " .. err end
    out[#out + 1] = rule
  end
  return out
end

--- The rule evaluate_all judged a request with: the first one whose path,
-- method and content type all match. Adapters that rebuild the prompt off the
-- request path (L3, sampling) use it; path alone is not enough, since a
-- tenant rule can match the path and still hand the request to the general
-- rule on method or content type.
function _M.rule_for(req, rules)
  local ct = _M.content_type(req.headers)
  for _, r in ipairs(rules or {}) do
    if path_matches(req.path or "", r.watch_paths)
      and not (r.methods and not r.methods[(req.method or ""):upper()])
      and ct_allowed(ct, r.content_types) then
      return r
    end
  end
  return nil
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
