-- core/rules.lua
-- L1: cheap, short-circuiting rule evaluation.
-- Returns "pass" | "block" | "suspect" plus the extracted text and a reason.

local normalize = require "jev.core.normalize"
local subject   = require "jev.core.subject"
local defaults  = require "jev.core.defaults"

local _M = {}

_M.PASS    = "pass"
_M.BLOCK   = "block"
_M.SUSPECT = "suspect"
-- A watched request L1 cannot read: compressed with an encoding the adapter
-- could not decode, binary, declared JSON the decoder refused with no text in
-- it, over max_body_bytes with no text in the part the adapter could hand
-- over, cut by the gateway in front when policy.partial = "unjudgeable", or a
-- prompt sent as token ids (TOKENS). policy.unjudgeable decides what happens,
-- and for token ids the rule's token_prompts too.
_M.UNJUDGEABLE = "unjudgeable"

-- A text field holds token ids (normalize.collect): the OpenAI completions
-- API, vLLM, SGLang (input_ids) and llama.cpp take a prompt as a list of ids
-- or of lists of them, llama.cpp ids and strings mixed, and the model reads
-- the text they stand for, which L1 cannot. Ids with no text to judge beside
-- them are unjudgeable; beside text, the text is judged and the ids still
-- make the request unjudgeable (core/init.lua: the stricter of the two).
_M.TOKENS = "unjudgeable: token prompt"

_M.MAX_BODY_BYTES  = 1048576   -- parsed whole up to here (nginx's default client_max_body_size)
_M.MAX_JUDGE_BYTES = 32768     -- text fingerprinted and sent to L2 (see normalize.window)
_M.TAIL_BYTES      = 65536     -- tail of an oversized body scanned alongside its head

-- Content types that are never a prompt. Everything else is read and its
-- format decided by the body (normalize.extract); a rule that lists
-- `content_types` instead keeps the old allow-list behaviour.
_M.SKIP_CONTENT_TYPES = {
  "image/", "audio/", "video/", "font/", "application/pdf", "application/zip", "application/gzip",
}

-- Path patterns are Lua patterns (cheap, anchored, no alternation needed),
-- matched against the path the backend routes on, not the one the gateway
-- reports. Every segment loses its `;` parameters (Tomcat, Jetty and Spring
-- route /v1;a=b/chat/completions as /v1/chat/completions), then empty and
-- `.` segments go and `..` is resolved, as the backend does once they are
-- gone (/v1/x/..;/chat). Unless the rule sets paths_case_sensitive = true,
-- ASCII letters are folded in the path and in the patterns alike: Express,
-- Koa, ASP.NET Core and Fiber route /V1/Chat/Completions to the
-- /v1/chat/completions handler. A letter after `%` names a class (%S, %W)
-- and keeps its case.
local LOWER = {}
for c = 65, 90 do LOWER[string.char(c)] = string.char(c + 32) end

local function canonical_path(path, case_sensitive)
  local p = path:gsub(";[^/]*", "")
  if p:find("//", 1, true) or p:find("/.", 1, true) then
    local out = {}
    for seg in p:gmatch("[^/]+") do
      if seg == ".." then
        out[#out] = nil
      elseif seg ~= "." then
        out[#out + 1] = seg
      end
    end
    local q = "/" .. table.concat(out, "/")
    if p:sub(-1) == "/" and q ~= "/" then q = q .. "/" end
    p = q
  end
  if case_sensitive then return p end
  return (p:gsub("[A-Z]", LOWER))
end

local folded = {}
local function fold_pattern(p)
  local f = folded[p]
  if not f then
    f = p:gsub("%%?.", function(t) if #t == 1 then return LOWER[t] end end)
    folded[p] = f
  end
  return f
end

--- The first of `patterns` (a rule's watch_paths) that matches `path`, or
-- nil. Every place that decides whether a rule watches a path uses this one,
-- core and adapters alike, so reading the body and judging it agree.
-- @param case_sensitive the rule's paths_case_sensitive
function _M.path_matches(path, patterns, case_sensitive)
  if not patterns or #patterns == 0 then return nil end
  local cs = case_sensitive == true
  local s = canonical_path(path or "", cs)
  for _, p in ipairs(patterns) do
    if s:find(cs and p or fold_pattern(p)) then return p end
  end
  return nil
end
local path_matches = _M.path_matches

-- always_suspect patterns are PCRE, matched through ctx.re_find so the same
-- rule files work under ngx.re (OpenResty), lrexlib (tests) or JS RegExp.
-- re_find returns the 1-based inclusive byte span of the match (from, to), or
-- just a truthy value; the span places the hit inside the judging window.
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
    local ok, from, to = pcall(re_find, s, p)
    if ok and from then
      if type(from) == "number" and type(to) == "number" then return p, from, to end
      return p
    end
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

--- The request's Content-Encoding codings, lowercased, without "identity";
-- "" when the body is not encoded.
function _M.content_encoding(headers)
  if type(headers) ~= "table" then return "" end
  local ce = headers["content-encoding"]
  if ce == nil then ce = headers["Content-Encoding"] end
  if type(ce) == "table" then ce = table.concat(ce, ",") end
  if type(ce) ~= "string" then return "" end
  local out = {}
  for tok in ce:lower():gmatch("[^,%s]+") do
    if tok ~= "identity" then out[#out + 1] = tok end
  end
  return table.concat(out, ", ")
end

-- true when the rule reads this content type; false when its allow list
-- (content_types) leaves it out; "media" when every value of the header is a
-- skip_content_types entry. The client picks the header and Ollama and
-- llama.cpp parse JSON whatever it says, so the body is still read and only
-- one that really is binary is skipped (judged()).
local function ct_watched(ct, rule)
  ct = (ct or ""):lower()
  local allowed = rule.content_types
  if allowed and #allowed > 0 then
    for _, a in ipairs(allowed) do
      if ct:find(a, 1, true) then return true end
    end
    return false
  end
  -- deny list: watched unless every value of the header is a skipped type
  local skip = rule.skip_content_types or _M.SKIP_CONTENT_TYPES
  local any = false
  for raw in ct:gmatch("[^,]+") do
    local v = raw:match("^%s*(.-)%s*$")
    if v ~= "" then
      any = true
      local skipped = false
      for _, sk in ipairs(skip) do
        if v:find(sk, 1, true) == 1 then skipped = true break end
      end
      if not skipped then return true end
    end
  end
  return not any or "media"
end

local CT_NOT_WATCHED = "content-type not watched"

-- A path in the rule's json_only_paths is watched only for a JSON body: one
-- normalize.extract() reads as JSON ("json"), or declared JSON the decoder
-- refused whose text fields the scanner found ("scan"). TGI serves
-- generation at the site root, where a site's own POST (a login form, an
-- upload, text that starts with {) must not reach the judge, or the IP and
-- subject reputation checks. A body extract() cannot read is decided on what
-- there is: past max_body_bytes, still encoded, empty, or with no
-- ctx.json_decode, its first byte or JSON media type (normalize.json_like on
-- the head the adapter kept); with no body at all, the Content-Type alone.
-- @return true when the rule does not watch the request; and extract()'s
--         results in a list when it ran, for judged() to reuse
local NOT_JSON = "path not watched: body not JSON"
local function json_only_miss(req, rule, ct, ctx)
  local jo = rule.json_only_paths
  if type(jo) ~= "table" or #jo == 0 or not path_matches(req.path, jo, rule.paths_case_sensitive) then
    return false
  end
  local body, decode = req.body, ctx and ctx.json_decode
  if type(body) ~= "string" or body == "" or not decode
     or math.max(tonumber(req.body_size) or 0, #body) > (rule.max_body_bytes or _M.MAX_BODY_BYTES)
     or (_M.content_encoding(req.headers) ~= "" and not req.decoded) then
    return not normalize.json_like(req.body_head or body, ct)
  end
  local ex = { normalize.extract(body, ct, rule.text_fields, decode) }
  return ex[2] ~= "json" and ex[2] ~= "scan", ex
end

local function untrusted_on(rule, ctx)
  return defaults.untrusted_spec(ctx and ctx.config, rule).enabled == true
end

-- Retrieved content (tool results, untrusted.fields) when untrusted judging is
-- on for `rule`, cut to its own judging window. Only from a body parsed whole:
-- past max_body_bytes there is no JSON structure to find it in.
-- @return { text, windowed } or nil; true when a walk bound left some of it
--         unread (the part, if any, is then a window); and the values read,
--         whole, when untrusted judging is on and the body was parsed
local function untrusted_part(decoded, rule, ctx)
  local spec = defaults.untrusted_spec(ctx and ctx.config, rule)
  if not spec.enabled or type(decoded) ~= "table" then return nil end
  local utext, uvalues, capped = normalize.extract_untrusted(decoded, spec, ctx and ctx.json_decode)
  if utext == "" then return nil, capped, uvalues end
  local windowed
  utext, windowed = normalize.window(utext, uvalues, rule.max_judge_bytes or _M.MAX_JUDGE_BYTES)
  return { text = utext, windowed = (windowed or capped) and true or false }, capped, uvalues
end

-- With untrusted judging on, true when the text's values (`values`) hold
-- retrieved content: one of `uvalues` (tool results and untrusted.fields
-- values read whole), or some of it went unread (`ucut`) and may be there.
-- The text's score is then not the subject's own, and reputation charges
-- none of it (core/init.lua rep_of), window and chunks included.
local function holds_retrieved(values, uvalues, ucut)
  if ucut then return true end
  local seen, any = {}, false
  for _, v in ipairs(uvalues) do
    if v ~= "" then seen[v], any = true, true end
  end
  if not any then return false end
  for _, v in ipairs(values) do
    if seen[v] then return true end
  end
  return false
end

-- The tool definitions the model reads (rule.tool_fields), judged as their
-- own part: all of them scanned by always_suspect, cut to their own judging
-- window, so they never take the room of the messages. From a body parsed
-- whole they are walked (normalize.extract_tools); past max_body_bytes, and
-- in JSON the decoder refused (normalize.extract's kind "scan"), the bytes
-- are scanned for them (normalize.scan_tools) and the part is a window.
-- @param values the strings read, in order
-- @param cut    true when a bound, or the body's size, left some out
-- @return { text, windowed, hit } or nil
local function tools_part(values, cut, rule, ctx)
  local ttext = table.concat(values, "\n")
  if ttext == "" then return nil end
  local hit, from, to = text_matches(ttext, rule.always_suspect, ctx)
  local windowed
  ttext, windowed = normalize.window(ttext, values, rule.max_judge_bytes or _M.MAX_JUDGE_BYTES, from, to)
  return { text = ttext, windowed = (windowed or cut) and true or false, hit = hit }
end

local function has_tool_fields(rule)
  return type(rule.tool_fields) == "table" and #rule.tool_fields > 0
end

-- Text to judge from the body (or, past max_body_bytes, from the head and
-- tail the adapter handed over), cut to the judging window. `ex`: the body's
-- extract() results json_only_miss already has, or nil.
-- @return text, reason-or-nil, hit pattern, windowed, chunks (list, when
--         judged in more than one piece), capped (chunks did not cover it all),
--         untrusted ({ text, windowed } when untrusted judging is on and the
--         body carries retrieved content), tools (tools_part), bound
--         (true when a walk bound left text fields, retrieved content or
--         tool definitions unread), retrieved (untrusted judging is on
--         and the text holds retrieved content: holds_retrieved, or the body
--         was scanned, not walked, and nothing tells the two apart), and
--         tokens (a text field holds token ids: TOKENS)
local function judged(req, rule, ctx, ct, size, ex)
  local max = rule.max_body_bytes or _M.MAX_BODY_BYTES
  -- a media type is taken at its word only when the bytes agree (or there
  -- are none to look at): anything that reads as JSON or text is judged
  local media = ct_watched(ct, rule) == "media"
  local values, text
  local partial, bound, retrieved = false, false, false
  local untrusted, tools, tokens
  -- the gateway in front forwarded only the first part of the body: what the
  -- adapter has is a head, whatever its size, never a whole document
  local gateway_cut = req.body_partial == true
  if gateway_cut and size <= max then size = max + 1 end
  if size > max then
    local head, tail = req.body_head, req.body_tail
    if not head and req.body then
      -- a whole body handed over (tests, small adapters): its head, and its
      -- tail when there is anything past the head
      head = normalize.head(req.body, max)
      if #req.body > #head then
        tail = normalize.tail(req.body:sub(#head + 1), _M.TAIL_BYTES)
      end
    end
    if media and not (head and normalize.is_text(head)) then return nil, CT_NOT_WATCHED end
    if not head then return nil, "unjudgeable: body too large" end
    -- policy.partial = "unjudgeable": the part the gateway cut off counts as
    -- unread, and policy.unjudgeable decides
    local pol = ctx and ctx.config and ctx.config.policy
    if gateway_cut and pol and pol.partial == "unjudgeable" then return nil, "unjudgeable: partial body" end
    local keys, deep = normalize.field_keys(rule.text_fields), normalize.deep_keys(rule.text_fields)
    local found = {}
    values = normalize.scan_strings(head, keys, {}, deep, found)
    if tail then normalize.scan_strings(tail, keys, values, deep, found) end
    tokens = found.tokens == true
    if #values == 0 and not tokens then return nil, "unjudgeable: body too large" end
    text, partial = table.concat(values, "\n"), true
    retrieved = untrusted_on(rule, ctx)
    if has_tool_fields(rule) then
      local tkeys = normalize.field_keys(rule.tool_fields)
      local tvalues = normalize.scan_tools(head, tkeys, {})
      if tail then normalize.scan_tools(tail, tkeys, tvalues) end
      tools = tools_part(tvalues, true, rule, ctx)
    end
  else
    local kind, decoded, cut, ids
    if ex then
      text, kind, values, decoded, cut, ids = ex[1], ex[2], ex[3], ex[4], ex[5], ex[6]
    else
      text, kind, values, decoded, cut, ids = normalize.extract(req.body, ct, rule.text_fields,
        ctx and ctx.json_decode)
    end
    tokens = ids == true
    if media and (kind == "binary" or kind == "none") then return nil, CT_NOT_WATCHED end
    if kind == "binary" then return nil, "unjudgeable: binary body" end
    -- declared JSON the decoder refused, with no text-field value to scan
    if kind == "invalid" then return nil, "unjudgeable: invalid json" end
    -- a "**" field hit its bound: the text is not all there
    if cut then partial, bound = true, true end
    local ucut, uvalues
    untrusted, ucut, uvalues = untrusted_part(decoded, rule, ctx)
    if ucut then bound = true end
    if uvalues then
      retrieved = holds_retrieved(values, uvalues, ucut)
    elseif kind == "scan" then
      retrieved = untrusted_on(rule, ctx)
    end
    if has_tool_fields(rule) and type(decoded) == "table" then
      local _, tvalues, tcut = normalize.extract_tools(decoded, rule.tool_fields, ctx and ctx.json_decode)
      tools = tools_part(tvalues, tcut, rule, ctx)
      if tcut then bound = true end
    elseif has_tool_fields(rule) and kind == "scan" then
      -- JSON the decoder refused (nesting past 1000, bytes after the
      -- value), declared or not, which the backend's parser may take:
      -- scanned for the tool definitions as past max_body_bytes
      tools = tools_part(normalize.scan_tools(req.body, normalize.field_keys(rule.tool_fields), {}), true, rule, ctx)
    end
  end
  if text == "" then return "", nil, nil, nil, nil, nil, untrusted, tools, bound, false, tokens end
  local hit, from, to = text_matches(text, rule.always_suspect, ctx)
  local budget = rule.max_judge_bytes or _M.MAX_JUDGE_BYTES
  local maxc = math.floor(tonumber(rule.max_judge_chunks) or 1)
  if maxc > 1 and #text > budget then
    -- judged in chunks: all of the text when it fits in max_judge_chunks
    -- pieces; otherwise the newest max_judge_chunks - 1 pieces whole and a
    -- window over everything older (capped: some of the text is not judged)
    local pieces, starts = normalize.chunks(text, budget)
    if #pieces <= maxc then
      return table.concat(pieces, "\n"), nil, hit, partial, pieces, false, untrusted, tools, bound, retrieved, tokens
    end
    local first_kept = #pieces - (maxc - 1) + 1
    local older = text:sub(1, starts[first_kept] - 1):gsub("\n$", "")
    local inside = from and to and to <= #older
    local win = normalize.window(older, { older }, budget, inside and from or nil, inside and to or nil)
    local out = { win }
    for k = first_kept, #pieces do out[#out + 1] = pieces[k] end
    return table.concat(out, "\n"), nil, hit, true, out, true, untrusted, tools, bound, retrieved, tokens
  end
  local windowed
  text, windowed = normalize.window(text, values, budget, from, to)
  return text, nil, hit, windowed or partial, nil, nil, untrusted, tools, bound, retrieved, tokens
end

-- A request the walk bounds cut and that would otherwise pass unjudged for
-- lack of text: what was left unread may be what the model reads.
local BOUND_REASON = "unjudgeable: json over the walk bounds"

--- Evaluate one rule set against a request.
-- @param req  { method, path, headers, body, body_size, client_ip }, and
--             where the adapter has them decoded, body_head, body_tail and
--             body_partial (the gateway forwarded only the body's first part)
-- @param rule rule table (see rules/*.lua)
-- @param ctx  { cache = {get=fn}, json_decode = fn, clock = fn,
--               re_find = fn(subject, pcre) -> truthy on match (case-insensitive) }
-- @return result, text, reason, windowed, chunks, capped, untrusted ({ text,
--         windowed } of retrieved content to judge on its own, or nil), tools
--         ({ text, windowed, hit } of the tool definitions, or nil). `only`
--         on either: the text alone would have passed and is not judged.
--         Then retrieved: true when untrusted judging is on and the text
--         holds retrieved content, so its score is not the subject's own;
--         and tokens: true when a text field holds token ids (TOKENS), with
--         result UNJUDGEABLE when there is nothing else to judge and SUSPECT
--         beside text that is judged.
function _M.evaluate(req, rule, ctx)
  -- 1. path watch list; a json_only_paths path only for a JSON body (what
  --    extract() reads it as, or the Content-Type when there is no body)
  if not path_matches(req.path, rule.watch_paths, rule.paths_case_sensitive) then
    return _M.PASS, "", "path not watched"
  end
  local ct = _M.content_type(req.headers)
  local miss, ex = json_only_miss(req, rule, ct, ctx)
  if miss then
    return _M.PASS, "", NOT_JSON
  end

  -- 2. reputation: one dict lookup, before anything that needs a body, so a
  --    headers-only forward-auth request can still be rejected. Reputation
  --    only ever blocks: a run of safe verdicts earns an IP nothing, or an
  --    attacker could warm one up with harmless requests and skip L2 after.
  if ctx and ctx.cache and req.client_ip then
    local rep = ctx.cache:get("rep:" .. req.client_ip)
    if type(rep) == "table" then
      local now = ctx.clock and ctx.clock() or 0
      if rep.blocked_until and rep.blocked_until > now then
        return _M.BLOCK, "", "ip reputation"
      end
    end
  end
  -- the same for the subject (core/subject.lua), when reputation is on
  if ctx and ctx.subject and subject.rep_blocked(ctx) then
    return _M.BLOCK, "", "subject reputation"
  end

  -- 3. method + content type (an allow list when the rule lists
  --    content_types; the deny list of media types is only settled once the
  --    body shows it is binary, in step 6)
  if rule.methods and not rule.methods[(req.method or ""):upper()] then
    return _M.PASS, "", "method not watched"
  end
  if not ct_watched(ct, rule) then
    return _M.PASS, "", CT_NOT_WATCHED
  end

  -- 4. body size: the larger of what the adapter declared and what it handed
  --    over, so a wrong or missing Content-Length cannot shrink the body.
  local size = math.max(tonumber(req.body_size) or 0, req.body and #req.body or 0)
  if size == 0 and req.body == nil and req.body_head == nil then
    return _M.PASS, "", "no body"
  end
  if size < (rule.min_body_bytes or 8) then
    return _M.PASS, "", "body too small"
  end

  -- 5. an encoded body is only readable once the adapter decoded it
  local ce = _M.content_encoding(req.headers)
  if ce ~= "" and not req.decoded then
    return _M.UNJUDGEABLE, "", "unjudgeable: content-encoding " .. ce
  end

  -- 6+7. extract text (whole body, or head + tail past max_body_bytes), regex
  --      prefilter over all of it, judging window, natural-language length
  local text, unj, hit, windowed, chunks, capped, untrusted, tools, bound, retrieved, tokens =
    judged(req, rule, ctx, ct, size, ex)
  if unj == CT_NOT_WATCHED then return _M.PASS, "", unj end
  if unj then return _M.UNJUDGEABLE, "", unj end
  local min_chars = rule.min_text_chars or 20
  -- retrieved content is judged on its own when there is enough of it, even
  -- beside a short message or none (an untrusted.fields value outside text_fields)
  if untrusted and #untrusted.text < min_chars then untrusted = nil end
  -- so are the tool definitions, and short ones an always_suspect pattern hit
  if tools and not tools.hit and #tools.text < min_chars then tools = nil end
  if text == "" and not untrusted and not tools then
    if tokens then return _M.UNJUDGEABLE, "", _M.TOKENS, nil, nil, nil, nil, nil, nil, true end
    if bound then return _M.UNJUDGEABLE, "", BOUND_REASON end
    return _M.PASS, "", "no text"
  end
  local judged_too = hit or #text >= min_chars
  if not judged_too then
    if not (untrusted or tools) then
      -- the strings beside token ids are pieces of the prompt, not all of it
      if tokens then return _M.UNJUDGEABLE, "", _M.TOKENS, nil, nil, nil, nil, nil, nil, true end
      if bound then return _M.UNJUDGEABLE, "", BOUND_REASON end
      return _M.PASS, "", "text too short"
    end
    -- the text alone would have passed: only the retrieved content and the
    -- tool definitions are judged
    if untrusted then untrusted.only = true end
    if tools then tools.only = true end
  end
  -- a walk bound cut what is judged: the reason says so, as for any window
  if bound then windowed = true end
  local tag = windowed and " (window)" or ""
  if chunks and not capped then tag = " (" .. #chunks .. " chunks" .. (windowed and ", window" or "") .. ")" end
  local why
  if hit then
    why = "pattern: " .. hit .. tag
  elseif tools and tools.hit then
    why = "pattern: " .. tools.hit .. " (tools" .. (tools.windowed and ", window" or "") .. ")"
  elseif judged_too then
    why = "natural language" .. tag
  elseif untrusted then
    why = "retrieved content" .. (untrusted.windowed and " (window)" or "")
  else
    why = "tool definitions" .. (tools.windowed and " (window)" or "")
  end
  return _M.SUSPECT, text, why, windowed, chunks, capped, untrusted, tools, retrieved, tokens or nil
end

--- The text evaluate() judges for this request under `rule`, in one window:
-- the same extraction, for an adapter that wants the request's text off the
-- request path. "" when there is none. Only the text: a request judged in
-- parts (chunks, retrieved content, tool definitions) is more than this, and
-- L3 judges all of them (core.l3_job).
function _M.judged_text(req, rule, ctx)
  if not rule or not req then return "" end
  local size = math.max(tonumber(req.body_size) or 0, req.body and #req.body or 0)
  local ct = _M.content_type(req.headers)
  local miss, ex = json_only_miss(req, rule, ct, ctx)
  if miss then return "" end
  -- one window, never chunks
  local one = setmetatable({ max_judge_chunks = 1 }, { __index = rule })
  local text = judged(req, one, ctx, ct, size, ex)
  return text or ""
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
  if out.json_only_paths ~= nil and type(out.json_only_paths) ~= "table" then
    return nil, "rule " .. out.id .. ": json_only_paths must be a list of patterns"
  end
  -- watch_paths and json_only_paths are Lua patterns; a malformed one raises
  -- on every request.
  for _, k in ipairs({ "watch_paths", "json_only_paths" }) do
    for i, p in ipairs(out[k] or {}) do
      if type(p) ~= "string" then return nil, "rule " .. out.id .. ": " .. k .. "[" .. i .. "] must be a string" end
      local perr = _M.pattern_error(p)
      if perr then return nil, "rule " .. out.id .. ": " .. k .. "[" .. i .. "] " .. perr end
    end
  end
  local uok, uerr = defaults.validate_untrusted(out.untrusted, "rule " .. out.id .. ": untrusted")
  if not uok then return nil, uerr end
  -- a prompt sent as token ids (TOKENS): "unjudgeable" leaves it to
  -- policy.unjudgeable, "block" refuses it in enforce mode whatever that says
  if out.token_prompts == nil then out.token_prompts = "unjudgeable" end
  if out.token_prompts ~= "unjudgeable" and out.token_prompts ~= "block" then
    return nil, "rule " .. out.id .. ": token_prompts must be unjudgeable|block"
  end
  if not out.text_fields then
    out.text_fields = { "system", "instructions", "preamble", "system_prompt", "systemInstruction.parts",
                        "system_instruction.parts", "documents", "template",
                        "messages[*].content", "messages[*].tool_calls[*].function.arguments.**",
                        "messages[*].tool_calls[*].custom.input", "messages[*].function_call.arguments.**",
                        "messages[*].content[*].input.**", "messages[*].parts",
                        "messages[*].parts[*].input.**", "messages[*].parts[*].output.**",
                        "contents[*].parts", "contents.parts", "chat_history[*].message", "message",
                        "prompt", "prompt.prompt_string", "prompt[*].prompt_string", "prompt.variables.**",
                        "input", "input[*].arguments.**", "input[*].input", "input[*].output",
                        "inputs", "instances[*].inputs", "instances[*].messages[*].content",
                        "query", "text", "input_ids", "suffix", "input_prefix", "input_suffix", "input_extra[*].text" }
  end
  if not out.tool_fields then
    out.tool_fields = { "tools", "functions", "response_format.json_schema", "text.format" }
  end
  for _, k in ipairs({ "text_fields", "tool_fields" }) do
    if type(out[k]) ~= "table" then return nil, "rule " .. out.id .. ": " .. k .. " must be a list of paths" end
    for i, p in ipairs(out[k]) do
      local perr = normalize.path_error(p)
      if perr then return nil, "rule " .. out.id .. ": " .. k .. "[" .. i .. "] " .. perr end
    end
  end
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

--- The rule evaluate_all judged a request with: the first one whose path
-- (json_only_paths included), method and content type all match. Adapters
-- that rebuild the prompt off the request path (L3, sampling) use it; path
-- alone is not enough, since a tenant rule can match the path and still hand
-- the request to the general rule on method or content type.
-- @param ctx { json_decode = fn }, as evaluate_all had it: a json_only_paths
--        path is decided on what the decoder makes of the body
function _M.rule_for(req, rules, ctx)
  local ct = _M.content_type(req.headers)
  for _, r in ipairs(rules or {}) do
    if path_matches(req.path, r.watch_paths, r.paths_case_sensitive)
      and not json_only_miss(req, r, ct, ctx)
      and not (r.methods and not r.methods[(req.method or ""):upper()])
      and ct_watched(ct, r) then
      return r
    end
  end
  return nil
end

--- Evaluate a list of rules; first non-pass result wins.
function _M.evaluate_all(req, rules, ctx)
  local last_reason = "no rules"
  for _, rule in ipairs(rules or {}) do
    local r, text, reason, windowed, chunks, capped, untrusted, tools, retrieved, tokens = _M.evaluate(req, rule, ctx)
    if r ~= _M.PASS then return r, text, reason, rule, windowed, chunks, capped, untrusted, tools, retrieved, tokens end
    last_reason = reason
  end
  return _M.PASS, "", last_reason, nil
end

return _M
