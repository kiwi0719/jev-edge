-- core/normalize.lua
-- Text extraction from request bodies and normalization for fingerprinting.
-- Pure Lua 5.1 / LuaJIT. No ngx.* usage.

local _M = {}

-- ---------------------------------------------------------------------------
-- Path extraction: "messages[*].content", "prompt", "input.text"
-- ---------------------------------------------------------------------------

local function split_path(path)
  local segs = {}
  for seg in path:gmatch("[^%.]+") do
    local name = seg:match("^([^%[]*)%[%*%]$")
    if name then
      segs[#segs + 1] = { key = name, each = true }
    else
      segs[#segs + 1] = { key = seg, each = false }
    end
  end
  return segs
end

-- A leaf that is not a string is a "content parts" value: the array form of
-- `messages[*].content` every current chat API accepts
-- (`[{type="text", text="..."}, {type="image_url", ...}]`), the Responses API's
-- `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
-- Collect every string, every part's `text`, and recurse into `content`, to a
-- bounded depth. Anything else (numbers, images, JSON null) contributes
-- nothing. A decoder that keeps null as a value (cjson.null) is assumed:
-- `[null, {...}]` goes on past the null, as the backend's parser does.
local LEAF_DEPTH = 4
local function collect(node, out, depth)
  if type(node) == "string" then
    out[#out + 1] = node
    return
  end
  if type(node) ~= "table" or depth > LEAF_DEPTH then return end
  if node[1] ~= nil then
    for _, item in ipairs(node) do collect(item, out, depth + 1) end
    return
  end
  if type(node.text) == "string" then out[#out + 1] = node.text end
  if node.content ~= nil then collect(node.content, out, depth + 1) end
end

local function walk(node, segs, i, out)
  if node == nil then return end
  if i > #segs then
    collect(node, out, 1)
    return
  end
  local seg = segs[i]
  local child = node
  if seg.key ~= "" then
    if type(node) ~= "table" then return end
    child = node[seg.key]
  end
  if seg.each then
    if type(child) ~= "table" then return end
    for _, item in ipairs(child) do
      walk(item, segs, i + 1, out)
    end
  else
    walk(child, segs, i + 1, out)
  end
end

--- Extract candidate text from a decoded JSON value using the given field paths.
-- @param decoded table (decoded JSON)
-- @param fields  list of path strings
-- @return string (joined with "\n"), may be ""; and the list of strings found
function _M.extract_json(decoded, fields)
  local out = {}
  for _, f in ipairs(fields or {}) do
    walk(decoded, split_path(f), 1, out)
  end
  return table.concat(out, "\n"), out
end

-- Tool results in the chat shapes gateways see:
--   OpenAI Chat Completions  messages[*] with role "tool" (or legacy "function"): content
--   Anthropic Messages       messages[*].content[*] with type "tool_result": content
--   OpenAI Responses         input[*] with type "function_call_output": output
local function tool_results(decoded, out)
  local msgs = decoded.messages
  if type(msgs) == "table" then
    for _, m in ipairs(msgs) do
      if type(m) == "table" then
        if m.role == "tool" or m.role == "function" then
          collect(m.content, out, 1)
        elseif type(m.content) == "table" then
          for _, block in ipairs(m.content) do
            if type(block) == "table" and block.type == "tool_result" then collect(block.content, out, 1) end
          end
        end
      end
    end
  end
  local input = decoded.input
  if type(input) == "table" then
    for _, item in ipairs(input) do
      if type(item) == "table" and item.type == "function_call_output" then collect(item.output, out, 1) end
    end
  end
end

--- Retrieved content in a decoded JSON body: tool results (when
-- `spec.tool_results`) and the values of `spec.fields`, in that order.
-- @param decoded table
-- @param spec    { tool_results = bool, fields = { path, ... } }
-- @return string (joined with "\n"), may be ""; and the list of strings found
function _M.extract_untrusted(decoded, spec)
  local out = {}
  if type(decoded) ~= "table" or type(spec) ~= "table" then return "", out end
  if spec.tool_results ~= false then tool_results(decoded, out) end
  for _, f in ipairs(spec.fields or {}) do
    walk(decoded, split_path(f), 1, out)
  end
  return table.concat(out, "\n"), out
end

-- ---------------------------------------------------------------------------
-- Format detection. The Content-Type a client sends is a hint, not a fact:
-- Ollama decodes JSON whatever the header says, and FastAPI parses a body
-- without one as JSON. So the body decides: JSON when it parses as JSON,
-- form or multipart when declared (or form-shaped with no header), text when
-- it reads as text, and "binary" otherwise, which L1 reports as unjudgeable
-- instead of letting it through as "no text".
-- ---------------------------------------------------------------------------

local BOM = "\239\187\191"

--- True when `s` reads as text: no NUL, and control bytes other than tab,
-- newline and carriage return under 1% of the bytes.
function _M.is_text(s)
  if s:find("%z") then return false end
  local _, ctl = s:gsub("[\1-\8\11\12\14-\31\127]", "")
  return ctl * 100 <= #s
end

-- The value of every `name=value` pair: in each `&`-separated piece, the text
-- after the first `=` that follows a non-empty name (leading `=` are skipped).
-- Plain finds, linear in the body: the pattern this replaces,
-- gmatch("([^&=]+)=([^&]*)"), gives the same values but backtracks from every
-- byte of a long run without `&` or `=`, quadratic in the access phase.
local function form_values(body, out)
  local i, n = 1, #body
  while i <= n do
    local amp = body:find("&", i, true) or n + 1
    local piece = body:sub(i, amp - 1)
    local name = piece:find("[^=]")
    local eq = name and piece:find("=", name, true)
    if eq then
      local v = piece:sub(eq + 1)
      v = v:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
      out[#out + 1] = v
    end
    i = amp + 1
  end
end

-- multipart/form-data: every field without a filename, and file parts whose
-- own Content-Type is text or JSON (a prompt uploaded as prompt.txt). Binary
-- files contribute nothing. At most MAX_PARTS parts are read.
local MAX_PARTS = 100
local function multipart_values(body, content_type, out)
  local boundary = content_type:match('[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy]="([^"]+)"')
    or content_type:match("[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy]=([^;%s,]+)")
  if not boundary then return end
  local delim = "--" .. boundary
  local pos = body:find(delim, 1, true)
  local parts = 0
  while pos and parts < MAX_PARTS do
    local after = pos + #delim
    if body:sub(after, after + 1) == "--" then break end   -- closing delimiter
    local next_pos = body:find(delim, after, true)
    local part = body:sub(after, (next_pos or #body + 1) - 1)
    part = part:gsub("^\r?\n", ""):gsub("\r?\n$", "")
    local hs, he = part:find("\r?\n\r?\n")
    if hs then
      local head, value = part:sub(1, hs - 1):lower(), part:sub(he + 1)
      local has_file = head:find("filename%*?=") ~= nil
      local pct = head:match("content%-type:%s*([^\r\n;]+)") or ""
      if (not has_file or pct:find("^text/") or pct:find("json", 1, true)) and _M.is_text(value) then
        out[#out + 1] = value
      end
    end
    parts = parts + 1
    pos = next_pos
  end
end

--- `s` with every \uD800-\uDFFF escape that is not half of a valid pair
-- written as \uFFFD. cjson refuses a lone surrogate; Python, Node and Go
-- accept it (Go reads U+FFFD), so the rest of the body reaches the model.
function _M.lone_surrogates(s)
  if not s:find("\\u[dD][89a-fA-F]") then return s end
  local out, last, i = {}, 1, 1
  while true do
    local j = s:find("\\", i, true)
    if not j then break end
    i = j + 2   -- any other escape is two bytes
    local cp = s:sub(j + 1, j + 1) == "u" and tonumber(s:match("^%x%x%x%x", j + 2) or "", 16)
    if cp then
      i = j + 6
      if cp >= 0xD800 and cp <= 0xDFFF then
        local lo = cp <= 0xDBFF and tonumber(s:match("^\\u(%x%x%x%x)", i) or "", 16)
        if lo and lo >= 0xDC00 and lo <= 0xDFFF then
          i = i + 6
        else
          out[#out + 1] = s:sub(last, j - 1)
          out[#out + 1] = "\\ufffd"
          last = i
        end
      end
    end
  end
  if last == 1 then return s end
  out[#out + 1] = s:sub(last)
  return table.concat(out)
end

--- Extract text from a raw body.
-- @param body         string
-- @param content_type string (may be nil)
-- @param fields       list of JSON paths
-- @param json_decode  function(string) -> table|nil
-- @return text string (the values joined with "\n"),
--         kind ("json"|"scan"|"invalid"|"form"|"multipart"|"text"|"binary"|"none"),
--         list of the values found (newest last), for window(),
--         and the decoded JSON value when kind is "json"
function _M.extract(body, content_type, fields, json_decode)
  if type(body) ~= "string" or body == "" then return "", "none", {} end
  local raw_ct = type(content_type) == "string" and content_type or ""
  local ct = raw_ct:lower()
  -- A UTF-8 BOM is not JSON (cjson rejects it) but Python's json.loads on
  -- bytes and Express's body-parser skip it: judge what the backend reads.
  if body:sub(1, 3) == BOM then body = body:sub(4) end
  -- declared JSON: a JSON media type (application/json, text/json,
  -- application/*+json), not "json" in a parameter such as a multipart
  -- boundary or "text/plain; profile=json"
  local declared_json = ct:match("^[^;]*"):find("json", 1, true) ~= nil
  local first = body:match("^%s*(.)")
  if first == "{" or first == "[" or declared_json then
    if not json_decode then return "", "none", {} end
    local ok, decoded = pcall(json_decode, _M.lone_surrogates(body))
    if ok and type(decoded) == "table" then
      local text, out = _M.extract_json(decoded, fields)
      return text, "json", out, decoded
    end
    if declared_json then
      -- a JSON scalar has no text fields
      if ok and decoded ~= nil then return "", "none", {} end
      -- The decoder refused it; the backend's parser may not (cjson refuses
      -- nesting past 1000 and bytes after the value, Go and Node do not).
      -- The text fields' string values, read by the tolerant scanner past
      -- max_body_bytes uses, are judged; a body with none is unjudgeable,
      -- never "no text".
      local out = _M.scan_strings(body, _M.field_keys(fields), {})
      if #out == 0 then return "", "invalid", {} end
      return table.concat(out, "\n"), "scan", out
    end
  end
  local out = {}
  if ct:find("application/x-www-form-urlencoded", 1, true)
     or (ct == "" and body:find("^[%w%.%-_~%%%+%[%]]+=[^%s]*$")) then
    form_values(body, out)
    return table.concat(out, "\n"), "form", out
  end
  if ct:find("multipart/form-data", 1, true) then
    multipart_values(body, raw_ct, out)
    return table.concat(out, "\n"), "multipart", out
  end
  if _M.is_text(body) then return body, "text", { body } end
  return "", "binary", {}
end

-- ---------------------------------------------------------------------------
-- Partial bodies. Past max_body_bytes the body is not parsed; the adapter
-- hands over the bytes it has (the head, and the tail where it can seek) and
-- this tolerant scanner pulls the JSON string values of the text-field keys
-- out of them, truncated JSON included.
-- ---------------------------------------------------------------------------

local function utf8_char(cp)
  if cp < 0x80 then return string.char(cp) end
  if cp < 0x800 then return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40) end
  if cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
  return string.char(0xF0 + math.floor(cp / 0x40000), 0x80 + math.floor(cp / 0x1000) % 0x40,
    0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
end

local ESC = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

-- Decode one JSON string body starting at `i` (just after the opening quote);
-- returns the value and the index after the closing quote (or #s + 1).
local function read_string(s, i)
  local buf, n = {}, #s
  while i <= n do
    local j = s:find('["\\]', i)
    if not j then buf[#buf + 1] = s:sub(i); return table.concat(buf), n + 1 end
    buf[#buf + 1] = s:sub(i, j - 1)
    if s:sub(j, j) == '"' then return table.concat(buf), j + 1 end
    local e = s:sub(j + 1, j + 1)
    if e == "u" then
      local hex = s:match("^%x%x%x%x", j + 2)
      if not hex then return table.concat(buf), n + 1 end
      local cp = tonumber(hex, 16)
      i = j + 6
      if cp >= 0xD800 and cp <= 0xDBFF then
        local lo = s:match("^\\u(%x%x%x%x)", i)
        local lcp = lo and tonumber(lo, 16)
        if lcp and lcp >= 0xDC00 and lcp <= 0xDFFF then
          cp = 0x10000 + (cp - 0xD800) * 0x400 + (lcp - 0xDC00)
          i = i + 6
        end
      end
      -- a lone surrogate is U+FFFD, as in lone_surrogates()
      if cp >= 0xD800 and cp <= 0xDFFF then cp = 0xFFFD end
      buf[#buf + 1] = utf8_char(cp)
    elseif e == "" then
      return table.concat(buf), n + 1
    else
      buf[#buf + 1] = ESC[e] or e
      i = j + 2
    end
  end
  return table.concat(buf), n + 1
end

--- The last key of each text-field path: "messages[*].content" -> "content".
function _M.field_keys(fields)
  local keys = {}
  for _, f in ipairs(fields or {}) do
    local last = f:match("([^%.%[%]%*]+)[%[%]%*]*$")
    if last then keys[last] = true end
  end
  -- content parts carry their text under "text"
  if keys.content then keys.text = true end
  return keys
end

--- Collect the string values of `keys` from possibly truncated JSON.
function _M.scan_strings(s, keys, out)
  local i = 1
  while true do
    local a, b, key = s:find('"([%w_%-]+)"%s*:%s*"', i)
    if not a then break end
    local value, nexti = read_string(s, b + 1)
    if keys[key] and value ~= "" then out[#out + 1] = value end
    i = nexti
  end
  return out
end

-- ---------------------------------------------------------------------------
-- Judging window. Text over the budget is cut down before it is fingerprinted
-- and sent to L2: the always_suspect hit (if any) with 1 KiB on each side,
-- then values newest first, the one that does not fit kept as head + tail.
-- Chat APIs resend the whole history every turn; the turns before the newest
-- were judged when they were the newest. Cuts never split a UTF-8 sequence.
-- ---------------------------------------------------------------------------

local function cont(s, i)
  local c = s:byte(i)
  return c ~= nil and c >= 0x80 and c < 0xC0
end

--- `s` cut to at most `n` bytes at a character boundary, from the front.
function _M.head(s, n)
  if n <= 0 then return "" end
  if #s <= n then return s end
  local e = n
  while e > 0 and cont(s, e + 1) do e = e - 1 end
  return s:sub(1, e)
end

--- `s` cut to at most `n` bytes at a character boundary, from the back.
function _M.tail(s, n)
  if n <= 0 then return "" end
  if #s <= n then return s end
  local b = #s - n + 1
  while b <= #s and cont(s, b) do b = b + 1 end
  return s:sub(b)
end

_M.HIT_CONTEXT = 1024

--- Split `text` into consecutive pieces of at most `budget` bytes covering
-- all of it, for judging in chunks (rule.max_judge_chunks). A cut prefers the
-- last newline in the second half of a piece (the newline itself is dropped,
-- it joined two values) and never splits a UTF-8 sequence.
-- @return pieces, and the byte offset in `text` where each piece starts
function _M.chunks(text, budget)
  local pieces, starts = {}, {}
  local i, n = 1, #text
  local half = math.floor(budget / 2)
  while i <= n do
    if n - i + 1 <= budget then
      pieces[#pieces + 1], starts[#starts + 1] = text:sub(i), i
      break
    end
    local e, nexti = i + budget - 1, nil
    for j = e, i + half + 1, -1 do
      if text:byte(j) == 10 then e, nexti = j - 1, j + 1 break end
    end
    if not nexti then
      -- back to a character boundary: at most 3 bytes, the longest run of
      -- continuation bytes in valid UTF-8. A longer run is invalid UTF-8 and
      -- is cut where it is; walking it back byte by byte made a 1-byte piece
      -- per step, O(n x budget) on a body of continuation bytes.
      local cut, k = e, 0
      while k < 3 and e > i and cont(text, e + 1) do e, k = e - 1, k + 1 end
      if e > i and cont(text, e + 1) then e = cut end
      nexti = e + 1
    end
    pieces[#pieces + 1], starts[#starts + 1] = text:sub(i, e), i
    i = nexti
  end
  return pieces, starts
end

--- @param text   the joined values
-- @param values the values, in order (newest last)
-- @param budget max bytes
-- @param from,to byte span of an always_suspect hit in `text`, or nil
-- @return the text to judge, true when it was cut
function _M.window(text, values, budget, from, to)
  if #text <= budget then return text, false end
  local out, rem = {}, budget
  if from and to then
    -- the hit and up to HIT_CONTEXT bytes each side, in at most half the budget
    local half = math.floor(budget / 2)
    local ctxb = math.max(0, math.min(_M.HIT_CONTEXT, math.floor((half - (to - from + 1)) / 2)))
    local a = math.max(1, from - ctxb)
    while a > 1 and cont(text, a) do a = a - 1 end
    local piece = _M.head(text:sub(a), math.min(math.min(to + ctxb, #text) - a + 1, half))
    out[1] = piece
    rem = rem - #piece - 1
  end
  local chosen = {}
  for i = #values, 1, -1 do
    if rem <= 0 then break end
    local v = values[i]
    if #v + 1 <= rem then
      chosen[i] = v
      rem = rem - #v - 1
    else
      local h = _M.head(v, math.floor((rem - 1) / 2))
      chosen[i] = h .. "\n" .. _M.tail(v, rem - 1 - #h - 1)
      rem = 0
    end
  end
  for i = 1, #values do
    if chosen[i] then out[#out + 1] = chosen[i] end
  end
  return table.concat(out, "\n"), true
end

-- ---------------------------------------------------------------------------
-- Normalization
-- ---------------------------------------------------------------------------

local DEFAULTS = {
  prefix_bytes   = 2048,
  strip_digits   = true,   -- remove digit runs >= 4
  strip_uuid     = true,
}

--- Normalize text so that trivially varied payloads share a fingerprint.
-- Steps: lowercase, strip UUIDs / long digit runs, collapse whitespace, truncate.
function _M.normalize(text, opts)
  opts = opts or DEFAULTS
  local s = tostring(text or ""):lower()
  if opts.strip_uuid ~= false then
    s = s:gsub("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x", "")
  end
  if opts.strip_digits ~= false then
    s = s:gsub("%d%d%d%d+", "")
  end
  s = s:gsub("%s+", " ")
  s = s:gsub("^ ", ""):gsub(" $", "")
  local n = opts.prefix_bytes or DEFAULTS.prefix_bytes
  if #s > n then s = s:sub(1, n) end
  return s
end

--- Fingerprint = hash(normalize(text)) over the WHOLE normalized text.
-- `opts.prefix_bytes` is deliberately ignored here: a fingerprint that only
-- covers a prefix lets any text that shares the prefix reuse a cached or
-- trusted verdict (0.3.0 hashed the first 2048 bytes; fixed in 0.3.1).
-- Text that normalizes to nothing (digit runs, UUIDs) is hashed as typed, so
-- it still gets a cache entry instead of a judge call per request; text that
-- is only whitespace is hashed as one space, one entry for every such body.
--
-- `hash` is injected by the adapter and MUST be collision-resistant
-- (sha256 hex or better). The fingerprint keys the verdict cache and the
-- operator trust store, both of which turn a hit into a verdict without a
-- judge call, so an attacker who can forge a hash forges a verdict. CRC32
-- and djb2 are linear and let a few appended bytes hit any chosen value;
-- `djb2` below exists for the golden vectors only.
function _M.fingerprint(text, opts, hash)
  local o = { strip_digits = opts and opts.strip_digits, strip_uuid = opts and opts.strip_uuid,
              prefix_bytes = math.huge }
  local norm = _M.normalize(text, o)
  if norm == "" then
    norm = _M.normalize(text, { strip_digits = false, strip_uuid = false, prefix_bytes = math.huge })
  end
  if norm == "" and text ~= nil and tostring(text) ~= "" then norm = " " end
  if norm == "" then return "" end
  return tostring(hash(norm))
end

--- Reference hash for tests and non-OpenResty adapters (djb2, hex).
function _M.djb2(s)
  local h = 5381
  for i = 1, #s do
    h = (h * 33 + s:byte(i)) % 4294967296
  end
  return string.format("%08x", h)
end

return _M
