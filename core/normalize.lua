-- core/normalize.lua
-- Text extraction from request bodies and normalization for fingerprinting.
-- Pure Lua 5.1 / LuaJIT. No ngx.* usage.

local _M = {}

-- ---------------------------------------------------------------------------
-- Path extraction: "messages[*].content", "prompt", "input.text"
-- A last segment "**" reads every key and string below the value, whatever
-- its shape: tool-call arguments are a string of JSON in OpenAI's APIs (read
-- decoded) and an object in Ollama's and Anthropic's; see deep_value.
-- ---------------------------------------------------------------------------

local function split_path(path)
  local segs = {}
  for seg in path:gmatch("[^%.]+") do
    local name = seg:match("^([^%[]*)%[%*%]$")
    if seg == "**" then
      segs[#segs + 1] = { key = seg, deep = true }
    elseif name then
      segs[#segs + 1] = { key = name, each = true }
    else
      segs[#segs + 1] = { key = seg, each = false }
    end
  end
  return segs
end

--- Why `path` (a text_fields or tool_fields entry) is not one, or nil.
function _M.path_error(path)
  if type(path) ~= "string" or path == "" then return "must be a non-empty string" end
  local segs = split_path(path)
  for i, s in ipairs(segs) do
    if s.deep and i < #segs then return "\"**\" must be the last segment" end
  end
  return nil
end

-- A leaf that is not a string is a "content parts" value: the array form of
-- `messages[*].content` every current chat API accepts
-- (`[{type="text", text="..."}, {type="image_url", ...}]`), the Responses API's
-- `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
-- Collect every string, every part's `text`, and recurse into `content`, to a
-- bounded depth. Two parts keep their text elsewhere: an Anthropic `document`
-- block under `source.data` (source type "text") or `source.content` (type
-- "content"), and a Responses `file_search_call` under `results[*].text`.
-- The depth leaves room for a content document inside a tool_result. Anything
-- else (numbers, images, JSON null) contributes nothing. A decoder that keeps
-- null as a value (cjson.null) is assumed: `[null, {...}]` goes on past the
-- null, as the backend's parser does.
local LEAF_DEPTH = 6
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
  local src = node.source
  if type(src) == "table" then
    if src.type == "text" and type(src.data) == "string" then out[#out + 1] = src.data end
    if src.type == "content" and src.content ~= nil then collect(src.content, out, depth + 1) end
  end
  if node.type == "file_search_call" and type(node.results) == "table" then
    collect(node.results, out, depth + 1)
  end
end

-- Go's encoding/json (Ollama's /api/chat, a default watched path) matches an
-- object key to a field without regard to case, and folds U+017F (long s) to
-- s and U+212A (Kelvin sign) to k: {"MESSAGES": ...} reaches the model. A
-- path key is matched the same way, and every key that folds to it is read,
-- since with several the backend may take any one: the exact key first, the
-- others in byte order.
local function fold(s)
  if not s:find("[A-Z\128-\255]") then return s end
  return (s:lower():gsub("\197\191", "s"):gsub("\226\132\170", "k"))
end
_M.fold = fold

-- A folded key starts with the folded name's first byte, or with that
-- letter's other case, or with the first byte of U+017F / U+212A.
local FIRST = { s = { [0x53] = true, [0x73] = true, [0xC5] = true },
                k = { [0x4B] = true, [0x6B] = true, [0xE2] = true } }

-- The keys of object `node` other than `key` itself that fold to `key`, in
-- byte order; nil when there are none (nearly always).
local function variants(node, key)
  if node[1] ~= nil then return nil end   -- an array
  local want = fold(key)
  local b = want:byte(1)
  local first = FIRST[want:sub(1, 1)]
  local others
  for k in pairs(node) do
    if type(k) == "string" and k ~= key and #k >= #want then
      local c = k:byte(1)
      if (c == b or (first and first[c]) or (c and c >= 0x41 and c <= 0x5A and c + 32 == b))
         and fold(k) == want then
        others = others or {}
        others[#others + 1] = k
      end
    end
  end
  if others then table.sort(others) end
  return others
end

-- ---------------------------------------------------------------------------
-- Bounded walks over JSON of any shape: tool-call arguments ("**") and tool
-- definitions (rule.tool_fields). The client picks the shape, so the walk is
-- bounded: DEEP_NODES object keys and array items per extraction (sorting
-- the keys of one big object is what costs: 150k keys take 45 ms under
-- LuaJIT, 50k about 13), and DEEP_DEPTH levels below the path's value, which
-- is cjson's own nesting limit: JSON either core decodes is never cut by
-- depth, the bound only guards the recursion. Object keys are read in byte
-- order: a Lua table has none, and both cores must produce the same text.
-- Past a bound the rest is left out and `capped` says so. An empty object or
-- array (and a decoder's null, which may be an empty table) adds nothing and
-- is not counted.
-- ---------------------------------------------------------------------------

_M.DEEP_DEPTH = 1000
_M.DEEP_NODES = 50000

-- @param max_bytes cap on the bytes of the strings taken (nil: none)
-- @param decode    json_decode, for "**" values that are a string of JSON
local function new_state(max_bytes, decode)
  return { out = {}, nodes = _M.DEEP_NODES, bytes = 0, max = max_bytes, capped = false, full = false,
           decode = decode }
end

-- The string keys of object `node` in byte order, counted against the node
-- budget; nil once the budget cannot cover them (the walk stops there).
local function keys_of(node, st)
  local keys, n = {}, 0
  for k in pairs(node) do
    if type(k) == "string" then
      n = n + 1
      if n > st.nodes then
        st.nodes, st.capped = 0, true
        return nil
      end
      keys[n] = k
    end
  end
  st.nodes = st.nodes - n
  table.sort(keys)
  return keys
end

-- Counts one array item against the node budget; false once it is spent.
local function count_item(st)
  if st.nodes <= 0 then
    st.capped = true
    return false
  end
  st.nodes = st.nodes - 1
  return true
end

-- Adds `s` (unless empty) to the output; with a byte cap (st.max, over the
-- strings' bytes) the string that crosses it is cut at a character boundary
-- and the walk ends.
local function take(st, s)
  if st.full then return end
  if st.max and st.bytes + #s > st.max then
    s = _M.head(s, st.max - st.bytes)
    st.full, st.capped = true, true
  end
  if s == "" then return end
  st.bytes = st.bytes + #s
  st.out[#st.out + 1] = s
end

--- Every key and string value below `node`, keys in byte order: what a
-- template that renders the value as JSON shows the model.
local function every_string(node, st, depth)
  if type(node) == "string" then return take(st, node) end
  if type(node) ~= "table" or st.full or next(node) == nil then return end
  if depth > _M.DEEP_DEPTH then
    st.capped = true
    return
  end
  if node[1] ~= nil then
    for _, v in ipairs(node) do
      if not count_item(st) then return end
      every_string(v, st, depth + 1)
      if st.full then return end
    end
    return
  end
  local keys = keys_of(node, st)
  if not keys then return end
  for _, k in ipairs(keys) do
    take(st, k)
    every_string(node[k], st, depth + 1)
    if st.full then return end
  end
end

-- Keys of a tool definition or JSON Schema whose values the model reads as
-- text: every key and string below them is taken (an enum's values, an
-- example object). Keys are matched folded, as Go's encoding/json does.
_M.TOOL_TEXT_KEYS = { name = true, description = true, title = true, enum = true, const = true,
                      default = true, examples = true }

-- A tool definition, a JSON Schema, or a list of them: the TOOL_TEXT_KEYS
-- values and the property names under `properties`, at any depth. Other
-- strings (type, format, $ref, a server URL, headers) are left out.
local function tool_walk(node, st, depth)
  if type(node) ~= "table" or st.full or next(node) == nil then return end
  if depth > _M.DEEP_DEPTH then
    st.capped = true
    return
  end
  if node[1] ~= nil then
    for _, v in ipairs(node) do
      if not count_item(st) then return end
      tool_walk(v, st, depth + 1)
      if st.full then return end
    end
    return
  end
  local keys = keys_of(node, st)
  if not keys then return end
  for _, k in ipairs(keys) do
    local v, f = node[k], fold(k)
    if _M.TOOL_TEXT_KEYS[f] then
      every_string(v, st, depth + 1)
    elseif f == "properties" and type(v) == "table" and v[1] == nil then
      -- property names are text too; each value is a schema
      local names = keys_of(v, st)
      if not names then return end
      for _, name in ipairs(names) do
        take(st, name)
        tool_walk(v[name], st, depth + 2)
        if st.full then return end
      end
    else
      tool_walk(v, st, depth + 1)
    end
    if st.full then return end
  end
end

-- The value a tool_fields path ends at: a string whole, anything else walked
-- as tool definitions.
local function tool_leaf(node, st)
  if type(node) == "string" then return take(st, node) end
  tool_walk(node, st, 1)
end

-- The value a "**" path ends at. A string that holds a JSON object or array
-- (OpenAI tool-call arguments) is read decoded, as the chat templates that
-- render arguments read it: its keys and strings, escapes resolved, and no
-- "{}" of an empty call. Anything else, and JSON the decoder refuses, is
-- read as it is.
local function deep_value(node, st)
  if type(node) == "string" and st.decode and node:find("^[ \t\n\r]*[%[{]") then
    local ok, v = pcall(st.decode, _M.lone_surrogates(node))
    if ok and type(v) == "table" then return every_string(v, st, 1) end
  end
  every_string(node, st, 1)
end

local NONE = {}
local walk
local function descend(child, segs, i, st)
  if segs[i].each then
    if type(child) ~= "table" then return end
    for _, v in ipairs(child) do
      walk(v, segs, i + 1, st)
    end
  else
    walk(child, segs, i + 1, st)
  end
end

-- st.out collects the values; st.leaf, when set, reads the value a path
-- ends at (tool_fields), collect() otherwise
walk = function(node, segs, i, st)
  if node == nil or st.full then return end
  if i > #segs then
    if st.leaf then return st.leaf(node, st) end
    collect(node, st.out, 1)
    return
  end
  if segs[i].deep then return deep_value(node, st) end
  local key = segs[i].key
  if key == "" then return descend(node, segs, i, st) end
  if type(node) ~= "table" then return end
  descend(node[key], segs, i, st)
  for _, k in ipairs(variants(node, key) or NONE) do
    descend(node[k], segs, i, st)
  end
end

--- Extract candidate text from a decoded JSON value using the given field paths.
-- @param decoded     table (decoded JSON)
-- @param fields      list of path strings
-- @param json_decode optional: reads a "**" value that is a string of JSON
-- @return string (joined with "\n"), may be ""; the list of strings found;
--         and true when a "**" walk hit a bound and left something out
function _M.extract_json(decoded, fields, json_decode)
  local st = new_state(nil, json_decode)
  for _, f in ipairs(fields or {}) do
    walk(decoded, split_path(f), 1, st)
  end
  return table.concat(st.out, "\n"), st.out, st.capped
end

--- Tool definitions in a decoded JSON body (rule.tool_fields): what the
-- model reads of the tools it may call and of the schema its answer must
-- follow. A path ending at a string takes it; one ending at a table is read
-- with tool_walk. A "**" path reads everything below it.
-- @param decoded     table (decoded JSON)
-- @param fields      list of path strings (text_fields syntax)
-- @param max_bytes   cap on the bytes of the strings taken (nil: none)
-- @param json_decode optional, as for extract_json
-- @return string (joined with "\n"), may be ""; the list of strings; and
--         true when a bound (depth, nodes, bytes) left something out
function _M.extract_tools(decoded, fields, max_bytes, json_decode)
  local st = new_state(max_bytes, json_decode)
  st.leaf = tool_leaf
  if type(decoded) == "table" then
    for _, f in ipairs(fields or {}) do
      walk(decoded, split_path(f), 1, st)
      if st.full then break end
    end
  end
  return table.concat(st.out, "\n"), st.out, st.capped
end

-- Tool results in the chat shapes gateways see:
--   OpenAI Chat Completions  messages[*] with role "tool" (or legacy "function"): content
--   Anthropic Messages       messages[*].content[*] with type "tool_result": content
--   OpenAI Responses         input[*] with a type ending in "_call_output"
--                            (function_call_output, custom_tool_call_output,
--                            local_shell_call_output, ...) or "mcp_call": output;
--                            "file_search_call": results[*].text
local function responses_result(item)
  local t = item.type
  return type(t) == "string" and (t:sub(-12) == "_call_output" or t == "mcp_call")
end

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
      if type(item) == "table" then
        if responses_result(item) then
          collect(item.output, out, 1)
        elseif item.type == "file_search_call" and type(item.results) == "table" then
          collect(item.results, out, 1)
        end
      end
    end
  end
end

--- Retrieved content in a decoded JSON body: tool results (when
-- `spec.tool_results`) and the values of `spec.fields`, in that order.
-- @param decoded table
-- @param spec    { tool_results = bool, fields = { path, ... } }
-- @return string (joined with "\n"), may be ""; and the list of strings found
function _M.extract_untrusted(decoded, spec)
  local st = new_state()
  local out = st.out
  if type(decoded) ~= "table" or type(spec) ~= "table" then return "", out end
  if spec.tool_results ~= false then tool_results(decoded, out) end
  for _, f in ipairs(spec.fields or {}) do
    walk(decoded, split_path(f), 1, st)
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
--         the decoded JSON value when kind is "json", and true when a "**"
--         walk hit a bound and left something out
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
      local text, out, capped = _M.extract_json(decoded, fields, json_decode)
      return text, "json", out, decoded, capped
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

--- The last key of each text-field path, folded (see fold):
-- "messages[*].content" -> "content".
function _M.field_keys(fields)
  local keys = {}
  for _, f in ipairs(fields or {}) do
    -- "arguments.**": the strings under "arguments"
    local last = f:gsub("%.%*%*$", ""):match("([^%.%[%]%*]+)[%[%]%*]*$")
    if last then keys[fold(last)] = true end
  end
  -- content parts carry their text under "text"
  if keys.content then keys.text = true end
  return keys
end

-- True when `key` is ASCII word characters, U+017F and U+212A only: the
-- byte class scan_strings finds keys with also matches other sequences of
-- those bytes (U+0144 is \197\132), which are not keys to either core.
local function key_chars(key)
  if not key:find("[\128-\255]") then return true end
  return key:gsub("\197\191", "s"):gsub("\226\132\170", "k"):find("^[%w_%-]+$") ~= nil
end

--- Collect the string values of `keys` (from field_keys) from possibly
-- truncated JSON. Keys match the way walk() matches them: folded, so every
-- spelling a case-insensitive backend reads is collected.
function _M.scan_strings(s, keys, out)
  local i = 1
  while true do
    -- key bytes: ASCII word characters and the bytes of U+017F and U+212A
    local a, b, key = s:find('"([%w_%-\197\191\226\132\170]+)"%s*:%s*"', i)
    if not a then break end
    if key_chars(key) then
      local value, nexti = read_string(s, b + 1)
      if keys[fold(key)] and value ~= "" then out[#out + 1] = value end
      i = nexti
    else
      i = a + 1   -- not a key: look again from the next byte
    end
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
-- Well-formed text for the judge. cjson keeps a string's bytes as sent, so
-- invalid UTF-8 from the client reaches the provider request, and a strict
-- judge server refuses the call (an L2 error, which passes the request).
-- ---------------------------------------------------------------------------

local FFFD = "\239\191\189"

--- `s` with every ill-formed UTF-8 sequence replaced by U+FFFD, one per
-- maximal subpart: what TextDecoder (the JavaScript core's body decoding),
-- Go and Node make of the same bytes.
function _M.valid_utf8(s)
  local i = s:find("[\128-\255]")
  if not i then return s end
  local out, last = {}, 1
  while i do
    local c = s:byte(i)
    -- bytes the lead byte needs, and the range of the first one after it
    local need, lo, hi = 0, 0x80, 0xBF
    if c >= 0xC2 and c <= 0xDF then need = 1
    elseif c == 0xE0 then need, lo = 2, 0xA0
    elseif c == 0xED then need, hi = 2, 0x9F
    elseif c >= 0xE1 and c <= 0xEF then need = 2
    elseif c == 0xF0 then need, lo = 3, 0x90
    elseif c == 0xF4 then need, hi = 3, 0x8F
    elseif c >= 0xF1 and c <= 0xF3 then need = 3
    end
    local j, bad = i + 1, need == 0
    while need > 0 do
      local d = s:byte(j)
      if not d or d < lo or d > hi then bad = true break end
      need, lo, hi, j = need - 1, 0x80, 0xBF, j + 1
    end
    if bad then
      out[#out + 1] = s:sub(last, i - 1)
      out[#out + 1] = FFFD
      last = j
    end
    i = s:find("[\128-\255]", j)
  end
  if last == 1 then return s end
  out[#out + 1] = s:sub(last)
  return table.concat(out)
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
