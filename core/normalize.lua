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
-- bounded depth. Anything else (numbers, images) contributes nothing.
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
-- @return string (joined with "\n"), may be ""
function _M.extract_json(decoded, fields)
  local out = {}
  for _, f in ipairs(fields or {}) do
    walk(decoded, split_path(f), 1, out)
  end
  return table.concat(out, "\n")
end

--- Extract text from a raw body given its content type.
-- @param body         string
-- @param content_type string (may be nil)
-- @param fields       list of JSON paths
-- @param json_decode  function(string) -> table|nil
-- @return text string, kind ("json"|"text"|"form"|"none")
function _M.extract(body, content_type, fields, json_decode)
  if type(body) ~= "string" or body == "" then return "", "none" end
  local ct = (type(content_type) == "string" and content_type or ""):lower()
  if ct:find("application/json", 1, true) or ct:find("+json", 1, true) then
    if not json_decode then return "", "none" end
    -- A UTF-8 BOM is not JSON (cjson rejects it) but Python's json.loads on
    -- bytes and Express's body-parser skip it: judge what the backend reads.
    if body:sub(1, 3) == "\239\187\191" then body = body:sub(4) end
    local ok, decoded = pcall(json_decode, body)
    if not ok or type(decoded) ~= "table" then return "", "none" end
    return _M.extract_json(decoded, fields), "json"
  elseif ct:find("application/x%-www%-form%-urlencoded") then
    local parts = {}
    for _, v in body:gmatch("([^&=]+)=([^&]*)") do
      v = v:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
      parts[#parts + 1] = v
    end
    return table.concat(parts, "\n"), "form"
  elseif ct:find("text/", 1, true) or ct == "" then
    return body, "text"
  end
  return "", "none"
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
-- it still gets a cache entry instead of a judge call per request.
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
