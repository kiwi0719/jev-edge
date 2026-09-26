-- resty/jev/body.lua
-- Request body for core: whole up to max_body_bytes, head and tail past it,
-- decoded when it carries a Content-Encoding. Shared by the OpenResty
-- adapter and the APISIX plugin (both run in the access phase).
--
-- Sets on `req`:
--   body          the whole (decoded) body, when it fits in `max`
--   body_head     past `max`: its first `max` bytes
--   body_tail     past `max`: its last TAIL_BYTES bytes after the head
--   body_size     the size core compares against max_body_bytes
--   body_received the bytes read off the wire, before any decoding
--   decoded       true when a Content-Encoding was decoded
-- An encoded body that cannot be decoded (unsupported coding, missing
-- library, corrupt data, or too large to decode whole) is left out, and core
-- reports the request unjudgeable. One that decodes past `max` gets a head
-- and a tail like a plain one, read on to SCAN_FACTOR x max of decoded
-- output; past that its end was never seen, neither is set and core reports
-- it unjudgeable (body too large).

local rules_m = require "jev.core.rules"
local normalize = require "jev.core.normalize"
local decode  = require "resty.jev.decode"

local _M = {}

-- How far past max_body_bytes a compressed body is decoded looking for its
-- end (the JS runtime reads a plain body as far: runtime.ts SCAN_FACTOR).
local SCAN_FACTOR = 4

local function read_file(path, max)
  local f = io.open(path, "rb")
  if not f then return nil end
  local size = f:seek("end") or 0
  f:seek("set", 0)
  if size <= max then
    local all = f:read(size) or ""
    f:close()
    return all, nil, nil, size
  end
  -- one byte past max tells normalize.head whether max falls inside a character
  local head = f:read(max + 1) or ""
  local t = math.min(rules_m.TAIL_BYTES, size - max)
  f:seek("set", size - t)
  local tail = f:read(t)
  f:close()
  -- a byte cut can land inside a UTF-8 sequence: keep whole characters only,
  -- or the broken bytes reach the L2 prompt (and a provider may refuse it)
  return nil, normalize.head(head, max), tail and (tail:gsub("^[\128-\191]+", "")), size
end

--- Fill `req` from the request body. `max` is the largest max_body_bytes of
-- the rules that watch this path.
function _M.fill(req, max)
  ngx.req.read_body()
  local whole, head, tail, size
  local data = ngx.req.get_body_data()
  if data then
    size = #data
    if size <= max then
      whole = data
    else
      -- whole UTF-8 characters only (see read_file)
      head = normalize.head(data, max)
      tail = normalize.tail(data:sub(#head + 1), rules_m.TAIL_BYTES)
    end
  else
    local file = ngx.req.get_body_file()
    if not file then return req end
    whole, head, tail, size = read_file(file, max)
    if not size then return req end
  end
  req.body_size = math.max(tonumber(req.body_size) or 0, size)
  req.body_received = size

  local ce = rules_m.content_encoding(req.headers)
  if ce ~= "" then
    -- only a body read whole can be decoded: a cut compressed stream is corrupt
    if not whole then return req end
    local out, truncated, info = decode.decode(whole, ce, max,
      { tail = rules_m.TAIL_BYTES, scan = SCAN_FACTOR * max })
    if not out then
      ngx.log(ngx.INFO, "jev-edge: body not decoded (", ce, "): ", truncated)
      return req
    end
    req.decoded = true
    if truncated then
      if info and info.complete then
        -- the newest message sits at the end of the body: scan its head and
        -- its tail, as for a plain body past max (whole characters only)
        req.body_head = normalize.head(out, max)
        local last = info.tail and info.tail:gsub("^[\128-\191]+", "")
        req.body_tail = last ~= "" and last or nil
        req.body_size = info.size
      else
        -- decoded past SCAN_FACTOR x max before the stream ended: the end
        -- was never seen, so there is nothing to judge it on
        req.body_size = math.max(info and info.size or 0, max + 1)
        ngx.log(ngx.INFO, "jev-edge: body not judged (", ce, "): decodes past ", SCAN_FACTOR * max, " bytes")
      end
    else
      req.body = out
      req.body_size = #out
    end
    return req
  end

  if whole then
    req.body = whole
    req.body_size = #whole
  else
    req.body_head, req.body_tail = head, tail
  end
  return req
end

return _M
