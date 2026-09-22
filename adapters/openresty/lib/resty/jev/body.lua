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
--   decoded       true when a Content-Encoding was decoded
-- An encoded body that cannot be decoded (unsupported coding, missing
-- library, corrupt data, or too large to decode whole) is left out, and core
-- reports the request unjudgeable.

local rules_m = require "jev.core.rules"
local decode  = require "resty.jev.decode"

local _M = {}

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
  local head = f:read(max)
  local t = math.min(rules_m.TAIL_BYTES, size - max)
  f:seek("set", size - t)
  local tail = f:read(t)
  f:close()
  return nil, head, tail, size
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
      head = data:sub(1, max)
      tail = data:sub(math.max(max + 1, size - rules_m.TAIL_BYTES + 1))
    end
  else
    local file = ngx.req.get_body_file()
    if not file then return req end
    whole, head, tail, size = read_file(file, max)
    if not size then return req end
  end
  req.body_size = math.max(tonumber(req.body_size) or 0, size)

  local ce = rules_m.content_encoding(req.headers)
  if ce ~= "" then
    -- only a body read whole can be decoded: a cut compressed stream is corrupt
    if not whole then return req end
    local out, truncated = decode.decode(whole, ce, max)
    if not out then
      ngx.log(ngx.INFO, "jev-edge: body not decoded (", ce, "): ", truncated)
      return req
    end
    req.decoded = true
    if truncated then
      req.body_head = out:sub(1, max)
      req.body_size = max + 1
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
