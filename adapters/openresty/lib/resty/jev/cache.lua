-- resty/jev/cache.lua
-- ngx.shared.DICT wrapper with the { get, set } contract core expects.
-- Values are tables; they are JSON-encoded because shared dicts hold only
-- scalars. A missing dict degrades to a no-op cache (fail-open).

local cjson = require "cjson.safe"

local _M = {}
_M.__index = _M

function _M.new(dict_name)
  local dict = ngx.shared[dict_name]
  if not dict then
    ngx.log(ngx.WARN, "jev-edge: lua_shared_dict ", dict_name, " not defined; cache disabled")
  end
  return setmetatable({ dict = dict, name = dict_name }, _M)
end

function _M.get(self, key)
  if not self.dict then return nil end
  local raw = self.dict:get(key)
  if raw == nil then return nil end
  if type(raw) ~= "string" then return raw end
  local decoded = cjson.decode(raw)
  if decoded == nil then return raw end
  return decoded
end

function _M.set(self, key, value, ttl)
  if not self.dict then return false end
  if value == nil then
    self.dict:delete(key)
    return true
  end
  local raw = value
  if type(value) == "table" then
    raw = cjson.encode(value)
    if not raw then return false end
  end
  local ok, err = self.dict:set(key, raw, tonumber(ttl) or 0)
  if not ok then
    ngx.log(ngx.WARN, "jev-edge: shared dict ", self.name, " set failed: ", err)
  end
  return ok
end

function _M.incr(self, key, by, ttl)
  if not self.dict then return nil end
  return self.dict:incr(key, by or 1, 0, tonumber(ttl) or 0)
end

return _M
