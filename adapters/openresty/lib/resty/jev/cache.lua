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
  local ok, err, forcible = self.dict:set(key, raw, tonumber(ttl) or 0)
  if not ok then
    ngx.log(ngx.WARN, "jev-edge: shared dict ", self.name, " set failed: ", err)
  elseif forcible and not self.warned_full then
    -- LRU eviction has started: valid entries are being dropped to make room.
    -- Said once per worker; the fix is a bigger dict or a separate jev_state.
    self.warned_full = true
    ngx.log(ngx.WARN, "jev-edge: shared dict ", self.name, " is full, evicting entries; raise its size")
  end
  return ok
end

function _M.incr(self, key, by, ttl)
  if not self.dict then return nil end
  return self.dict:incr(key, by or 1, 0, tonumber(ttl) or 0)
end

--- Atomic set-if-absent: true only for the caller that created the key.
function _M.add(self, key, value, ttl)
  if not self.dict then return false end
  if type(value) == "table" then value = cjson.encode(value) end
  local ok = self.dict:add(key, value, tonumber(ttl) or 0)
  return ok and true or false
end

--- Reset a key's ttl (incr only sets one when it creates the key).
function _M.expire(self, key, ttl)
  if not self.dict or not self.dict.expire then return false end
  return self.dict:expire(key, tonumber(ttl) or 0)
end

--- The same store with every key under `prefix`: one dict holding
-- independent breaker / adaptive / in-flight state for several runtimes.
function _M.prefixed(self, prefix)
  local base = self
  local p = tostring(prefix)
  return {
    get    = function(_, k) return base:get(p .. k) end,
    set    = function(_, k, v, ttl) return base:set(p .. k, v, ttl) end,
    incr   = function(_, k, by, ttl) return base:incr(p .. k, by, ttl) end,
    add    = function(_, k, v, ttl) return base:add(p .. k, v, ttl) end,
    expire = function(_, k, ttl) return base:expire(p .. k, ttl) end,
  }
end

return _M
