-- resty/jev/cache.lua
-- ngx.shared.DICT wrapper with the { get, set } contract core expects.
-- Values are tables; they are JSON-encoded because shared dicts hold only
-- scalars. A missing dict degrades to a no-op cache (fail-open).

local cjson = require "cjson.safe"

local _M = {}
_M.__index = _M

--- @param opts optional { no_evict = true }: writes never evict other keys.
-- set uses safe_set, and incr / add create a key with safe_add, so a full
-- dict refuses the new entry (set / add return false, incr nil) instead of
-- dropping the least recently used ones. Expired keys are still reclaimed.
function _M.new(dict_name, opts)
  local dict = ngx.shared[dict_name]
  if not dict then
    ngx.log(ngx.WARN, "jev-edge: lua_shared_dict ", dict_name, " not defined; cache disabled")
  end
  return setmetatable({ dict = dict, name = dict_name, no_evict = opts and opts.no_evict or nil }, _M)
end

-- Said once per worker: a no-evict dict is full and new entries are dropped.
local function refused(self, err)
  if err == "no memory" then
    if not self.warned_full then
      self.warned_full = true
      ngx.log(ngx.WARN, "jev-edge: shared dict ", self.name, " is full, new entries are dropped",
        " (nothing is evicted); raise its size")
    end
  else
    ngx.log(ngx.WARN, "jev-edge: shared dict ", self.name, " write failed: ", err)
  end
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
  if self.no_evict then
    local ok, err = self.dict:safe_set(key, raw, tonumber(ttl) or 0)
    if not ok then refused(self, err) end
    return ok and true or false
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
  by = by or 1
  if not self.no_evict then return self.dict:incr(key, by, 0, tonumber(ttl) or 0) end
  -- incr with an init value may evict to create the key: create it with
  -- safe_add instead, and count on if another worker created it first
  local n, err = self.dict:incr(key, by)
  if n or err ~= "not found" then return n end
  local ok, aerr = self.dict:safe_add(key, by, tonumber(ttl) or 0)
  if ok then return by end
  if aerr == "exists" then return (self.dict:incr(key, by)) end
  refused(self, aerr)
  return nil
end

--- Atomic set-if-absent: true only for the caller that created the key.
function _M.add(self, key, value, ttl)
  if not self.dict then return false end
  if type(value) == "table" then value = cjson.encode(value) end
  if self.no_evict then
    local ok, err = self.dict:safe_add(key, value, tonumber(ttl) or 0)
    if not ok and err ~= "exists" then refused(self, err) end
    return ok and true or false
  end
  local ok = self.dict:add(key, value, tonumber(ttl) or 0)
  return ok and true or false
end

--- Reset a key's ttl (incr only sets one when it creates the key).
function _M.expire(self, key, ttl)
  if not self.dict or not self.dict.expire then return false end
  return self.dict:expire(key, tonumber(ttl) or 0)
end

-- ---------------------------------------------------------------------------
-- Subject stores (subject.enabled), one pair per worker and dict names.
-- ---------------------------------------------------------------------------

local subject_pairs, rep_warned = {}, {}

--- The stores subject tracking writes: trajectories in `ring_dict`, written
-- without evicting (a full dict drops new trajectory entries, never a key
-- already there), and reputation points and blocks in `rep_dict`. The ring
-- takes a new key on nearly every request under a new subject value, which
-- any client can send, so sharing an evicting dict let a flood of random
-- cookies push every block out. Without `rep_dict` declared, reputation
-- falls back to `ring_dict` (a WARN once per worker when `rep_on`): still
-- written the evicting way, so a full ring never refuses a block.
-- @return ring_store, rep_store
function _M.subject_stores(ring_dict, rep_dict, rep_on)
  local k = ring_dict .. "\0" .. rep_dict
  local pair = subject_pairs[k]
  if not pair then
    local ring = _M.new(ring_dict, { no_evict = true })
    local rep_ok = ngx.shared[rep_dict] ~= nil
    pair = { ring = ring, rep = rep_ok and _M.new(rep_dict) or _M.new(ring_dict), shared = not rep_ok }
    subject_pairs[k] = pair
  end
  if pair.shared and rep_on and not rep_warned[k] then
    rep_warned[k] = true
    ngx.log(ngx.WARN, "jev-edge: lua_shared_dict ", rep_dict, " not defined; subject reputation shares ",
      ring_dict, " with the trajectories: once it is full, recording points and blocks evicts the",
      " least recently used keys there, idle blocks included")
  end
  return pair.ring, pair.rep
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
