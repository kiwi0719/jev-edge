-- core/breaker.lua
-- Circuit breaker over tumbling windows of `window_s` seconds. State lives in
-- an injected store so that nginx workers can share it through a shared dict.
--
-- store interface: get(key) -> value|nil ; set(key, value, ttl_seconds)
-- clock: function() -> seconds (number, may be fractional)

local _M = {}

_M.CLOSED    = 0
_M.OPEN      = 1
_M.HALF_OPEN = 2

_M.DEFAULTS = {
  window_s    = 60,
  min_samples = 20,
  fail_ratio  = 0.5,
  open_s      = 30,
  key_prefix  = "brk:",
}

local function cfg(self, k) return self.cfg[k] or _M.DEFAULTS[k] end

local function bucket(self, now)
  return math.floor(now / cfg(self, "window_s"))
end

local function counters(self, now)
  local key = cfg(self, "key_prefix") .. "w:" .. bucket(self, now)
  local c = self.store:get(key)
  if type(c) ~= "table" then c = { ok = 0, fail = 0 } end
  return key, c
end

function _M.new(store, clock, config)
  return setmetatable({
    store = store,
    clock = clock,
    cfg   = config or {},
  }, { __index = _M })
end

function _M.state(self)
  local s = self.store:get(cfg(self, "key_prefix") .. "state")
  if type(s) ~= "table" then return _M.CLOSED end
  local now = self.clock()
  if s.state == _M.OPEN then
    if now >= (s.until_ts or 0) then
      return _M.HALF_OPEN
    end
    return _M.OPEN
  end
  return s.state or _M.CLOSED
end

--- Should a request try L2 right now?
-- In HALF_OPEN exactly one probe is admitted per open period.
function _M.allow(self)
  local st = self:state()
  if st == _M.CLOSED then return true end
  if st == _M.OPEN then return false end
  -- half-open: claim the probe slot
  local key = cfg(self, "key_prefix") .. "probe"
  if self.store:get(key) then return false end
  self.store:set(key, true, cfg(self, "open_s"))
  return true
end

local function record(self, ok)
  local now = self.clock()
  local key, c = counters(self, now)
  if ok then c.ok = c.ok + 1 else c.fail = c.fail + 1 end
  self.store:set(key, c, cfg(self, "window_s") * 2)

  local st = self:state()
  if st == _M.HALF_OPEN then
    if ok then
      self.store:set(cfg(self, "key_prefix") .. "state", { state = _M.CLOSED }, 0)
      self.store:set(cfg(self, "key_prefix") .. "probe", nil, 0)
      -- The window that tripped us is still full of failures; start the
      -- closed period from a clean count or the next success re-trips.
      self.store:set(key, { ok = 1, fail = 0 }, cfg(self, "window_s") * 2)
    else
      self:trip(now)
    end
    return
  end

  local total = c.ok + c.fail
  if st == _M.CLOSED and total >= cfg(self, "min_samples")
     and (c.fail / total) >= cfg(self, "fail_ratio") then
    self:trip(now)
  end
end

function _M.trip(self, now)
  now = now or self.clock()
  self.store:set(cfg(self, "key_prefix") .. "state",
    { state = _M.OPEN, until_ts = now + cfg(self, "open_s") }, 0)
  self.store:set(cfg(self, "key_prefix") .. "probe", nil, 0)
end

function _M.success(self) record(self, true) end
function _M.failure(self) record(self, false) end

return _M
