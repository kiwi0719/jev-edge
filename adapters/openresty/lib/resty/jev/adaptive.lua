-- resty/jev/adaptive.lua
-- Adaptive L2 timeout with an operator-set ceiling.
--
--   effective = clamp(headroom * (mean + 2*sd), timeout_ms, timeout_max_ms)
--
-- mean/sd are exponentially weighted over successful L2 latencies shared
-- across workers through the cache dict. A timeout contributes a censored
-- sample (1.2 * the timeout that fired, capped at the ceiling) so the estimate
-- can climb after a latency step; a sustained move above the ceiling is the
-- breaker's job, not this module's.
--
-- Until `warmup` samples are seen the configured timeout_ms is used as is.

local _M = {}

local KEY_N    = "adapt:n"
local KEY_MEAN = "adapt:mean"
local KEY_VAR  = "adapt:var"

local DEFAULTS = {
  alpha   = 0.1,
  warmup  = 20,
  headroom = 1.5,
}

function _M.new(cache, cfg)
  local self = {
    cache  = cache,
    enabled = cfg.timeout_adaptive ~= false,
    floor  = tonumber(cfg.timeout_ms) or 400,
    ceil   = tonumber(cfg.timeout_max_ms) or (2.5 * (tonumber(cfg.timeout_ms) or 400)),
    headroom = tonumber(cfg.timeout_headroom) or DEFAULTS.headroom,
    alpha  = tonumber(cfg.timeout_alpha) or DEFAULTS.alpha,
    warmup = tonumber(cfg.timeout_warmup) or DEFAULTS.warmup,
  }
  if self.ceil < self.floor then self.ceil = self.floor end
  return setmetatable(self, { __index = _M })
end

function _M.stats(self)
  if not self.cache then return 0, 0, 0 end
  local n = tonumber(self.cache:get(KEY_N)) or 0
  local mean = tonumber(self.cache:get(KEY_MEAN)) or 0
  local var = tonumber(self.cache:get(KEY_VAR)) or 0
  return n, mean, var
end

--- Timeout to use for the next L2 call, in ms.
function _M.current(self)
  if not self.enabled or not self.cache then return self.floor end
  local n, mean, var = self:stats()
  if n < self.warmup then return self.floor end
  local est = self.headroom * (mean + 2 * math.sqrt(math.max(var, 0)))
  if est < self.floor then return self.floor end
  if est > self.ceil then return self.ceil end
  -- whole ms, never under a fractional floor
  return math.max(self.floor, math.floor(est))
end

local function observe(self, ms)
  local n, mean, var = self:stats()
  if n == 0 then
    mean, var = ms, 0
  else
    local a = self.alpha
    local diff = ms - mean
    mean = mean + a * diff
    var = (1 - a) * (var + a * diff * diff)
  end
  self.cache:set(KEY_N, n + 1, 0)
  self.cache:set(KEY_MEAN, mean, 0)
  self.cache:set(KEY_VAR, var, 0)
end

function _M.success(self, ms)
  if self.enabled and self.cache and ms and ms > 0 then observe(self, ms) end
end

function _M.timeout(self, fired_ms)
  if not self.enabled or not self.cache then return end
  local censored = math.min((fired_ms or self.floor) * 1.2, self.ceil)
  observe(self, censored)
end

return _M
