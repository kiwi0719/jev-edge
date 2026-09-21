-- core/defaults.lua
-- Default configuration and a deep-merge helper.

local _M = {}

_M.config = {
  jev = {
    provider    = "jev",
    model       = "jev-latest",
    timeout_ms       = 400,   -- floor and cold-start value
    timeout_max_ms   = 1000,  -- ceiling the adaptive estimate may reach
    timeout_headroom = 1.5,   -- multiplier over observed mean + 2 sd
    timeout_adaptive = true,
    max_inflight = 64,
  },
  rules  = { "llm-endpoints" },
  policy = {
    mode              = "monitor",
    block_threshold   = 0.85,
    suspect_threshold = 0.5,
    block_status      = 403,
    block_body        = '{"error":"request rejected"}',
  },
  cache = {
    fp_ttl          = 300,
    rep_ttl         = 600,
    fp_prefix_bytes = 2048,
  },
  async = {
    enabled         = true,
    max_async       = 32,
    rep_block_after = 3,
    rep_block_ttl   = 600,
  },
  breaker = {
    window_s    = 60,
    min_samples = 20,
    fail_ratio  = 0.5,
    open_s      = 30,
  },
}

local function is_list(t)
  return type(t) == "table" and #t > 0 and next(t, #t) == nil
end

--- Deep-merge `over` onto a copy of `base`. Lists are replaced, not merged.
function _M.merge(base, over)
  local out = {}
  for k, v in pairs(base or {}) do
    out[k] = (type(v) == "table" and not is_list(v)) and _M.merge(v, nil) or v
  end
  for k, v in pairs(over or {}) do
    if type(v) == "table" and not is_list(v) and type(out[k]) == "table" and not is_list(out[k]) then
      out[k] = _M.merge(out[k], v)
    else
      out[k] = v
    end
  end
  return out
end

--- Validate a merged config. Returns true or nil, err.
function _M.validate(c)
  local p = c.policy or {}
  if p.mode ~= "monitor" and p.mode ~= "enforce" then
    return nil, "policy.mode must be monitor|enforce"
  end
  if type(p.block_threshold) ~= "number" or type(p.suspect_threshold) ~= "number" then
    return nil, "policy thresholds must be numbers"
  end
  if p.suspect_threshold > p.block_threshold then
    return nil, "policy.suspect_threshold must be <= block_threshold"
  end
  if type(c.jev.timeout_ms) ~= "number" or c.jev.timeout_ms <= 0 then
    return nil, "jev.timeout_ms must be > 0"
  end
  if c.jev.timeout_max_ms ~= nil and (type(c.jev.timeout_max_ms) ~= "number" or c.jev.timeout_max_ms < c.jev.timeout_ms) then
    return nil, "jev.timeout_max_ms must be >= timeout_ms"
  end
  return true
end

return _M
