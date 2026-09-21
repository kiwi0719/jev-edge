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
    block_threshold   = 0.7,
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
    rep_block_after = 0,      -- 0 = never block by reputation; N = block an IP after N
                              -- malicious verdicts. Off by default: one NAT or carrier
                              -- IP can hide thousands of users.
    rep_block_ttl   = 600,
  },
  sampling = {
    enabled     = false,     -- keep a sample of decisions for replay and labelling
    rate        = 0.05,      -- share of eligible decisions kept
    min_verdict = "suspicious", -- "safe" | "suspicious" | "malicious": keep this label and above
    max_samples = 1000,      -- ring size in the cache dict
    ttl         = 86400,     -- seconds a sample stays readable
    text_bytes  = 512,       -- normalized text kept per sample (never the raw body)
    log         = false,     -- also write each sample as one JSON line at INFO
  },
  feedback = {
    -- False-positive loop: an operator marks a request "not an attack" and its
    -- fingerprint is trusted from then on. Off by default; turning it on means
    -- accepting that a POST can create a bypass, so /_jev/feedback also needs
    -- a token (see the adapter config).
    enabled      = false,
    trust_ttl    = 604800,   -- 7 days. Trust always expires: a permanent entry
                             -- is a bypass nobody reviews again.
    max_renewals = 4,        -- times traffic or a repeat report may extend it
                             -- (~5 weeks total), then it must expire. A template
                             -- still firing by then is a rule bug, not a label.
    token        = nil,      -- shared secret for POST /_jev/feedback; without it
                             -- the endpoint refuses every request.
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
  local sm = c.sampling or {}
  if sm.rate ~= nil and (type(sm.rate) ~= "number" or sm.rate < 0 or sm.rate > 1) then
    return nil, "sampling.rate must be in [0,1]"
  end
  local mv = sm.min_verdict
  if mv ~= nil and mv ~= "safe" and mv ~= "suspicious" and mv ~= "malicious" then
    return nil, "sampling.min_verdict must be safe|suspicious|malicious"
  end
  local fb = c.feedback or {}
  if fb.trust_ttl ~= nil and (type(fb.trust_ttl) ~= "number" or fb.trust_ttl <= 0) then
    return nil, "feedback.trust_ttl must be > 0"
  end
  if fb.max_renewals ~= nil and (type(fb.max_renewals) ~= "number" or fb.max_renewals < 0) then
    return nil, "feedback.max_renewals must be >= 0"
  end
  if fb.enabled == true and (fb.token == nil or fb.token == "") then
    return nil, "feedback.enabled needs feedback.token set"
  end
  local max_ms = c.jev.timeout_max_ms
  if max_ms ~= nil and (type(max_ms) ~= "number" or max_ms < c.jev.timeout_ms) then
    return nil, "jev.timeout_max_ms must be >= timeout_ms"
  end
  return true
end

return _M
