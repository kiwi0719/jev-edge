-- core/policy.lua
-- Map a score (or an error) to an action, a verdict label and an async flag.

local verdict = require "jev.core.verdict"

local _M = {}

_M.DEFAULTS = {
  mode              = "monitor",  -- "monitor" | "enforce"
  block_threshold   = 0.7,
  suspect_threshold = 0.5,
  block_status      = 403,
  block_body        = '{"error":"request rejected"}',
}

--- Decide from a numeric score.
-- @return action, label, async
function _M.decide(score, policy)
  policy = policy or _M.DEFAULTS
  local block_t   = policy.block_threshold   or _M.DEFAULTS.block_threshold
  local suspect_t = policy.suspect_threshold or _M.DEFAULTS.suspect_threshold
  local enforce   = (policy.mode or "monitor") == "enforce"

  if score >= block_t then
    return (enforce and verdict.ACTION_BLOCK or verdict.ACTION_PASS), verdict.MALICIOUS, false
  elseif score >= suspect_t then
    return verdict.ACTION_PASS, verdict.SUSPICIOUS, true
  end
  return verdict.ACTION_PASS, verdict.SAFE, false
end

--- Decide when L2 failed (timeout, 5xx, parse error). Always pass.
function _M.on_error()
  return verdict.ACTION_PASS, verdict.ERROR, true
end

--- Decide when L2 was skipped by the breaker. Always pass.
function _M.on_skipped()
  return verdict.ACTION_PASS, verdict.SKIPPED, true
end

return _M
