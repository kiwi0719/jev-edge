-- resty/jev/async.lua
-- L3 side-path: re-judge ambiguous / failed requests off the request path,
-- warm the fingerprint cache and maintain per-IP reputation.

local judge_mod = require "jev.core.judge"
local policy    = require "jev.core.policy"
local verdict   = require "jev.core.verdict"

local _M = {}

local INFLIGHT_KEY = "inflight:l3"

local function done(job)
  local st = job.state or job.cache
  local n = st:incr(INFLIGHT_KEY, -1)
  -- The key can be evicted or reset (reload, dict flush); never let the
  -- counter go negative or the cap silently grows by that much.
  if n and n < 0 then st:set(INFLIGHT_KEY, 0, 0) end
end

local function handler(premature, job)
  -- A timer that never ran still holds a slot: the shared dict outlives the
  -- worker (HUP reload), so the slot must be given back or it is lost forever.
  if premature then return done(job) end
  local cache = job.cache
  local cfg = job.cfg
  local ok, err = pcall(function()
    -- L3 is the retry L2 could not afford: give it the ceiling, not the
    -- adaptive estimate that just failed.
    local timeout = cfg.async.timeout_ms or math.max(cfg.jev.timeout_max_ms or 0, 5000)
    local answers, jerr = job.judge.call(job.prompt, timeout)
    if not answers then
      ngx.log(ngx.WARN, "jev-edge: L3 judge failed: ", tostring(jerr))
      return
    end
    local score, top, n = judge_mod.reduce(answers)
    if n == 0 then
      -- no score in the answer: a provider fault, never a cached SAFE
      ngx.log(ngx.WARN, "jev-edge: L3 answer has no scores")
      return
    end
    local _, label = policy.decide(score, cfg.policy)
    local why = top ~= "" and (top .. " " .. string.format("%.2f", score)) or "l3"

    -- the same key core reads (core.cache_key): scoped to the rule and provider
    if job.cache_key then
      cache:set(job.cache_key, { score = score, reason = why }, cfg.cache.fp_ttl)
    end

    if job.client_ip and job.client_ip ~= "" then
      local key = "rep:" .. job.client_ip
      local rep = cache:get(key)
      if type(rep) ~= "table" then rep = { malicious = 0, safe = 0 } end
      if label == verdict.MALICIOUS then
        rep.malicious = (rep.malicious or 0) + 1
        rep.safe = 0
        local after = tonumber(cfg.async.rep_block_after) or 0
        if after > 0 and rep.malicious >= after then
          rep.blocked_until = ngx.now() + (cfg.async.rep_block_ttl or 600)
        end
        if job.on_alert then
          pcall(job.on_alert, { ip = job.client_ip, score = score, reason = why, fingerprint = job.fingerprint })
        else
          ngx.log(ngx.ERR, "jev-edge: ALERT ip=", job.client_ip, " score=", score, " reason=", why)
        end
      elseif label == verdict.SAFE then
        rep.safe = (rep.safe or 0) + 1
      end
      cache:set(key, rep, cfg.cache.rep_ttl)
    end
  end)
  if not ok then ngx.log(ngx.ERR, "jev-edge: L3 error: ", err) end
  done(job)
end

--- Schedule an L3 job. Never blocks; drops when over max_async.
-- @param job { cfg, cache, state, judge, prompt, fingerprint, cache_key, client_ip, on_alert }
--   cache_key: core.cache_key() for the rule that judged the request; nil
--   (text had no fingerprint) means reputation only, no verdict-cache write.
--   cache: verdict / reputation dict; state: where the in-flight counter lives
--   (defaults to cache).
function _M.schedule(job)
  local cfg = job.cfg
  if not cfg.async or cfg.async.enabled == false then return false, "disabled" end
  local st = job.state or job.cache
  local n = st:incr(INFLIGHT_KEY, 1)
  if n and n > (cfg.async.max_async or 32) then
    done(job)
    return false, "max_async exceeded"
  end
  local ok, err = ngx.timer.at(0, handler, job)
  if not ok then
    done(job)
    ngx.log(ngx.WARN, "jev-edge: timer.at failed: ", err)
    return false, err
  end
  return true
end

return _M
