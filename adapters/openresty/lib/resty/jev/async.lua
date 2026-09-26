-- resty/jev/async.lua
-- L3 side-path: re-judge ambiguous / failed requests off the request path,
-- warm the fingerprint cache and maintain per-IP reputation. What is judged
-- and what is written is core's (core.l3_job, core.l3_result): the parts L2
-- judged, and the whole request's cache key only when every part answered.

local core    = require "jev.core"
local verdict = require "jev.core.verdict"
local rules_m = require "jev.core.rules"

local _M = {}

local INFLIGHT_KEY = "inflight:l3"

local function done(job)
  local st = job.state or job.cache
  local n = st:incr(INFLIGHT_KEY, -1)
  -- The key can be evicted or reset (reload, dict flush); never let the
  -- counter go negative or the cap silently grows by that much.
  if n and n < 0 then st:set(INFLIGHT_KEY, 0, 0) end
end

-- One answer (or nil) per part, in order; several parts at once when the
-- judge can (resty.jev.http's call_many, one light thread each).
local function judge_all(judge, parts, timeout)
  local results = {}
  if #parts > 1 and type(judge.call_many) == "function" then
    local prompts = {}
    for k, part in ipairs(parts) do prompts[k] = part.prompt end
    local rs = judge.call_many(prompts, timeout) or {}
    for k = 1, #parts do
      local r = rs[k] or {}
      if not r[1] then ngx.log(ngx.WARN, "jev-edge: L3 judge failed: ", tostring(r[2])) end
      results[k] = r[1]
    end
    return results
  end
  for k, part in ipairs(parts) do
    local answers, jerr = judge.call(part.prompt, timeout)
    if not answers then ngx.log(ngx.WARN, "jev-edge: L3 judge failed: ", tostring(jerr)) end
    results[k] = answers
  end
  return results
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
    local res = core.l3_result(job.job, judge_all(job.judge, job.job.parts, timeout), cfg)
    if not res then
      -- no score in any answer: a provider fault, never a cached SAFE
      ngx.log(ngx.WARN, "jev-edge: L3 got no score for the request")
      return
    end

    -- the keys core reads (core.cache_key): each part's, and the whole
    -- request's only when every part answered
    for _, w in ipairs(res.writes) do cache:set(w[1], w[2], cfg.cache.fp_ttl) end

    if job.client_ip and job.client_ip ~= "" then
      -- IPv6 counted per client_ip.ipv6_prefix network, as L1 reads it
      local key = "rep:" .. rules_m.ip_key(job.client_ip, cfg)
      local rep = cache:get(key)
      if type(rep) ~= "table" then rep = { malicious = 0 } end
      -- charged for the client's own text, as subject reputation is: a score
      -- from retrieved content or the tool definitions alone adds nothing
      -- (core.l3_result)
      if res.charge == verdict.MALICIOUS then
        rep.malicious = (rep.malicious or 0) + 1
        local after = tonumber(cfg.async.rep_block_after) or 0
        if after > 0 and rep.malicious >= after then
          rep.blocked_until = ngx.now() + (cfg.async.rep_block_ttl or 600)
        end
      end
      if res.verdict == verdict.MALICIOUS then
        if job.on_alert then
          pcall(job.on_alert, { ip = job.client_ip, score = res.score, reason = res.reason,
                                fingerprint = job.job.fingerprint })
        else
          ngx.log(ngx.ERR, "jev-edge: ALERT ip=", job.client_ip, " score=", res.score, " reason=", res.reason)
        end
      end
      cache:set(key, rep, cfg.cache.rep_ttl)
    end
  end)
  if not ok then ngx.log(ngx.ERR, "jev-edge: L3 error: ", err) end
  done(job)
end

--- Schedule an L3 job. Never blocks; drops when over max_async.
-- @param job { cfg, cache, state, judge, job, client_ip, on_alert }
--   job: core.l3_job() for the request (its parts' prompts and cache keys).
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
