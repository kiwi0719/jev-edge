-- resty/jev/async.lua
-- L3 side-path: re-judge ambiguous / failed requests off the request path,
-- warm the fingerprint cache and maintain per-IP reputation.

local judge_mod = require "jev.core.judge"
local policy    = require "jev.core.policy"
local verdict   = require "jev.core.verdict"

local _M = {}

local INFLIGHT_KEY = "inflight:l3"

local function handler(premature, job)
  if premature then return end
  local cache = job.cache
  local cfg = job.cfg
  local ok, err = pcall(function()
    local answers, jerr = job.judge.call(job.prompt, cfg.async.timeout_ms or 5000)
    if not answers then
      ngx.log(ngx.WARN, "jev-edge: L3 judge failed: ", tostring(jerr))
      return
    end
    local score, top = judge_mod.reduce(answers)
    local _, label = policy.decide(score, cfg.policy)
    local why = top ~= "" and (top .. " " .. string.format("%.2f", score)) or "l3"

    if job.fingerprint ~= "" then
      cache:set("fp:" .. job.fingerprint, { score = score, reason = why }, cfg.cache.fp_ttl)
    end

    if job.client_ip and job.client_ip ~= "" then
      local key = "rep:" .. job.client_ip
      local rep = cache:get(key)
      if type(rep) ~= "table" then rep = { malicious = 0, safe = 0 } end
      if label == verdict.MALICIOUS then
        rep.malicious = (rep.malicious or 0) + 1
        rep.safe = 0
        if rep.malicious >= (cfg.async.rep_block_after or 3) then
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
  cache:incr(INFLIGHT_KEY, -1)
end

--- Schedule an L3 job. Never blocks; drops when over max_async.
-- @param job { cfg, cache, judge, prompt, fingerprint, client_ip, on_alert }
function _M.schedule(job)
  local cfg = job.cfg
  if not cfg.async or cfg.async.enabled == false then return false, "disabled" end
  local n = job.cache:incr(INFLIGHT_KEY, 1)
  if n and n > (cfg.async.max_async or 32) then
    job.cache:incr(INFLIGHT_KEY, -1)
    return false, "max_async exceeded"
  end
  local ok, err = ngx.timer.at(0, handler, job)
  if not ok then
    job.cache:incr(INFLIGHT_KEY, -1)
    ngx.log(ngx.WARN, "jev-edge: timer.at failed: ", err)
    return false, err
  end
  return true
end

return _M
