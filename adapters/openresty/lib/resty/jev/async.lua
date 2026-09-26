-- resty/jev/async.lua
-- L3 side-path: re-judge ambiguous / failed requests off the request path,
-- warm the fingerprint cache and maintain per-IP reputation. What is judged
-- and what is written is core's (core.l3_job, core.l3_result): the parts L2
-- judged, and the whole request's cache key only when every part answered.

local core    = require "jev.core"
local verdict = require "jev.core.verdict"
local judge_m = require "jev.core.judge"
local http    = require "resty.jev.http"

local _M = {}

-- L3 is the retry L2 could not afford: it gets the ceiling, not the adaptive
-- estimate that just failed.
local function l3_timeout(cfg)
  return cfg.async.timeout_ms or math.max(cfg.jev.timeout_max_ms or 0, 5000)
end

-- The jobs in flight, counted as leases (resty.jev.http slots): a timer
-- killed mid-job (a worker past worker_shutdown_timeout) never runs done(),
-- and its slot comes back with the lease instead of never. A job's parts are
-- judged at once (call_many), so it runs about one L3 timeout.
local function slots(cfg, st)
  return http.slots(st, "inflight:l3", math.ceil(l3_timeout(cfg) / 1000) + 5)
end

local function done(job)
  if job.slot then slots(job.cfg, job.state or job.cache).give(job.slot) end
  job.slot = nil
end

-- resty.jev.http takes no L2 in-flight slot for these calls: L3 has its own
-- cap (max_async), and the L2 slots are the ones that just overflowed.
local LANE = { lane = "l3" }

-- One answer (or nil) per part, in order; several parts at once when the
-- judge can (resty.jev.http's call_many, one light thread each). The second
-- value is nil when every part answered, "busy" when the only failures were
-- a judge's in-flight cap, "failed" otherwise.
local function judge_all(judge, parts, timeout)
  local results, failed = {}, nil
  local function fail(err)
    ngx.log(ngx.WARN, "jev-edge: L3 judge failed: ", tostring(err))
    if err == judge_m.BUSY and failed ~= "failed" then failed = "busy" else failed = "failed" end
  end
  if #parts > 1 and type(judge.call_many) == "function" then
    local prompts = {}
    for k, part in ipairs(parts) do prompts[k] = part.prompt end
    local rs = judge.call_many(prompts, timeout, LANE) or {}
    for k = 1, #parts do
      local r = rs[k] or {}
      if not r[1] then fail(r[2]) end
      results[k] = r[1]
    end
    return results, failed
  end
  for k, part in ipairs(parts) do
    local answers, jerr = judge.call(part.prompt, timeout, LANE)
    if not answers then fail(jerr) end
    results[k] = answers
  end
  return results, failed
end

local function handler(premature, job)
  -- A timer that never ran still holds a slot: the shared dict outlives the
  -- worker (HUP reload), so the slot must be given back or it is lost forever.
  if premature then return done(job) end
  local cache = job.cache
  local cfg = job.cfg
  local result
  local ok, err = pcall(function()
    local answers, failed = judge_all(job.judge, job.job.parts, l3_timeout(cfg))
    local res = core.l3_result(job.job, answers, cfg)
    -- a job with a part that got no answer is not a second look, even when
    -- the other parts' answers are written
    result = failed or (res and "ok" or "no_scores")
    if not res then
      -- no score in any answer: a provider fault, never a cached SAFE
      ngx.log(ngx.WARN, "jev-edge: L3 got no score for the request")
      return
    end

    -- the keys core reads (core.cache_key): each part's, and the whole
    -- request's only when every part answered
    for _, w in ipairs(res.writes) do cache:set(w[1], w[2], cfg.cache.fp_ttl) end

    if job.client_ip and job.client_ip ~= "" then
      local key = "rep:" .. job.client_ip
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
  if not ok then
    result = "error"
    ngx.log(ngx.ERR, "jev-edge: L3 error: ", err)
  end
  if job.on_result then pcall(job.on_result, result) end
  done(job)
end

--- Schedule an L3 job. Never blocks; drops when over max_async.
-- @param job { cfg, cache, state, judge, job, client_ip, on_alert, on_result }
--   job: core.l3_job() for the request (its parts' prompts and cache keys).
--   cache: verdict / reputation dict; state: where the in-flight counter lives
--   (defaults to cache).
--   on_result: optional function(result) once the job has run, result one of
--   "ok" (every part answered), "failed" (a part got no answer: provider
--   error or timeout), "busy" (the judge's in-flight cap, and nothing else,
--   refused a part), "no_scores" (answers without a score) or "error" (the
--   job threw).
function _M.schedule(job)
  local cfg = job.cfg
  if not cfg.async or cfg.async.enabled == false then return false, "disabled" end
  local slot = slots(cfg, job.state or job.cache).take(cfg.async.max_async or 32)
  if slot == nil then return false, "max_async exceeded" end
  job.slot = slot
  local ok, err = ngx.timer.at(0, handler, job)
  if not ok then
    done(job)
    ngx.log(ngx.WARN, "jev-edge: timer.at failed: ", err)
    return false, err
  end
  return true
end

return _M
