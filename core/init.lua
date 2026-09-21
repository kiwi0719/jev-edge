-- core/init.lua
-- Entry point: evaluate(req, ctx) -> verdict
--
-- ctx (all IO is injected):
--   config      merged config table (see core/defaults.lua)
--   rules       list of loaded rule tables
--   cache       { get = fn(self,key), set = fn(self,key,val,ttl) }
--   trust       same contract, for fingerprint trust only (default: cache).
--               Split it out to put trust somewhere shared or durable without
--               moving the hot verdict cache too.
--   judge       { call = fn(prompt, timeout_ms) -> answers|nil, err }
--                 answers: { [template_name] = probability }
--   breaker     object from core/breaker.lua (optional)
--   subject     optional { id = string, history = table|nil, record = fn(entry) }
--                 Per-subject trajectory (core/subject.lua). Absent, or absent
--                 id, means today's behaviour exactly. `history` is read on the
--                 request path and is IGNORED in this version; `record` is a
--                 sink the core hands one entry to without waiting.
--   clock       fn() -> seconds
--   hash        fn(string) -> string
--   json_decode fn(string) -> table
--   log         fn(level, msg) (optional)

local rules_mod = require "jev.core.rules"
local normalize = require "jev.core.normalize"
local judge     = require "jev.core.judge"
local policy    = require "jev.core.policy"
local trust     = require "jev.core.trust"
local verdict   = require "jev.core.verdict"
local subject   = require "jev.core.subject"

local _M = { _VERSION = "0.3.0" }

local function log(ctx, level, msg)
  if ctx.log then ctx.log(level, msg) end
end

local function now_ms(ctx)
  return (ctx.clock and ctx.clock() or 0) * 1000
end

-- Every exit that produced a decision goes through here, so a trajectory has
-- no holes: a cache hit and a breaker skip are as much a step in an attack as
-- an L2 call is. The one exit that does not is L1 PASS -- the request was
-- never a candidate, and that is the hot path.
local function finish(ctx, v)
  subject.record(ctx, v)
  return v
end

function _M.evaluate(req, ctx)
  local cfg = ctx.config

  -- L1 ------------------------------------------------------------------
  local r, text, reason, rule = rules_mod.evaluate_all(req, ctx.rules, ctx)

  if r == rules_mod.PASS then
    return verdict.new({ verdict = verdict.SKIPPED, source = verdict.SRC_L1, reason = reason })
  end
  if r == rules_mod.BLOCK then
    local action = (cfg.policy.mode == "enforce") and verdict.ACTION_BLOCK or verdict.ACTION_PASS
    return finish(ctx, verdict.new({
      action = action, verdict = verdict.MALICIOUS, score = 1,
      source = verdict.SRC_L1, reason = reason,
    }))
  end

  local fp = normalize.fingerprint(text, { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)

  -- trust ---------------------------------------------------------------
  -- An operator called this exact text a false positive. Checked before the
  -- verdict cache so it wins over a stale malicious score for the same text.
  if fp ~= "" and trust.enabled(cfg.feedback) then
    local store = ctx.trust or ctx.cache
    local now = ctx.clock and ctx.clock() or 0
    local rec = trust.get(store, fp, now)
    if rec then
      trust.touch(store, fp, rec, now, cfg.feedback)
      return finish(ctx, verdict.new({
        action = verdict.ACTION_PASS, verdict = verdict.SAFE, score = 0,
        source = verdict.SRC_TRUST, fingerprint = fp,
        reason = rec.by and ("fingerprint trusted by " .. rec.by) or "fingerprint trusted",
      }))
    end
  end

  -- cache ---------------------------------------------------------------
  if fp ~= "" and ctx.cache then
    local hit = ctx.cache:get("fp:" .. fp)
    if type(hit) == "table" and type(hit.score) == "number" then
      local action, label, async = policy.decide(hit.score, cfg.policy)
      return finish(ctx, verdict.new({
        action = action, verdict = label, score = hit.score, async = async,
        source = verdict.SRC_CACHE, reason = hit.reason or reason, fingerprint = fp,
      }))
    end
  end

  -- breaker -------------------------------------------------------------
  if ctx.breaker and not ctx.breaker:allow() then
    local action, label, async = policy.on_skipped()
    return finish(ctx, verdict.new({
      action = action, verdict = label, async = async,
      source = verdict.SRC_BREAKER, reason = "breaker open", fingerprint = fp,
    }))
  end

  -- L2 ------------------------------------------------------------------
  local prompt, perr = judge.build(rule.templates, text, {
    path = req.path or "", method = req.method or "",
    deployment = rule.deployment_context or cfg.jev.deployment_context or "",
  })
  if not prompt then
    log(ctx, "error", "jev-edge: " .. perr)
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = perr, fingerprint = fp }))
  end

  local t0 = now_ms(ctx)
  local answers, jerr = ctx.judge.call(prompt, cfg.jev.timeout_ms)
  local elapsed = now_ms(ctx) - t0

  if not answers then
    if ctx.breaker then ctx.breaker:failure() end
    log(ctx, "warn", "jev-edge: L2 failed: " .. tostring(jerr))
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = tostring(jerr or "error"),
      fingerprint = fp, l2_ms = elapsed }))
  end

  if ctx.breaker then ctx.breaker:success() end
  local score, top = judge.reduce(answers)
  local action, label, async = policy.decide(score, cfg.policy)
  local why = top ~= "" and (top .. " " .. string.format("%.2f", score)) or reason

  if fp ~= "" and ctx.cache then
    ctx.cache:set("fp:" .. fp, { score = score, reason = why }, cfg.cache.fp_ttl)
  end

  return finish(ctx, verdict.new({
    action = action, verdict = label, score = score, async = async,
    source = verdict.SRC_L2, reason = why, fingerprint = fp, l2_ms = elapsed,
  }))
end

return _M
