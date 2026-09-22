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

local _M = { _VERSION = "0.4.0" }

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

--- Verdict-cache key for a fingerprint judged under `rule`.
-- A score is only valid for the prompt that produced it: the same text judged
-- with another rule's templates or deployment context, or by another
-- provider or model, may score differently, so each gets its own entry
-- (a lenient tenant's SAFE must not be replayed on a strict one). Trust
-- stays keyed by fingerprint alone: an operator vouches for the text.
-- @param fp   fingerprint (non-empty)
-- @param rule the rule L1 matched
-- @param cfg  merged config
-- @param hash the ctx.hash the fingerprint was made with
function _M.cache_key(fp, rule, cfg, hash)
  local jev = cfg and cfg.jev or {}
  local scope = table.concat({
    tostring(rule and rule.id or ""),
    table.concat(rule and rule.templates or {}, ","),
    tostring(rule and rule.deployment_context or jev.deployment_context or ""),
    tostring(jev.provider or ""),
    tostring(jev.model or ""),
  }, "\n")
  return "fp:" .. tostring(hash(scope)):sub(1, 16) .. ":" .. fp
end

function _M.evaluate(req, ctx)
  local cfg = ctx.config

  -- L1 ------------------------------------------------------------------
  local r, text, reason, rule, windowed = rules_mod.evaluate_all(req, ctx.rules, ctx)

  if r == rules_mod.PASS then
    return verdict.new({ verdict = verdict.SKIPPED, source = verdict.SRC_L1, reason = reason })
  end
  if r == rules_mod.UNJUDGEABLE then
    -- A watched request nobody read. Not judged, so `skipped`; blocked only
    -- when the operator chose that and the gateway enforces.
    local block = cfg.policy.mode == "enforce" and cfg.policy.unjudgeable == "block"
    return finish(ctx, verdict.new({
      action = block and verdict.ACTION_BLOCK or verdict.ACTION_PASS,
      verdict = verdict.SKIPPED, source = verdict.SRC_L1, reason = reason,
    }))
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
  local ckey = fp ~= "" and _M.cache_key(fp, rule, cfg, ctx.hash) or nil
  if ckey and ctx.cache then
    local hit = ctx.cache:get(ckey)
    if type(hit) == "table" and type(hit.score) == "number" then
      local action, label = policy.decide(hit.score, cfg.policy)
      -- Never async on a hit: the cached score already is the judge's
      -- answer, and a re-judge per hit would turn the cache into an
      -- amplifier (one suspicious prompt repeated N times = N L3 calls).
      return finish(ctx, verdict.new({
        action = action, verdict = label, score = hit.score, async = false,
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

  local score, top, n = judge.reduce(answers)
  if n == 0 then
    -- An answer with no score in it is a provider fault, not a SAFE verdict:
    -- caching score 0 would wave the same text through for fp_ttl.
    if ctx.breaker then ctx.breaker:failure() end
    log(ctx, "warn", "jev-edge: L2 answer has no scores")
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = "no scores in answer",
      fingerprint = fp, l2_ms = elapsed }))
  end
  if ctx.breaker then ctx.breaker:success() end
  local action, label, async = policy.decide(score, cfg.policy)
  local why = top ~= "" and (top .. " " .. string.format("%.2f", score)) or reason
  -- the score is for the window, not the whole text; say so
  if windowed and top ~= "" then why = why .. " (window)" end

  if ckey and ctx.cache then
    ctx.cache:set(ckey, { score = score, reason = why }, cfg.cache.fp_ttl)
  end

  return finish(ctx, verdict.new({
    action = action, verdict = label, score = score, async = async,
    source = verdict.SRC_L2, reason = why, fingerprint = fp, l2_ms = elapsed,
  }))
end

return _M
