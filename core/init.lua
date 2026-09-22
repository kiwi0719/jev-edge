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
--                 err == judge.BUSY: the adapter's own in-flight cap refused
--                 the call; not a provider failure, not fed to the breaker
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
local defaults  = require "jev.core.defaults"

local _M = { _VERSION = "0.6.0" }

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
  subject.rep_record(ctx, v)
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
-- @param over optional { templates, deployment }: the question this entry
--             answers when it is not the rule's own (retrieved content)
function _M.cache_key(fp, rule, cfg, hash, over)
  local jev = cfg and cfg.jev or {}
  local templates = over and over.templates or (rule and rule.templates) or {}
  local deployment = over and over.deployment
  if deployment == nil then deployment = rule and rule.deployment_context or jev.deployment_context or "" end
  local scope = table.concat({
    tostring(rule and rule.id or ""),
    table.concat(templates, ","),
    tostring(deployment),
    tostring(jev.provider or ""),
    tostring(jev.model or ""),
  }, "\n")
  return "fp:" .. tostring(hash(scope)):sub(1, 16) .. ":" .. fp
end

-- Joins the whole text and the retrieved content into what the request's
-- fingerprint covers: trust and the verdict cache must not treat a request
-- with new retrieved content as one already judged.
local UNTRUSTED_SEP = "\n<untrusted content>\n"

-- Judge a request in parts: text that did not fit one window, chunk by chunk
-- (rule.max_judge_chunks), and retrieved content with its own question
-- (untrusted.enabled). Each part has its own verdict-cache entry, so the
-- unchanged history of a long conversation (earlier tool results included)
-- is not paid for again on every turn; the misses go to the judge together
-- (ctx.judge.call_many, in parallel, when the adapter has it). The request's
-- score is the highest part score. A part the judge failed on turns the
-- request into an error unless another part already blocks.
-- @param parts  list of { text, templates, context, over } (over: cache_key's)
-- @param suffix appended to the reason when a part answered
local function judge_parts(ctx, rule, parts, suffix, fp, ckey, reason)
  local cfg = ctx.config
  local scores, tops, pending = {}, {}, {}
  for i, part in ipairs(parts) do
    local cfp = normalize.fingerprint(part.text, { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)
    local ck = cfp ~= "" and _M.cache_key(cfp, rule, cfg, ctx.hash, part.over) or nil
    local hit = ck and ctx.cache and ctx.cache:get(ck)
    if type(hit) == "table" and type(hit.score) == "number" then
      scores[i], tops[i] = hit.score, tostring(hit.reason or ""):match("^(%S+)") or ""
    else
      local prompt, perr = judge.build(part.templates, part.text, part.context)
      if not prompt then
        log(ctx, "error", "jev-edge: " .. perr)
        local action, label, async = policy.on_error()
        return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
          source = verdict.SRC_L2, reason = perr, fingerprint = fp }))
      end
      pending[#pending + 1] = { i = i, prompt = prompt, ck = ck }
    end
  end

  local t0 = now_ms(ctx)
  local results = {}
  if #pending > 1 and type(ctx.judge.call_many) == "function" then
    local prompts = {}
    for k, p in ipairs(pending) do prompts[k] = p.prompt end
    results = ctx.judge.call_many(prompts, cfg.jev.timeout_ms) or {}
  else
    for k, p in ipairs(pending) do
      local a, e = ctx.judge.call(p.prompt, cfg.jev.timeout_ms)
      results[k] = { a, e }
    end
  end
  local elapsed = now_ms(ctx) - t0

  local err, failed, answered
  for k, p in ipairs(pending) do
    local a, e = results[k] and results[k][1], results[k] and results[k][2]
    local s, t, n
    if a then s, t, n = judge.reduce(a) end
    if not a or n == 0 then
      err = err or tostring(e or (a and "no scores in answer") or "error")
      if e ~= judge.BUSY then failed = true end
    else
      answered = true
      scores[p.i], tops[p.i] = s, t
      if p.ck and ctx.cache then
        ctx.cache:set(p.ck, { score = s, reason = t .. " " .. string.format("%.2f", s) }, cfg.cache.fp_ttl)
      end
    end
  end
  -- only calls that reached the provider say anything about its health
  if ctx.breaker then
    if failed then ctx.breaker:failure() elseif answered then ctx.breaker:success() end
  end

  local best, top = nil, ""
  for i = 1, #parts do
    if scores[i] and (not best or scores[i] > best) then best, top = scores[i], tops[i] end
  end
  if err and not (best and best >= cfg.policy.block_threshold) then
    log(ctx, "warn", "jev-edge: L2 failed on a chunk: " .. err)
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = err, fingerprint = fp, l2_ms = elapsed }))
  end

  local action, label, async = policy.decide(best, cfg.policy)
  local why = top ~= "" and (top .. " " .. string.format("%.2f", best)) or reason
  if top ~= "" then why = why .. suffix end
  if ckey and ctx.cache then
    ctx.cache:set(ckey, { score = best, reason = why }, cfg.cache.fp_ttl)
  end
  return finish(ctx, verdict.new({
    action = action, verdict = label, score = best, async = async,
    source = verdict.SRC_L2, reason = why, fingerprint = fp, l2_ms = elapsed,
  }))
end

function _M.evaluate(req, ctx)
  local cfg = ctx.config

  -- L1 ------------------------------------------------------------------
  local r, text, reason, rule, windowed, chunks, capped, untrusted = rules_mod.evaluate_all(req, ctx.rules, ctx)

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

  local fp = normalize.fingerprint(untrusted and (text .. UNTRUSTED_SEP .. untrusted.text) or text,
    { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)
  local uspec = untrusted and defaults.untrusted_spec(cfg, rule)

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
  local ckey = fp ~= "" and _M.cache_key(fp, rule, cfg, ctx.hash, uspec and {
    templates = { table.concat(rule.templates or {}, ","), "+" .. table.concat(uspec.templates, ",") },
  }) or nil
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
  if chunks and #chunks > 1 then
    -- max_judge_chunks > 1 was the operator's choice to judge long text in
    -- full; what still did not fit is unjudgeable, and policy.unjudgeable
    -- decides as it does for any other unreadable request
    if capped and cfg.policy.unjudgeable == "block" and cfg.policy.mode == "enforce" then
      return finish(ctx, verdict.new({
        action = verdict.ACTION_BLOCK, verdict = verdict.SKIPPED, source = verdict.SRC_L1,
        reason = "unjudgeable: text over max_judge_chunks", fingerprint = fp,
      }))
    end
  end
  if (chunks and #chunks > 1) or untrusted then
    local context = {
      path = req.path or "", method = req.method or "",
      deployment = rule.deployment_context or cfg.jev.deployment_context or "",
    }
    local parts = {}
    if not (untrusted and untrusted.only) then
      for _, c in ipairs((chunks and #chunks > 1) and chunks or { text }) do
        parts[#parts + 1] = { text = c, templates = rule.templates, context = context }
      end
    end
    local suffix = ""
    if chunks and #chunks > 1 then
      suffix = capped and " (window)" or (" (" .. #chunks .. " chunks)")
    elseif windowed or (untrusted and untrusted.windowed) then
      suffix = " (window)"
    end
    if untrusted then
      -- asked without the deployment context, the way the question was measured
      parts[#parts + 1] = { text = untrusted.text, templates = uspec.templates,
        context = { path = req.path or "", method = req.method or "", deployment = "" },
        over = { templates = uspec.templates, deployment = "" } }
    end
    return judge_parts(ctx, rule, parts, suffix, fp, ckey, reason)
  end
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
    if ctx.breaker and jerr ~= judge.BUSY then ctx.breaker:failure() end
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
