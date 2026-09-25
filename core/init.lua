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
--   judge       { call = fn(prompt, timeout_ms) -> answers|nil, err, kind }
--                 answers: { [template_name] = probability }
--                 err == judge.BUSY: the adapter's own in-flight cap refused
--                 the call; not a provider failure, not fed to the breaker
--                 kind: judge.TRANSPORT | TIMEOUT | UNAVAILABLE (breaker
--                 failures) or REJECTED | UNUSABLE (not); none = counted
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

local _M = { _VERSION = "0.6.1" }

local function log(ctx, level, msg)
  if ctx.log then ctx.log(level, msg) end
end

local function now_ms(ctx)
  return (ctx.clock and ctx.clock() or 0) * 1000
end

-- What subject reputation charges for a request judged in parts: nil (the
-- verdict's own label) when the subject's own text scored the request's
-- score, its own score when a part it is not charged for (the tool
-- definitions) scored higher, and false when none of its own text was judged.
-- The whole request's cache entry keeps it as `rep`, so a hit charges the same.
local function rep_of(best, own)
  if own == nil then return false end
  if own == best then return nil end
  return own
end

-- Every exit that produced a decision goes through here, so a trajectory has
-- no holes: a cache hit and a breaker skip are as much a step in an attack as
-- an L2 call is. The one exit that does not is L1 PASS -- the request was
-- never a candidate, and that is the hot path.
-- @param rep optional, rep_of(): what subject reputation charges
local function finish(ctx, v, rep)
  subject.record(ctx, v)
  local charge
  if rep == false then
    charge = false
  elseif type(rep) == "number" then
    charge = select(2, policy.decide(rep, ctx.config.policy))
  end
  subject.rep_record(ctx, v, charge)
  return v
end

-- Tell the breaker how a request it admitted went. Only calls that reached
-- the provider and found it failing count against it (judge.counts); a
-- request that says nothing about its health releases a half-open probe.
local function settle(ctx, failed, answered)
  local b = ctx.breaker
  if not b then return end
  if failed then b:failure()
  elseif answered then b:success()
  elseif b.release then b:release() end
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

-- Joins the whole text, the retrieved content and the tool definitions into
-- what the request's fingerprint covers: trust and the verdict cache must not
-- treat a request with new retrieved content or new tools as one already
-- judged.
local UNTRUSTED_SEP = "\n<untrusted content>\n"
local TOOLS_SEP = "\n<tool definitions>\n"

-- Names the tool-definitions part in the reason when its score decides.
local TOOLS_LABEL = "tools+"

-- What L2 judges for a request L1 found suspect, and L3 after it: the
-- request's fingerprint and whole-request cache key, the judge's context,
-- and, when it is judged in more than one piece, the parts and the suffix
-- their reason takes (for one piece, the suffix its reason takes).
local function plan(req, cfg, hash, rule, text, windowed, chunks, capped, untrusted, tools)
  local whole = text
  if untrusted then whole = whole .. UNTRUSTED_SEP .. untrusted.text end
  if tools then whole = whole .. TOOLS_SEP .. tools.text end
  local p = { fp = normalize.fingerprint(whole, { prefix_bytes = cfg.cache.fp_prefix_bytes }, hash) }
  local uspec = untrusted and defaults.untrusted_spec(cfg, rule)
  -- The whole request's entry. Judged in parts, it names the parts in its
  -- scope, so it never answers for the same text judged in one piece.
  local over
  if uspec or tools then
    local names = { table.concat(rule.templates or {}, ",") }
    if uspec then names[#names + 1] = "+" .. table.concat(uspec.templates, ",") end
    if tools then names[#names + 1] = "+tools" end
    over = { templates = names }
  end
  p.key = p.fp ~= "" and _M.cache_key(p.fp, rule, cfg, hash, over) or nil
  p.context = {
    path = req.path or "", method = req.method or "",
    deployment = rule.deployment_context or cfg.jev.deployment_context or "",
  }
  if not ((chunks and #chunks > 1) or untrusted or tools) then
    -- the score is for the window, not the whole text; the reason says so
    p.suffix = windowed and " (window)" or ""
    return p
  end
  local parts = {}
  -- the text only stands aside when it alone would have passed
  if not ((untrusted and untrusted.only) or (tools and tools.only)) then
    for _, c in ipairs((chunks and #chunks > 1) and chunks or { text }) do
      parts[#parts + 1] = { text = c, templates = rule.templates, context = p.context }
    end
  end
  local suffix = ""
  if chunks and #chunks > 1 then
    suffix = capped and " (window)" or (" (" .. #chunks .. " chunks" .. (windowed and ", window" or "") .. ")")
  elseif windowed or (untrusted and untrusted.windowed) or (tools and tools.windowed) then
    suffix = " (window)"
  end
  if untrusted then
    -- asked without the deployment context, the way the question was measured
    parts[#parts + 1] = { text = untrusted.text, templates = uspec.templates,
      context = { path = req.path or "", method = req.method or "", deployment = "" },
      over = { templates = uspec.templates, deployment = "" } }
  end
  if tools then
    -- the client sent them: the same question and scope as its own text,
    -- so the entry is the one any text like it gets. An agent loads them
    -- from servers the user may not control: their score decides the
    -- request, but the subject's reputation is charged for its own text.
    parts[#parts + 1] = { text = tools.text, templates = rule.templates, context = p.context,
      label = TOOLS_LABEL, rep = false }
  end
  p.parts, p.suffix = parts, suffix
  return p
end

-- Judge a request in parts: text that did not fit one window, chunk by chunk
-- (rule.max_judge_chunks), retrieved content with its own question
-- (untrusted.enabled), and the tool definitions (rule.tool_fields). Each part
-- has its own verdict-cache entry, so the unchanged history of a long
-- conversation (earlier tool results included) and an unchanged tool set are
-- not paid for again on every turn; the misses go to the judge together
-- (ctx.judge.call_many, in parallel, when the adapter has it). The request's
-- score is the highest part score. A part the judge failed on turns the
-- request into an error unless another part already blocks.
-- @param parts  list of { text, templates, context, over, label, rep } (over:
--               cache_key's; label: put before the template name in the
--               reason when this part's score decides; rep = false: not the
--               subject's own text, its score is not charged to it)
-- @param suffix appended to the reason when a part answered
local function judge_parts(ctx, rule, parts, suffix, fp, ckey, reason)
  local cfg = ctx.config
  local scores, tops, pending = {}, {}, {}
  for i, part in ipairs(parts) do
    local cfp = normalize.fingerprint(part.text, { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)
    local ck = cfp ~= "" and _M.cache_key(cfp, rule, cfg, ctx.hash, part.over) or nil
    local hit = ck and ctx.cache and ctx.cache:get(ck)
    if type(hit) == "table" and type(hit.score) == "number" then
      -- a part's entry holds its own reason, unlabelled: the same text is
      -- the same entry whichever part it came in
      scores[i], tops[i] = hit.score, tostring(hit.reason or ""):match("^(%S+)") or ""
    else
      local prompt, perr = judge.build(part.templates, part.text, part.context)
      if not prompt then
        log(ctx, "error", "jev-edge: " .. perr)
        settle(ctx)
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
      local a, e, kind = ctx.judge.call(p.prompt, cfg.jev.timeout_ms)
      results[k] = { a, e, kind }
    end
  end
  local elapsed = now_ms(ctx) - t0

  local err, failed, answered
  for k, p in ipairs(pending) do
    local r = results[k] or {}
    local a, e, kind = r[1], r[2], r[3]
    local s, t, n
    if a then s, t, n = judge.reduce(a) end
    if not a or n == 0 then
      if a then e, kind = "no scores in answer", judge.UNUSABLE end
      err = err or judge.reason(e, kind)
      if judge.counts(e, kind) then failed = true end
    else
      answered = true
      scores[p.i], tops[p.i] = s, t
      if p.ck and ctx.cache then
        ctx.cache:set(p.ck, { score = s, reason = t .. " " .. string.format("%.2f", s) }, cfg.cache.fp_ttl)
      end
    end
  end
  -- only calls that reached the provider say anything about its health
  settle(ctx, failed, answered)

  local best, top, own = nil, "", nil
  for i = 1, #parts do
    if scores[i] and (not best or scores[i] > best) then
      best, top = scores[i], tops[i]
      if top ~= "" and parts[i].label then top = parts[i].label .. top end
    end
    if scores[i] and parts[i].rep ~= false and (not own or scores[i] > own) then own = scores[i] end
  end
  local rep = rep_of(best, own)
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
    ctx.cache:set(ckey, { score = best, reason = why, rep = rep }, cfg.cache.fp_ttl)
  end
  return finish(ctx, verdict.new({
    action = action, verdict = label, score = best, async = async,
    source = verdict.SRC_L2, reason = why, fingerprint = fp, l2_ms = elapsed,
  }), rep)
end

function _M.evaluate(req, ctx)
  local cfg = ctx.config

  -- L1 ------------------------------------------------------------------
  local r, text, reason, rule, windowed, chunks, capped, untrusted, tools = rules_mod.evaluate_all(req, ctx.rules, ctx)

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

  local p = plan(req, cfg, ctx.hash, rule, text, windowed, chunks, capped, untrusted, tools)
  local fp, ckey = p.fp, p.key

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
  if ckey and ctx.cache then
    local hit = ctx.cache:get(ckey)
    if type(hit) == "table" and type(hit.score) == "number" then
      local action, label = policy.decide(hit.score, cfg.policy)
      -- Never async on a hit: the cached score already is the judge's
      -- answer, and a re-judge per hit would turn the cache into an
      -- amplifier (one suspicious prompt repeated N times = N L3 calls).
      local rep = hit.rep
      if rep ~= false and type(rep) ~= "number" then rep = nil end
      return finish(ctx, verdict.new({
        action = action, verdict = label, score = hit.score, async = false,
        source = verdict.SRC_CACHE, reason = hit.reason or reason, fingerprint = fp,
      }), rep)
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
      settle(ctx)
      return finish(ctx, verdict.new({
        action = verdict.ACTION_BLOCK, verdict = verdict.SKIPPED, source = verdict.SRC_L1,
        reason = "unjudgeable: text over max_judge_chunks", fingerprint = fp,
      }))
    end
  end
  if p.parts then return judge_parts(ctx, rule, p.parts, p.suffix, fp, ckey, reason) end
  local prompt, perr = judge.build(rule.templates, text, p.context)
  if not prompt then
    log(ctx, "error", "jev-edge: " .. perr)
    settle(ctx)
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = perr, fingerprint = fp }))
  end

  local t0 = now_ms(ctx)
  local answers, jerr, jkind = ctx.judge.call(prompt, cfg.jev.timeout_ms)
  local elapsed = now_ms(ctx) - t0

  if not answers then
    local why = judge.reason(jerr, jkind)
    settle(ctx, judge.counts(jerr, jkind))
    log(ctx, "warn", "jev-edge: L2 failed: " .. why)
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = why,
      fingerprint = fp, l2_ms = elapsed }))
  end

  local score, top, n = judge.reduce(answers)
  if n == 0 then
    -- An answer with no score in it is an error, not a SAFE verdict: caching
    -- score 0 would wave the same text through for fp_ttl. Nor is it the
    -- provider failing: the judged text can make a judge answer that way.
    local why = judge.reason("no scores in answer", judge.UNUSABLE)
    settle(ctx)
    log(ctx, "warn", "jev-edge: L2 answer has no scores")
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = why,
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

-- ---------------------------------------------------------------------------
-- L3: an adapter re-judges a request off the request path when L2 could not
-- answer it or answered in the suspicious band. It judges what L2 judged:
-- the same parts (every chunk, the retrieved content, the tool definitions)
-- with the same prompts, keeps each part's answer under that part's cache
-- key, and writes the whole request's key only when every part answered, so
-- a cached score is never one for less than the whole request.
-- ---------------------------------------------------------------------------

--- What L3 judges for a request: its parts as prompts, with the key each
-- answer is kept under. The request goes through L1 again with the same
-- rules, without the stores (reputation is not looked up again).
-- @param req the request, as evaluate() had it
-- @param ctx { config, rules, hash, json_decode, re_find, log }
-- @return nil when L1 no longer finds it suspect or a prompt cannot be
--         built; else { fingerprint, key (the whole request's cache key, or
--         nil), reason (L1's), suffix, parts = { { prompt, key, label, rep } } }
function _M.l3_job(req, ctx)
  local cfg = ctx.config
  local r, text, reason, rule, windowed, chunks, capped, untrusted, tools = rules_mod.evaluate_all(req, ctx.rules,
    { config = cfg, json_decode = ctx.json_decode, re_find = ctx.re_find, log = ctx.log })
  if r ~= rules_mod.SUSPECT then return nil end
  local p = plan(req, cfg, ctx.hash, rule, text, windowed, chunks, capped, untrusted, tools)
  local job = { fingerprint = p.fp, key = p.key, reason = reason, suffix = p.suffix, parts = {} }
  -- one piece: its answer is the whole request's
  local parts = p.parts or { { text = text, templates = rule.templates, context = p.context } }
  for i, part in ipairs(parts) do
    local prompt = judge.build(part.templates, part.text, part.context)
    if not prompt then return nil end
    local key = p.key
    if p.parts then
      local cfp = normalize.fingerprint(part.text, { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)
      key = cfp ~= "" and _M.cache_key(cfp, rule, cfg, ctx.hash, part.over) or nil
    end
    job.parts[i] = { prompt = prompt, key = key, label = part.label, rep = part.rep }
  end
  return job
end

--- What L3's answers make of a job: the highest part score and its verdict
-- and reason (as L2 would have given them), the label reputation charges
-- (that of the subject's own text; see rep_of), and the cache writes.
-- @param job     from l3_job
-- @param results results[k] is the judge's answers for job.parts[k], or nil
--                when that call failed
-- @param cfg     merged config
-- @return nil when no part answered with a score; else { score, verdict,
--         reason, charge (a label, or nil: charge nothing), writes =
--         { { key, value }, ... } }: each answered part under its own key,
--         and the whole request's key only when every part answered
function _M.l3_result(job, results, cfg)
  local best, top, own, all = nil, "", nil, true
  local writes = {}
  for k, part in ipairs(job.parts) do
    local a = results[k]
    local s, t, n
    if type(a) == "table" then s, t, n = judge.reduce(a) end
    if not s or n == 0 then
      all = false
    else
      if part.key and part.key ~= job.key then
        writes[#writes + 1] = { part.key, { score = s, reason = t .. " " .. string.format("%.2f", s) } }
      end
      if not best or s > best then
        best, top = s, t
        if top ~= "" and part.label then top = part.label .. top end
      end
      if part.rep ~= false and (not own or s > own) then own = s end
    end
  end
  if not best then return nil end
  local _, label = policy.decide(best, cfg.policy)
  local why = top ~= "" and (top .. " " .. string.format("%.2f", best) .. job.suffix) or job.reason
  local rep = rep_of(best, own)
  if all and job.key then
    writes[#writes + 1] = { job.key, { score = best, reason = why, rep = rep } }
  end
  local charge = label
  if rep == false then
    charge = nil
  elseif rep then
    charge = select(2, policy.decide(rep, cfg.policy))
  end
  return { score = best, verdict = label, reason = why, charge = charge, writes = writes }
end

return _M
