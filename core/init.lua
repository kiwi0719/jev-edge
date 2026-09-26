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

-- What reputation charges for a request judged in parts: the max score over
-- the subject's own parts, the text it wrote. Retrieved content and tool
-- definitions come from elsewhere (a web page, a mailbox, an MCP server the
-- user may not control): their score decides the request, but charging it
-- would let anyone who plants text there get users blocked. With untrusted
-- judging on, the text is not the subject's own either when it holds
-- retrieved content (a role "tool" message, a Responses *_output item: L1's
-- `retrieved`), since its one score cannot say which of the two it is for;
-- with untrusted judging off the text is charged whole, as it always was.
-- nil (the verdict's own label) when the subject's own text scored the
-- request's score, its own score when a part it is not charged for scored
-- higher, and false when none of its own text was judged. The whole
-- request's cache entry keeps it as `rep`, so a hit charges the same; L3
-- charges IP reputation on the same label (l3_result).
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

-- The judge endpoint as the cache scope names it: scheme and host
-- lowercased (they are case-insensitive), trailing slashes dropped; the rest
-- byte for byte.
local function scope_endpoint(e)
  e = tostring(e)
  local scheme, auth, rest = e:match("^(%a[%w+.%-]*://)([^/?#]*)(.*)$")
  if scheme then
    local user, host = auth:match("^(.*@)([^@]*)$")
    if user then auth = user .. host:lower() else auth = auth:lower() end
    e = scheme:lower() .. auth .. rest
  end
  return (e:gsub("/+$", ""))
end

-- A value of jev.questions in a canonical spelling: a table as its keys
-- sorted, each key=value, nested the same way (a list's keys are 1, 2, ...).
local function canon(v)
  if type(v) ~= "table" then return tostring(v) end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = tostring(k) end
  table.sort(keys)
  local byname = {}
  for k, x in pairs(v) do byname[tostring(k)] = x end
  local out = {}
  for i, k in ipairs(keys) do out[i] = k .. "=" .. canon(byname[k]) end
  return "{" .. table.concat(out, ",") .. "}"
end

-- The question wording a provider reads for these templates
-- (providers/jev.lua: only these fields); nil when none is overridden.
local WORDING = { "instructions", "criteria", "instructions_ctx", "criteria_ctx" }
local function scope_questions(qs, templates, hash)
  if type(qs) ~= "table" then return nil end
  -- a whole request's entry names its parts ("injection,abuse", "+untrusted")
  local names, seen = {}, {}
  for _, t in ipairs(templates) do
    for n in tostring(t):gmatch("[^,+]+") do
      if not seen[n] then seen[n] = true; names[#names + 1] = n end
    end
  end
  table.sort(names)
  local lines = {}
  for _, n in ipairs(names) do
    local q = qs[n]
    if type(q) == "table" then
      for _, k in ipairs(WORDING) do
        if q[k] ~= nil then lines[#lines + 1] = n .. "." .. k .. "=" .. canon(q[k]) end
      end
    end
  end
  if #lines == 0 then return nil end
  return tostring(hash(table.concat(lines, "\n")))
end

--- Verdict-cache key for a fingerprint judged under `rule`.
-- A score is only valid for the prompt that produced it: the same text judged
-- with another rule's templates or deployment context, by another provider,
-- model or endpoint (a thin Worker's origin is its endpoint), or with other
-- question wording (jev.questions), may score differently, so each gets its
-- own entry (a lenient tenant's SAFE must not be replayed on a strict one).
-- The endpoint and the wording join the scope only when set, so the keys of
-- a config without them stay as they were. Trust stays keyed by fingerprint
-- alone: an operator vouches for the text.
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
  local fields = {
    tostring(rule and rule.id or ""),
    table.concat(templates, ","),
    tostring(deployment),
    tostring(jev.provider or ""),
    tostring(jev.model or ""),
  }
  if type(jev.endpoint) == "string" and jev.endpoint ~= "" then
    fields[#fields + 1] = "endpoint=" .. scope_endpoint(jev.endpoint)
  end
  local q = scope_questions(jev.questions, templates, hash)
  if q then fields[#fields + 1] = "questions=" .. q end
  return "fp:" .. tostring(hash(table.concat(fields, "\n"))):sub(1, 16) .. ":" .. fp
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
local function plan(req, cfg, hash, rule, text, windowed, chunks, capped, untrusted, tools, retrieved)
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
  -- the text holds retrieved content: not the subject's own (rep_of)
  if retrieved then p.rep = false end
  if not ((chunks and #chunks > 1) or untrusted or tools) then
    -- the score is for the window, not the whole text; the reason says so
    p.suffix = windowed and " (window)" or ""
    return p
  end
  local parts = {}
  -- the text only stands aside when it alone would have passed
  if not ((untrusted and untrusted.only) or (tools and tools.only)) then
    for _, c in ipairs((chunks and #chunks > 1) and chunks or { text }) do
      parts[#parts + 1] = { text = c, templates = rule.templates, context = p.context, rep = p.rep }
    end
  end
  local suffix = ""
  if chunks and #chunks > 1 then
    suffix = capped and " (window)" or (" (" .. #chunks .. " chunks" .. (windowed and ", window" or "") .. ")")
  elseif windowed or (untrusted and untrusted.windowed) or (tools and tools.windowed) then
    suffix = " (window)"
  end
  if untrusted then
    -- asked without the deployment context, the way the question was
    -- measured. Not the subject's own text: not charged to it (rep_of).
    parts[#parts + 1] = { text = untrusted.text, templates = uspec.templates,
      context = { path = req.path or "", method = req.method or "", deployment = "" },
      over = { templates = uspec.templates, deployment = "" }, rep = false }
  end
  if tools then
    -- the client sent them: the same question and scope as its own text,
    -- so the entry is the one any text like it gets. An agent loads them
    -- from servers the user may not control: not charged either (rep_of).
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
-- request into an error unless another part already blocks. A part whose
-- prompt cannot be built (a template judge does not know, which config
-- validation refuses) is logged and left out, and the others are judged:
-- the request is an error only when no part is left. Its score is then for
-- less than the whole request, and the whole request's entry is not written.
-- @param parts  list of { text, templates, context, over, label, rep } (over:
--               cache_key's; label: put before the template name in the
--               reason when this part's score decides; rep = false: not the
--               subject's own text (retrieved content, tool definitions, a
--               text that holds retrieved content), its score is not charged
--               to it)
-- @param suffix appended to the reason when a part answered
local function judge_parts(ctx, rule, parts, suffix, fp, ckey, reason)
  local cfg = ctx.config
  local scores, tops, pending = {}, {}, {}
  local left_out
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
      if prompt then
        pending[#pending + 1] = { i = i, prompt = prompt, ck = ck }
      else
        log(ctx, "error", "jev-edge: " .. perr .. " (that part is not judged)")
        left_out = left_out or perr
      end
    end
  end
  if #pending == 0 and next(scores) == nil then
    -- no part left to judge
    settle(ctx)
    local action, label, async = policy.on_error()
    return finish(ctx, verdict.new({ action = action, verdict = label, async = async,
      source = verdict.SRC_L2, reason = left_out, fingerprint = fp }))
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
  if ckey and ctx.cache and not left_out then
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
  local r, text, reason, rule, windowed, chunks, capped, untrusted, tools, retrieved =
    rules_mod.evaluate_all(req, ctx.rules, ctx)

  if r == rules_mod.PASS then
    return verdict.new({ verdict = verdict.SKIPPED, source = verdict.SRC_L1, reason = reason })
  end
  if r == rules_mod.UNJUDGEABLE then
    -- A watched request nobody read. Not judged, so `skipped`; blocked only
    -- when the operator chose that and the gateway enforces. For a prompt
    -- given as token ids the rule's token_prompts chooses, when it has one.
    local choice = cfg.policy.unjudgeable
    if reason == rules_mod.TOKEN_REASON then choice = rules_mod.token_prompts(rule, cfg.policy) end
    local block = cfg.policy.mode == "enforce" and choice == "block"
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

  local p = plan(req, cfg, ctx.hash, rule, text, windowed, chunks, capped, untrusted, tools, retrieved)
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
      -- none of this request's own text was judged alone: whatever the entry says
      if p.rep == false then rep = false end
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
    ctx.cache:set(ckey, { score = score, reason = why, rep = p.rep }, cfg.cache.fp_ttl)
  end

  return finish(ctx, verdict.new({
    action = action, verdict = label, score = score, async = async,
    source = verdict.SRC_L2, reason = why, fingerprint = fp, l2_ms = elapsed,
  }), p.rep)
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
-- @return nil when L1 no longer finds it suspect or no prompt can be
--         built; else { fingerprint, key (the whole request's cache key, or
--         nil), reason (L1's), suffix, parts = { { prompt, key, label, rep } } }.
--         A part of several whose prompt cannot be built is left out, as
--         judge_parts leaves it out, and key is then nil: an answer for the
--         rest is not one for the whole request.
function _M.l3_job(req, ctx)
  local cfg = ctx.config
  local r, text, reason, rule, windowed, chunks, capped, untrusted, tools, retrieved = rules_mod.evaluate_all(req,
    ctx.rules, { config = cfg, json_decode = ctx.json_decode, re_find = ctx.re_find, log = ctx.log })
  if r ~= rules_mod.SUSPECT then return nil end
  local p = plan(req, cfg, ctx.hash, rule, text, windowed, chunks, capped, untrusted, tools, retrieved)
  local job = { fingerprint = p.fp, key = p.key, reason = reason, suffix = p.suffix, parts = {} }
  -- one piece: its answer is the whole request's
  local parts = p.parts or { { text = text, templates = rule.templates, context = p.context, rep = p.rep } }
  for _, part in ipairs(parts) do
    local prompt = judge.build(part.templates, part.text, part.context)
    if prompt then
      local key = p.key
      if p.parts then
        local cfp = normalize.fingerprint(part.text, { prefix_bytes = cfg.cache.fp_prefix_bytes }, ctx.hash)
        key = cfp ~= "" and _M.cache_key(cfp, rule, cfg, ctx.hash, part.over) or nil
      end
      job.parts[#job.parts + 1] = { prompt = prompt, key = key, label = part.label, rep = part.rep }
    elseif p.parts then
      job.key = nil
    end
  end
  if #job.parts == 0 then return nil end
  return job
end

--- What L3's answers make of a job: the highest part score and its verdict
-- and reason (as L2 would have given them), the label reputation charges
-- (that of the subject's own text, never retrieved content or tool
-- definitions; see rep_of), and the cache writes.
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
