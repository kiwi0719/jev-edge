-- core/defaults.lua
-- Default configuration and a deep-merge helper.

local normalize = require "jev.core.normalize"
local judge     = require "jev.core.judge"

local _M = {}

_M.config = {
  jev = {
    provider    = "jev",
    model       = "jev-latest",
    timeout_ms       = 400,   -- floor and cold-start value
    timeout_max_ms   = 1000,  -- ceiling the adaptive estimate may reach
    timeout_headroom = 1.5,   -- multiplier over observed mean + 2 sd
    timeout_adaptive = true,
    max_inflight = 64,
  },
  rules  = { "llm-endpoints" },
  client_ip = {
    -- How adapters that sit behind another proxy (authz, forward-auth) find
    -- the client address in X-Forwarded-For. Proxies APPEND to the header,
    -- so the client's own value is on the left and the one your proxy added
    -- is on the right: `trusted_hops = 1` takes the last element, 2 the one
    -- before it (a load balancer in front of the gateway), and so on. Never
    -- the first element: that is whatever the client typed.
    trusted_hops = 1,
  },
  policy = {
    mode              = "monitor",
    block_threshold   = 0.7,
    suspect_threshold = 0.5,
    block_status      = 403,
    block_body        = '{"error":"request rejected"}',
    -- A watched request L1 cannot read (an encoding the adapter could not
    -- decode, a binary body, declared JSON the decoder refused with no text
    -- in it, or an oversized one with no text in the part the adapter
    -- has): "pass" forwards it as `skipped` with reason
    -- "unjudgeable: ...", "block" rejects it in enforce mode. Normal SDKs
    -- send none of these; "block" is the stricter choice once you are sure.
    unjudgeable       = "pass",
    -- A body the gateway in front cut before handing it over (Envoy's
    -- allow_partial_message, HAProxy past tune.bufsize; the request's
    -- `body_partial`): "judge" scans the part it has as the head of a larger
    -- body, and what was cut off is never read; "unjudgeable" reports the
    -- request unjudgeable instead, so policy.unjudgeable decides.
    -- "unjudgeable" makes the gateway's flag (x-envoy-auth-partial-body,
    -- X-Jev-Body-Partial) mean "do not judge": a flag a client can set
    -- itself then skips judging whenever policy.unjudgeable = "pass". Use it
    -- with unjudgeable = "block", where a forged flag only refuses the
    -- client's own request, and only behind a relay that drops a client's
    -- copy of the flag (docs/recipes.md, "Bodies past maxRequestBytes").
    partial           = "judge",
  },
  cache = {
    fp_ttl          = 300,
    rep_ttl         = 600,
    fp_prefix_bytes = 2048,   -- since 0.3.1: only bounds sampled/logged text; the
                              -- fingerprint always covers the whole normalized text
  },
  async = {
    enabled         = true,
    max_async       = 32,
    rep_block_after = 0,      -- 0 = never block by reputation; N = block an IP after N
                              -- malicious verdicts. Off by default: one NAT or carrier
                              -- IP can hide thousands of users.
    rep_block_ttl   = 600,
  },
  sampling = {
    enabled     = false,     -- keep a sample of decisions for replay and labelling
    rate        = 0.05,      -- share of eligible decisions kept
    min_verdict = "suspicious", -- "safe" | "suspicious" | "malicious": keep this label and above
    max_samples = 1000,      -- ring size in the cache dict
    ttl         = 86400,     -- seconds a sample stays readable
    text_bytes  = 512,       -- normalized text kept per sample (never the raw body)
    log         = false,     -- also write each sample as one JSON line at INFO
  },
  subject = {
    -- Who is the subject of a trajectory. Off by default; "ip" needs nothing
    -- else, "header" / "cookie" take `name`. The raw value is a credential
    -- (API key, session id) and is never stored: adapters hash it with `salt`
    -- before core, the store, the log or a sample ever see it. `hashed = true`
    -- says the value already is a hash (a thin Worker forwarding X-Jev-Subject).
    enabled      = false,
    from         = "ip",       -- "ip" | "header" | "cookie"
    name         = nil,        -- header or cookie name for "header" / "cookie"
    salt         = nil,        -- per-deployment secret mixed into the hash; required unless hashed
    hashed       = false,
    history_ttl  = 3600,       -- seconds a subject's trajectory stays readable
    max_entries  = 20,         -- entries kept per subject; older ones drop
    -- Subject reputation (core/subject.lua): judged verdicts add points over a
    -- sliding window_s; at block_at points the subject is blocked at L1 for
    -- block_ttl seconds. block_at = 0 is off. Pick block_at with
    -- `make calibrate` from monitor-mode logs (it reports points per subject).
    reputation = {
      block_at   = 0,
      window_s   = 600,
      block_ttl  = 600,
      suspicious = 1,          -- points per suspicious verdict
      malicious  = 3,          -- points per malicious verdict
    },
    -- Trajectories live in their own dict (`jev_subject`), sized by the
    -- operator: a scraper with a million sessions can fill it, and when it
    -- does only trajectories are evicted, never verdicts or trust.
  },
  feedback = {
    -- False-positive loop: an operator marks a request "not an attack" and its
    -- fingerprint is trusted from then on. Off by default; turning it on means
    -- accepting that a POST can create a bypass, so /_jev/feedback also needs
    -- a token (see the adapter config).
    enabled      = false,
    trust_ttl    = 604800,   -- 7 days. Trust always expires: a permanent entry
                             -- is a bypass nobody reviews again.
    max_renewals = 4,        -- times traffic or a repeat report may extend it
                             -- (~5 weeks total), then it must expire. A template
                             -- still firing by then is a rule bug, not a label.
    token        = nil,      -- shared secret for POST /_jev/feedback; without it
                             -- the endpoint refuses every request.
  },
  breaker = {
    window_s    = 60,
    min_samples = 20,
    fail_ratio  = 0.5,
    open_s      = 30,
  },
  -- Retrieved content judged on its own. Off by default. On, the text an app
  -- fetched for its assistant (tool results, and the `fields` below) is also
  -- sent to the judge in a parallel call with the `untrusted` question,
  -- without the deployment context, and the request gets the higher of the
  -- two scores. Costs one more provider call per request that carries such
  -- content. The whole-text judgment is unchanged. A rule's own `untrusted`
  -- table overrides these keys for that rule. Measured in bench/suite
  -- (README, "Experiment: judging retrieved content on its own").
  untrusted = {
    enabled      = false,
    -- OpenAI `role: "tool"` / `"function"` messages, Anthropic `tool_result`
    -- content blocks, Responses API `*_call_output` and `mcp_call` items and
    -- `file_search_call` results, Gemini `functionResponse` parts, and
    -- retrieved `documents` (Cohere, vLLM): core/normalize.lua tool_results
    tool_results = true,
    -- JSON paths (text_fields syntax) whose values are retrieved content the
    -- app sends outside a tool message, e.g. { "context", "sources[*].text" }.
    -- Retrieved text pasted into the user's message cannot be told apart.
    fields       = {},
    templates    = { "untrusted" },
  },
}

--- The untrusted-content settings for `rule`: config.untrusted with the
-- rule's own `untrusted` table over it.
function _M.untrusted_spec(cfg, rule)
  local base = (cfg and cfg.untrusted) or _M.config.untrusted
  local over = rule and rule.untrusted
  if type(over) ~= "table" then return base end
  local out = {}
  for k, v in pairs(base) do out[k] = v end
  for k, v in pairs(over) do out[k] = v end
  return out
end

--- True when `t` is a list: a table whose keys are exactly 1..#t (an empty
-- table is one). A JSON object is not, nor is JSON null (cjson.null).
function _M.is_list(t)
  if type(t) ~= "table" then return false end
  local n, count = #t, 0
  for k in pairs(t) do
    if type(k) ~= "number" or k < 1 or k > n or k % 1 ~= 0 then return false end
    count = count + 1
  end
  return count == n
end

--- Why `v` is not a list of non-empty strings (`nonempty`: with one at
-- least), or nil.
function _M.string_list_error(v, what, nonempty)
  if not _M.is_list(v) then return what .. " must be a list of strings" end
  if nonempty and #v == 0 then return what .. " must not be empty" end
  for i, s in ipairs(v) do
    if type(s) ~= "string" or s == "" then return what .. "[" .. i .. "] must be a non-empty string" end
  end
  return nil
end

--- Why `v` is not a list of template names judge knows, or nil: a rule's
-- templates (core/rules.lua resolve) and untrusted.templates. A name
-- judge.build cannot find turns every request judged with it into an L2
-- error, which fails open.
function _M.templates_error(v, what)
  local err = _M.string_list_error(v, what, true)
  if err then return err end
  for i, name in ipairs(v) do
    if not judge.get(name) then return what .. "[" .. i .. "] " .. name .. " is not a template" end
  end
  return nil
end

--- Type check for an untrusted table (config section or a rule's override).
function _M.validate_untrusted(u, where)
  if u == nil then return true end
  if type(u) ~= "table" then return nil, where .. " must be a table" end
  for _, k in ipairs({ "enabled", "tool_results" }) do
    if u[k] ~= nil and type(u[k]) ~= "boolean" then return nil, where .. "." .. k .. " must be true|false" end
  end
  if u.fields ~= nil then
    local err = _M.string_list_error(u.fields, where .. ".fields")
    if err then return nil, err end
    -- a field path is checked the way a rule's text_fields are
    for i, v in ipairs(u.fields) do
      local perr = normalize.path_error(v)
      if perr then return nil, where .. ".fields[" .. i .. "] " .. perr end
    end
  end
  -- a name judge does not know makes every request with retrieved content
  -- an L2 error, the whole-text judgment included
  if u.templates ~= nil then
    local err = _M.templates_error(u.templates, where .. ".templates")
    if err then return nil, err end
  end
  return true
end

local function is_list(t)
  return type(t) == "table" and #t > 0 and next(t, #t) == nil
end

--- Deep-merge `over` onto a copy of `base`. Lists are replaced, not merged.
function _M.merge(base, over)
  local out = {}
  for k, v in pairs(base or {}) do
    out[k] = (type(v) == "table" and not is_list(v)) and _M.merge(v, nil) or v
  end
  for k, v in pairs(over or {}) do
    if type(v) == "table" and not is_list(v) and type(out[k]) == "table" and not is_list(out[k]) then
      out[k] = _M.merge(out[k], v)
    else
      out[k] = v
    end
  end
  return out
end

--- Validate a merged config. Returns true or nil, err.
function _M.validate(c)
  local p = c.policy or {}
  if p.mode ~= "monitor" and p.mode ~= "enforce" then
    return nil, "policy.mode must be monitor|enforce"
  end
  if type(p.block_threshold) ~= "number" or type(p.suspect_threshold) ~= "number" then
    return nil, "policy thresholds must be numbers"
  end
  if p.suspect_threshold > p.block_threshold then
    return nil, "policy.suspect_threshold must be <= block_threshold"
  end
  if p.block_threshold > 1 or p.suspect_threshold < 0 then
    return nil, "policy thresholds must be in [0,1]"
  end
  if p.unjudgeable ~= nil and p.unjudgeable ~= "pass" and p.unjudgeable ~= "block" then
    return nil, "policy.unjudgeable must be pass|block"
  end
  if p.partial ~= nil and p.partial ~= "judge" and p.partial ~= "unjudgeable" then
    return nil, "policy.partial must be judge|unjudgeable"
  end
  -- the adapters write it as the block response's body: a table (a JSON
  -- object where a JSON document encoded as a string belongs) or JSON null
  -- turned every block into a 500, which a relay's failure mode allows
  if p.block_body ~= nil and type(p.block_body) ~= "string" then
    return nil, "policy.block_body must be a string"
  end
  if p.block_status ~= nil and (type(p.block_status) ~= "number"
     or p.block_status < 200 or p.block_status > 599 or p.block_status % 1 ~= 0) then
    return nil, "policy.block_status must be an HTTP status code"
  end
  local ca = c.cache or {}
  if ca.fp_ttl ~= nil and (type(ca.fp_ttl) ~= "number" or ca.fp_ttl <= 0) then
    return nil, "cache.fp_ttl must be > 0"
  end
  if ca.rep_ttl ~= nil and (type(ca.rep_ttl) ~= "number" or ca.rep_ttl <= 0) then
    return nil, "cache.rep_ttl must be > 0"
  end
  local br = c.breaker or {}
  for _, k in ipairs({ "window_s", "open_s" }) do
    if br[k] ~= nil and (type(br[k]) ~= "number" or br[k] <= 0) then
      return nil, "breaker." .. k .. " must be > 0"
    end
  end
  if br.min_samples ~= nil and (type(br.min_samples) ~= "number" or br.min_samples < 1) then
    return nil, "breaker.min_samples must be >= 1"
  end
  if br.fail_ratio ~= nil and (type(br.fail_ratio) ~= "number" or br.fail_ratio <= 0 or br.fail_ratio > 1) then
    return nil, "breaker.fail_ratio must be in (0,1]"
  end
  local ci = c.client_ip or {}
  local hops = ci.trusted_hops
  if hops ~= nil and (type(hops) ~= "number" or hops < 1 or hops % 1 ~= 0) then
    return nil, "client_ip.trusted_hops must be an integer >= 1"
  end
  local as = c.async or {}
  if as.max_async ~= nil and (type(as.max_async) ~= "number" or as.max_async < 0) then
    return nil, "async.max_async must be >= 0"
  end
  if type(c.jev.timeout_ms) ~= "number" or c.jev.timeout_ms <= 0 then
    return nil, "jev.timeout_ms must be > 0"
  end
  -- the judge is built from these on the request path (ensure_runtime), where
  -- a table or JSON null (cjson.null) threw and failed every request open
  for _, k in ipairs({ "provider", "model", "endpoint", "api_key", "api_key_env", "deployment_context" }) do
    if c.jev[k] ~= nil and type(c.jev[k]) ~= "string" then
      return nil, "jev." .. k .. " must be a string"
    end
  end
  if c.jev.provider == "" then return nil, "jev.provider must be a non-empty string" end
  local sm = c.sampling or {}
  if sm.rate ~= nil and (type(sm.rate) ~= "number" or sm.rate < 0 or sm.rate > 1) then
    return nil, "sampling.rate must be in [0,1]"
  end
  if sm.max_samples ~= nil and (type(sm.max_samples) ~= "number" or sm.max_samples < 1) then
    return nil, "sampling.max_samples must be >= 1"
  end
  local mv = sm.min_verdict
  if mv ~= nil and mv ~= "safe" and mv ~= "suspicious" and mv ~= "malicious" then
    return nil, "sampling.min_verdict must be safe|suspicious|malicious"
  end
  local sj = c.subject or {}
  if sj.from ~= nil and sj.from ~= "ip" and sj.from ~= "header" and sj.from ~= "cookie" then
    return nil, "subject.from must be ip|header|cookie"
  end
  if sj.enabled == true then
    if (sj.from == "header" or sj.from == "cookie") and (type(sj.name) ~= "string" or sj.name == "") then
      return nil, "subject.from = " .. sj.from .. " needs subject.name"
    end
    if not sj.hashed and (type(sj.salt) ~= "string" or sj.salt == "") then
      return nil, "subject.enabled needs subject.salt (or hashed = true)"
    end
  end
  if sj.max_entries ~= nil and (type(sj.max_entries) ~= "number" or sj.max_entries < 1) then
    return nil, "subject.max_entries must be >= 1"
  end
  local sr = sj.reputation or {}
  for _, k in ipairs({ "block_at", "suspicious", "malicious" }) do
    if sr[k] ~= nil and (type(sr[k]) ~= "number" or sr[k] < 0) then
      return nil, "subject.reputation." .. k .. " must be a number >= 0"
    end
  end
  for _, k in ipairs({ "window_s", "block_ttl" }) do
    if sr[k] ~= nil and (type(sr[k]) ~= "number" or sr[k] <= 0) then
      return nil, "subject.reputation." .. k .. " must be > 0"
    end
  end
  if (tonumber(sr.block_at) or 0) > 0 and not sj.enabled then
    return nil, "subject.reputation.block_at needs subject.enabled"
  end
  if sj.history_ttl ~= nil and (type(sj.history_ttl) ~= "number" or sj.history_ttl <= 0) then
    return nil, "subject.history_ttl must be > 0"
  end
  local fb = c.feedback or {}
  if fb.trust_ttl ~= nil and (type(fb.trust_ttl) ~= "number" or fb.trust_ttl <= 0) then
    return nil, "feedback.trust_ttl must be > 0"
  end
  if fb.max_renewals ~= nil and (type(fb.max_renewals) ~= "number" or fb.max_renewals < 0) then
    return nil, "feedback.max_renewals must be >= 0"
  end
  if fb.enabled == true and (fb.token == nil or fb.token == "") then
    return nil, "feedback.enabled needs feedback.token set"
  end
  -- per-provider question wording (providers/jev.lua): { [template] = { instructions = ..., ... } }
  local qs = c.jev.questions
  if qs ~= nil then
    if type(qs) ~= "table" then return nil, "jev.questions must be a table" end
    for name, q in pairs(qs) do
      if type(name) ~= "string" or type(q) ~= "table" then
        return nil, "jev.questions must map template names to tables"
      end
      for _, k in ipairs({ "instructions", "instructions_ctx" }) do
        if q[k] ~= nil and (type(q[k]) ~= "string" or q[k] == "") then
          return nil, "jev.questions." .. name .. "." .. k .. " must be a non-empty string"
        end
      end
      for _, k in ipairs({ "criteria", "criteria_ctx" }) do
        if q[k] ~= nil and type(q[k]) ~= "table" then
          return nil, "jev.questions." .. name .. "." .. k .. " must be a table"
        end
      end
    end
  end
  local max_ms = c.jev.timeout_max_ms
  if max_ms ~= nil and (type(max_ms) ~= "number" or max_ms < c.jev.timeout_ms) then
    return nil, "jev.timeout_max_ms must be >= timeout_ms"
  end
  local uok, uerr = _M.validate_untrusted(c.untrusted, "untrusted")
  if not uok then return nil, uerr end
  return true
end

return _M
