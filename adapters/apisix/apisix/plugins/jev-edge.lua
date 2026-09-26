-- apisix/plugins/jev-edge.lua
-- jev-edge as an Apache APISIX plugin. Same core, same OpenResty modules
-- (cache, provider HTTP client, breaker, L3 timer); what this file adds is
-- the APISIX plugin contract (schema, phases, per-route config) and the
-- mapping from APISIX's request API to core's `req` table.
--
-- Install: put the repo on the Lua path and declare the shared dict:
--
--   # conf/config.yaml
--   apisix:
--     extra_lua_path: "/opt/jev-edge/adapters/apisix/?.lua;/opt/jev-edge/adapters/openresty/lib/?.lua;
--                      /opt/jev-edge/?.lua"   (one line, no spaces)
--   plugins:
--     - jev-edge
--     - ...
--   nginx_config:
--     http:
--       lua_shared_dict:
--         jev_cache: 64m
--       # `env TYPESAFE_API_KEY;` is `nginx_config.envs: [TYPESAFE_API_KEY]`
--     envs:
--       - TYPESAFE_API_KEY
--
-- then enable it on a route, service or globally with the same keys as the
-- Lua config file: jev, rules, policy, cache, breaker, async.

require("resty.jev.loader")()

local core      = require("apisix.core")
local jev_core  = require("jev.core")
local defaults  = require("jev.core.defaults")
local verdict   = require("jev.core.verdict")
local breaker_m = require("jev.core.breaker")
local cache_m   = require("resty.jev.cache")
local http      = require("resty.jev.http")
local async     = require("resty.jev.async")
local rules_mod = require("jev.core.rules")
local body_m    = require("resty.jev.body")
local sampling  = require("jev.core.sampling")
local subject_m = require("jev.core.subject")
local cjson     = require("cjson.safe")
local sha256    = require("resty.sha256")
local to_hex    = require("resty.string").to_hex

local DICT = "jev_cache"
local SUBJECT_DICT = "jev_subject"
local HEADER_NAMES = { "X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id" }

local schema = {
  type = "object",
  properties = {
    jev = {
      type = "object",
      properties = {
        provider           = { type = "string", enum = { "jev", "openai-compat", "mock" }, default = "jev" },
        endpoint           = { type = "string" },
        model              = { type = "string" },
        api_key            = { type = "string" },
        api_key_env        = { type = "string", default = "TYPESAFE_API_KEY" },
        deployment_context = { type = "string" },
        timeout_ms         = { type = "integer", minimum = 1 },
        timeout_max_ms     = { type = "integer", minimum = 1 },
        timeout_adaptive   = { type = "boolean" },
        max_inflight       = { type = "integer", minimum = 1 },
        -- mock provider knobs, for tests
        mock_score         = { type = "number", minimum = 0, maximum = 1 },
        mock_header        = { type = "string" },
        mock_delay_ms      = { type = "integer", minimum = 0 },
        mock_fail_ratio    = { type = "number", minimum = 0, maximum = 1 },
      },
    },
    rules = {
      type = "array", minItems = 1, default = { "llm-endpoints" },
      items = { anyOf = {
        { type = "string" },
        { type = "object", properties = { id = { type = "string" } } },
      } },
      description = "rule set ids under rules/, or inline rules "
        .. "({ id, extends, watch_paths, deployment_context, ... })",
    },
    subject = {
      type = "object",
      properties = {
        enabled     = { type = "boolean" },
        from        = { type = "string", enum = { "ip", "header", "cookie" } },
        name        = { type = "string" },
        salt        = { type = "string" },
        hashed      = { type = "boolean" },
        history_ttl = { type = "number", minimum = 1 },
        max_entries = { type = "integer", minimum = 1 },
      },
    },
    sampling = {
      type = "object",
      properties = {
        enabled     = { type = "boolean" },
        rate        = { type = "number", minimum = 0, maximum = 1 },
        min_verdict = { type = "string", enum = { "safe", "suspicious", "malicious" } },
        max_samples = { type = "integer", minimum = 1 },
        ttl         = { type = "number", minimum = 0 },
        text_bytes  = { type = "integer", minimum = 1 },
        log         = { type = "boolean" },
      },
    },
    policy = {
      type = "object",
      properties = {
        mode              = { type = "string", enum = { "monitor", "enforce" } },
        block_threshold   = { type = "number", minimum = 0, maximum = 1 },
        suspect_threshold = { type = "number", minimum = 0, maximum = 1 },
        block_status      = { type = "integer", minimum = 400, maximum = 499 },
        block_body        = { type = "string" },
      },
    },
    -- retrieved content judged on its own (core/defaults.lua `untrusted`)
    untrusted = {
      type = "object",
      properties = {
        enabled      = { type = "boolean" },
        tool_results = { type = "boolean" },
        fields       = { type = "array", items = { type = "string", minLength = 1 } },
        templates    = { type = "array", minItems = 1,
                         items = { type = "string", enum = { "untrusted", "injection", "abuse" } } },
      },
    },
    cache = {
      type = "object",
      properties = {
        fp_ttl          = { type = "number", minimum = 0 },
        rep_ttl         = { type = "number", minimum = 0 },
        fp_prefix_bytes = { type = "integer", minimum = 1 },
      },
    },
    breaker = {
      type = "object",
      properties = {
        window_s    = { type = "number", minimum = 1 },
        min_samples = { type = "integer", minimum = 1 },
        fail_ratio  = { type = "number", minimum = 0, maximum = 1 },
        open_s      = { type = "number", minimum = 0 },
      },
    },
    async = {
      type = "object",
      properties = {
        enabled         = { type = "boolean" },
        max_async       = { type = "integer", minimum = 0 },
        rep_block_after = { type = "integer", minimum = 0 },
        rep_block_ttl   = { type = "number", minimum = 0 },
      },
    },
  },
}

local _M = {
  version  = 0.1,
  priority = 2450,   -- after auth plugins (2500+), before proxy-rewrite (1008) and the AI plugins
  name     = "jev-edge",
  schema   = schema,
}

-- A shipped rule set by id. The id names a module, so only a plain name is
-- looked up (as the Kong schema allows): anything else is an error, never a
-- require of a table or a path.
local function load_rule(id)
  if type(id) ~= "string" or not id:match("^[%w_%-]+$") then
    return nil, "rule set id must be a name of letters, digits, '_' or '-', got " .. tostring(id)
  end
  local ok, r = pcall(require, "jev.rules." .. id)
  if ok then return r end
  -- the require error lists every searched path; the id is what matters
  return nil, "rule set '" .. id .. "' not found (jev.rules." .. id .. ")"
end

function _M.check_schema(conf)
  local ok, err = core.schema.check(schema, conf)
  if not ok then return false, err end
  local merged = defaults.merge(defaults.config, conf)
  local vok, verr = defaults.validate(merged)
  if not vok then return false, verr end
  -- the rules as a request would load them: a typo'd id, an unknown
  -- template or a malformed pattern is refused here, where the Admin API
  -- (or the standalone loader) reports it, instead of being dropped at run
  -- time and turning judging off for the route
  local _, rerr = rules_mod.resolve_all(merged.rules, load_rule)
  if rerr then return false, rerr end
  return true
end

-- ---------------------------------------------------------------------------
-- runtime per plugin conf (APISIX hands the same conf table to every request
-- of a route until the route changes, so identity is the cache key)
-- ---------------------------------------------------------------------------

local runtimes = setmetatable({}, { __mode = "k" })
local cache
local subject_store

-- SHA-256 for fingerprints and subject ids, the same as the OpenResty adapter
-- and the JavaScript hosts: a collision-resistant fingerprint (it keys the
-- verdict cache and the trust store) and one trajectory per user whichever
-- adapter saw them.
local function sha256_hex(s)
  local h = sha256:new()
  h:update(s)
  return to_hex(h:final())
end
local sha256_hex_subject = sha256_hex

local function subject_ctx(rt, req)
  local scfg = rt.cfg.subject
  if not scfg or not scfg.enabled then return nil end
  -- the raw Cookie header(s), not the cookie variable: nginx's $cookie_<name>
  -- is the first match, compared case-insensitively, quotes kept, while the
  -- backend may read another. Every candidate is an id (core/subject.lua
  -- cookie_values); reputation checks and charges each, ids[1] names the
  -- trajectory and the logs.
  local ids = subject_m.hash_ids(scfg, subject_m.extract_all(scfg, {
    ip = req.client_ip,
    header = function(n) return req.headers[n] end,
    cookie_header = req.headers["cookie"],
  }), sha256_hex_subject)
  local id = ids[1]
  if not id then return nil end
  subject_store = subject_store or cache_m.new(SUBJECT_DICT)
  local store = subject_store
  return {
    id = id,
    ids = ids,
    history = subject_m.ring_load(store, id, scfg.max_entries),
    -- Two atomic dict operations, inline: cheaper than the timer it
    -- replaces and safe across workers (no read-modify-write).
    record = function(e)
      subject_m.ring_append(store, id, e, scfg.max_entries, scfg.history_ttl)
    end,
    -- reputation counters (subject.reputation): incr is atomic in the dict
    store = store,
  }
end

local function load_rules(specs)
  local out = {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, load_rule)
    if rule then out[#out + 1] = rule
    else core.log.error("jev-edge: rules[", i, "] failed to load: ", tostring(err)) end
  end
  return out
end

-- The rule core judged with (path, method and content type all match; a
-- json_only_paths path on what the decoder makes of the body).
local function rule_for(rt, req)
  return rules_mod.rule_for(req, rt.rules, { json_decode = cjson.decode })
end

-- Decision sampling into the shared dict ring; read it with
-- `resty.jev.edge.samples()` on the OpenResty side or through sampling.log.
local function maybe_sample(rt, v, req, ctx)
  if not sampling.should_sample(rt.cfg, v, math.random) then return end
  local ok, err = pcall(function()
    local s = sampling.build(rt.cfg, v, req, rule_for(rt, req),
      { rid = ctx.var.request_id, ts = ngx.now(), json_decode = cjson.decode })
    sampling.store(rt.cfg, cache, s)
    if rt.cfg.sampling.log then core.log.info("jev-edge sample: ", cjson.encode(s)) end
  end)
  if not ok then core.log.warn("jev-edge: sampling failed: ", err) end
end

local function runtime_for(conf)
  local rt = runtimes[conf]
  if rt then return rt end
  local cfg = defaults.merge(defaults.config, conf)
  if not cfg.jev.api_key and cfg.jev.provider ~= "mock" and cfg.jev.api_key_env then
    cfg.jev.api_key = os.getenv(cfg.jev.api_key_env)
    if not cfg.jev.api_key then
      core.log.warn("jev-edge: env ", cfg.jev.api_key_env, " is empty (add it to nginx_config.envs in config.yaml)")
    end
  end
  cache = cache or cache_m.new(DICT)
  -- Breaker, adaptive timeout and in-flight counters describe one provider,
  -- not the whole gateway: routes that call the same provider, endpoint and
  -- model share them, a route with another provider (or a broken key on a
  -- different endpoint) gets its own, so one cannot trip the other's breaker.
  local st = cache:prefixed("p:" .. sha256_hex(table.concat({
    tostring(cfg.jev.provider or ""), tostring(cfg.jev.endpoint or ""), tostring(cfg.jev.model or ""),
  }, "\n")):sub(1, 12) .. ":")
  local judge, err = http.new(cfg.jev, st)
  if not judge then
    core.log.error("jev-edge: ", err)
    judge = { call = function() return nil, err end }
  end
  rt = {
    cfg = cfg, rules = load_rules(cfg.rules), judge = judge, state = st,
    breaker = breaker_m.new(st, ngx.now, cfg.breaker),
  }
  runtimes[conf] = rt
  return rt
end

-- ---------------------------------------------------------------------------
-- request mapping
-- ---------------------------------------------------------------------------

local function build_req(rt, ctx)
  -- 0 = no limit: past the default 100 the rest are dropped, and a
  -- Content-Type sent after 100 junk headers would read as absent.
  local headers = ngx.req.get_headers(0)
  local req = {
    method    = core.request.get_method(),
    path      = ctx.var.uri,
    headers   = headers,
    client_ip = core.request.get_remote_client_ip(ctx),
    body      = nil,
    body_size = tonumber(headers["content-length"]) or 0,
  }
  -- whole up to max_body_bytes, head and tail past it, decoded (resty.jev.body)
  local max = 0
  for _, r in ipairs(rt.rules) do
    if rules_mod.path_matches(req.path, r.watch_paths, r.paths_case_sensitive) then
      max = math.max(max, r.max_body_bytes or rules_mod.MAX_BODY_BYTES)
    end
  end
  if max > 0 then body_m.fill(req, max) end
  return req
end

-- the byte span of the match, which places the hit in the judging window
local function re_find(subject, pattern)
  return ngx.re.find(subject, pattern, "ijo")
end

local function maybe_async(rt, v, req)
  if not v.async then return end
  -- L3 exists to get an answer L2 could not; while the breaker is open the
  -- provider is the reason, and hammering it from timers only keeps it open.
  if rt.breaker:state() ~= breaker_m.CLOSED then return end
  -- the parts L2 judged, their prompts and cache keys (core.l3_job): never a
  -- whole-request cache entry for less than the whole request
  local job = jev_core.l3_job(req, { config = rt.cfg, rules = rt.rules, hash = sha256_hex,
                                     json_decode = cjson.decode, re_find = re_find })
  if not job then return end
  async.schedule({ cfg = rt.cfg, cache = cache, state = rt.state, judge = rt.judge, job = job,
    client_ip = req.client_ip })
end

-- ---------------------------------------------------------------------------
-- phases
-- ---------------------------------------------------------------------------

function _M.access(conf, ctx)
  -- the client's own X-Jev-* go first, whatever happens next
  for _, h in ipairs(HEADER_NAMES) do core.request.set_header(ctx, h, nil) end

  local rt, v
  local ok, err = pcall(function()
    -- inside the pcall: a conf that fails to build a runtime fails open,
    -- as any other adapter error does, instead of a 500 for every request
    rt = runtime_for(conf)
    local req = build_req(rt, ctx)
    local subj = subject_ctx(rt, req)
    ctx.jev_subject = subj and subj.id or nil
    v = jev_core.evaluate(req, {
      config = rt.cfg, rules = rt.rules, cache = cache, trust = cache, judge = rt.judge, breaker = rt.breaker,
      subject = subj,
      clock = ngx.now, hash = sha256_hex,
      json_decode = cjson.decode, re_find = re_find,
      log = function(level, msg) if level == "error" then core.log.error(msg) else core.log.warn(msg) end end,
    })
    maybe_async(rt, v, req)
    maybe_sample(rt, v, req, ctx)
  end)

  if not ok then
    core.log.error("jev-edge: access error, failing open: ", err)
    core.request.set_header(ctx, "X-Jev-Verdict", verdict.ERROR)
    core.request.set_header(ctx, "X-Jev-Source", "adapter")
    return
  end

  ctx.jev = v
  for k, val in pairs(verdict.headers(v)) do core.request.set_header(ctx, k, val) end
  core.request.set_header(ctx, "X-Jev-Request-Id", ctx.var.request_id or "")

  if v.action == verdict.ACTION_BLOCK then
    -- the client sees the verdict and the request id, never the score, the
    -- reason or the source (verdict.client_headers): those go to the log
    core.response.set_header("Content-Type", "application/json")
    for k, val in pairs(verdict.client_headers(v)) do core.response.set_header(k, val) end
    core.response.set_header("X-Jev-Request-Id", ctx.var.request_id or "")
    return rt.cfg.policy.block_status or 403, rt.cfg.policy.block_body or '{"error":"request rejected"}'
  end
end

--- `$jev_log` for APISIX's logger plugins (http-logger, file-logger, ...):
-- the same JSON object the OpenResty adapter writes, registered as a
-- custom variable so `log_format: { jev: "$jev_log" }` works.
function _M.init()
  core.ctx.register_var("jev_log", function(ctx)
    local v = ctx.jev
    if not v then return "" end
    return cjson.encode({
      ts = ngx.now(), rid = ctx.var.request_id, path = ctx.var.uri, ip = ctx.var.remote_addr,
      src = v.source, score = v.score, verdict = v.verdict, action = v.action,
      l2_ms = v.l2_ms, fp = v.fingerprint, reason = v.reason, subject = ctx.jev_subject,
    })
  end)
end

return _M
