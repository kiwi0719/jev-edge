-- apisix/plugins/jev-edge.lua
-- jev-edge as an Apache APISIX plugin. Same core, same OpenResty modules
-- (cache, provider HTTP client, breaker, L3 timer); what this file adds is
-- the APISIX plugin contract (schema, phases, per-route config) and the
-- mapping from APISIX's request API to core's `req` table.
--
-- Install: put the repo on the Lua path and declare the shared dicts:
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
--       # custom_lua_shared_dict, not lua_shared_dict: APISIX renders only its
--       # own dicts from that key and drops anything else put there
--       custom_lua_shared_dict:
--         jev_cache: 64m
--         jev_subject: 16m        # with subject.enabled
--         jev_subject_rep: 4m     # with subject.reputation
--       # `env TYPESAFE_API_KEY;` is `nginx_config.envs: [TYPESAFE_API_KEY]`
--     envs:
--       - TYPESAFE_API_KEY
--
-- Without jev_cache there is no verdict cache, the breaker never opens and
-- max_inflight, max_async and reputation do nothing; the plugin logs an error
-- at startup when it is missing.
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
local SUBJECT_REP_DICT = "jev_subject_rep"   -- subject reputation, apart from the trajectories
local HEADER_NAMES = { "X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id" }

local schema = {
  type = "object",
  properties = {
    jev = {
      type = "object",
      properties = {
        provider           = { type = "string", enum = { "jev", "laya", "openai-compat", "mock" }, default = "jev" },
        endpoint           = { type = "string" },
        model              = { type = "string" },
        api_key            = { type = "string" },
        api_key_env        = { type = "string", default = "TYPESAFE_API_KEY" },
        deployment_context = { type = "string" },
        timeout_ms         = { type = "integer", minimum = 1 },
        timeout_max_ms     = { type = "integer", minimum = 1 },
        timeout_adaptive   = { type = "boolean" },
        max_inflight       = { type = "integer", minimum = 1 },
        ssl_verify         = { type = "boolean" },
        -- per-template question wording: { <template> = { instructions, criteria, ... } }
        questions          = { type = "object" },
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
        reputation  = {
          type = "object",
          properties = {
            block_at   = { type = "number", minimum = 0 },
            window_s   = { type = "number", exclusiveMinimum = 0 },
            block_ttl  = { type = "number", exclusiveMinimum = 0 },
            suspicious = { type = "number", minimum = 0 },
            malicious  = { type = "number", minimum = 0 },
          },
        },
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
        block_status      = { type = "integer", minimum = 200, maximum = 599 },
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
  -- Kept encrypted in etcd (apisix.data_encryption, on by default); APISIX
  -- decrypts them before the plugin sees conf. Either may also be an
  -- $env:// or $secret:// reference, resolved in runtime_for.
  encrypt_fields = { "jev.api_key", "subject.salt" },
}

-- Priority 1000, access phase (APISIX 3.13). Every rewrite-phase plugin runs
-- first, whatever its priority: the auth plugins (key-auth 2500, jwt-auth
-- 2510, basic-auth, openid-connect 2599, ...) and the ones that rewrite the
-- request (proxy-rewrite 1008, ai-prompt-decorator 1070, ai-prompt-template
-- 1071, body-transformer 1080), so the judged request is the one they made.
-- Of the access-phase plugins, these run before jev-edge: consumer-restriction
-- (2400), forward-auth (2002), opa (2001), authz-keycloak (2000),
-- ai-prompt-guard (1072), ai-rate-limiting (1030) and limit-conn, limit-count
-- and limit-req (1001-1003). A request they refuse never costs a judge call
-- and never gets a verdict, as with the Kong plugin (905, after
-- rate-limiting). ai-proxy (1040) calls the model in before_proxy, after
-- every access handler, so it only ever sees an admitted request.
-- ai-request-rewrite (1073) calls its LLM in the access phase, before
-- jev-edge: to judge first, raise jev-edge above it with _meta.priority.
--
-- run_policy = "prefer_route": a global rule's instance is skipped for a
-- request whose route (with its service and plugin_config) has jev-edge of
-- its own, so the route's conf decides and the request is judged once. A
-- conf that comes from a consumer is merged after the global rules ran, and
-- two global rules can both carry the plugin: access() judges once per
-- request whatever reaches it (ctx.jev_ran).
local _M = {
  version    = 0.1,
  priority   = 1000,
  name       = "jev-edge",
  schema     = schema,
  run_policy = "prefer_route",
}

function _M.check_schema(conf)
  local ok, err = core.schema.check(schema, conf)
  if not ok then return false, err end
  local merged = defaults.merge(defaults.config, conf)
  local vok, verr = defaults.validate(merged)
  if not vok then return false, verr end
  return true
end

-- ---------------------------------------------------------------------------
-- runtime per plugin conf (APISIX hands the same conf table to every request
-- of a route until the route changes, so identity is the cache key)
-- ---------------------------------------------------------------------------

local runtimes = setmetatable({}, { __mode = "k" })
local cache

-- A dict the config needs and nginx.conf does not have: one error per worker
-- and dict, naming the key APISIX reads it from.
local missing_logged = {}
local function check_dict(name, why)
  if ngx.shared[name] or missing_logged[name] then return end
  missing_logged[name] = true
  core.log.error("jev-edge: lua_shared_dict ", name, " is not defined (", why, "); declare it under ",
    "nginx_config.http.custom_lua_shared_dict in config.yaml: APISIX ignores ",
    "nginx_config.http.lua_shared_dict")
end

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

local function subject_ctx(rt, req, ctx)
  local scfg = rt.cfg.subject
  if not scfg or not scfg.enabled then return nil end
  local raw = subject_m.extract(scfg, {
    ip = req.client_ip,
    header = function(n) return req.headers[n] end,
    cookie = function(n) return ctx.var["cookie_" .. tostring(n)] end,
  })
  local id = subject_m.hash_id(scfg, raw, sha256_hex_subject)
  if not id then return nil end
  local rep_on = type(scfg.reputation) == "table" and (tonumber(scfg.reputation.block_at) or 0) > 0
  local ring, rep = cache_m.subject_stores(SUBJECT_DICT, SUBJECT_REP_DICT, rep_on)
  return {
    id = id,
    history = subject_m.ring_load(ring, id, scfg.max_entries),
    -- Two atomic dict operations, inline: cheaper than the timer it
    -- replaces and safe across workers (no read-modify-write). They never
    -- evict: a full dict drops the new entry.
    record = function(e)
      subject_m.ring_append(ring, id, e, scfg.max_entries, scfg.history_ttl)
    end,
    -- reputation counters and blocks (subject.reputation): incr is atomic in the dict
    store = rep,
  }
end

local function load_rules(specs)
  local out = {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, function(id)
      local ok, r = pcall(require, "jev.rules." .. id)
      if ok then return r end
      return nil, tostring(r)
    end)
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

-- APISIX's secret references ($env://NAME, $secret://manager/id/key), when
-- this APISIX has them (3.x).
local fetch_secrets
do
  local ok, secret = pcall(require, "apisix.secret")
  if ok and type(secret) == "table" then fetch_secrets = secret.fetch_secrets end
end

-- conf with its $env:// and $secret:// references resolved: a copy, which
-- APISIX caches per conf table for five minutes and then reads again, so a
-- rotated secret is picked up within that. Without the secret module, or
-- when resolving throws, conf as it is.
local function resolved(conf)
  if not fetch_secrets then return conf end
  local ok, r = pcall(fetch_secrets, conf, true, conf, "")
  if ok and type(r) == "table" then return r end
  if not ok then core.log.error("jev-edge: resolving secret references failed: ", r) end
  return conf
end

local function is_ref(v)
  return type(v) == "string" and (v:sub(1, 7):upper() == "$ENV://" or v:sub(1, 10) == "$secret://")
end

-- The two referenceable fields as resolved now: the runtime is rebuilt when
-- they differ from the ones it was built from.
local function secrets(c)
  local j, s = c.jev, c.subject
  return type(j) == "table" and j.api_key or nil, type(s) == "table" and s.salt or nil
end

local function runtime_for(conf)
  local rconf = resolved(conf)
  local key, salt = secrets(rconf)
  local rt = runtimes[conf]
  if rt and rt.src_api_key == key and rt.src_salt == salt then return rt end
  local cfg = defaults.merge(defaults.config, rconf)
  -- a reference APISIX could not resolve (no such variable or secret) is
  -- never sent as the bearer token: no key, so api_key_env applies
  if is_ref(cfg.jev.api_key) then
    core.log.error("jev-edge: jev.api_key reference ", cfg.jev.api_key, " did not resolve")
    cfg.jev.api_key = nil
  end
  if cfg.subject and is_ref(cfg.subject.salt) then
    core.log.error("jev-edge: subject.salt reference ", cfg.subject.salt, " did not resolve")
  end
  if not cfg.jev.api_key and cfg.jev.provider ~= "mock" and cfg.jev.api_key_env then
    cfg.jev.api_key = os.getenv(cfg.jev.api_key_env)
    if not cfg.jev.api_key then
      core.log.warn("jev-edge: env ", cfg.jev.api_key_env, " is empty (add it to nginx_config.envs in config.yaml)")
    end
  end
  if cfg.subject and cfg.subject.enabled then
    check_dict(SUBJECT_DICT, "subject.enabled: no trajectories, no subject reputation")
  end
  cache = cache or cache_m.new(DICT)
  -- Breaker, adaptive timeout and in-flight counter: shared by the routes
  -- and consumers that call the same provider, endpoint and model with the
  -- same key, max_inflight and breaker settings (resty.jev.http
  -- state_prefix), and only by them: a conf whose key is revoked or over
  -- quota, or whose breaker is tuned to trip early, opens its own breaker.
  local st = cache:prefixed(http.state_prefix(cfg, sha256_hex))
  local judge, err = http.new(cfg.jev, st)
  if not judge then
    core.log.error("jev-edge: ", err)
    judge = { call = function() return nil, err end }
  end
  rt = {
    cfg = cfg, rules = load_rules(cfg.rules), judge = judge, state = st,
    breaker = breaker_m.new(st, ngx.now, cfg.breaker),
    src_api_key = key, src_salt = salt,
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

-- The X-Jev-* request headers as this request's verdict set them; a name
-- the table does not hold is removed.
local function set_request_headers(ctx, headers)
  for _, h in ipairs(HEADER_NAMES) do core.request.set_header(ctx, h, headers and headers[h]) end
end

-- The subject header the config reads, lowercased: an X-Jev-* name there (a
-- thin Worker's X-Jev-Subject, read with hashed = true) is the deployment's
-- own and stays.
local function subject_header(scfg)
  if type(scfg) == "table" and scfg.from == "header" and type(scfg.name) == "string" then
    return scfg.name:lower()
  end
  return nil
end

-- Every other X-Jev-* request header, once judging has read what it needs
-- (the mock score header, a subject header). set_request_headers() handles
-- only the names jev-edge sets; X-Jev-Subject, X-Jev-Body-Partial or any
-- other X-Jev-* a client sent would reach the upstream as if jev-edge had
-- set it.
local function sweep_inbound(ctx, scfg)
  local keep = subject_header(scfg)
  local drop = {}
  for k in pairs(ngx.req.get_headers(0)) do
    if type(k) == "string" then
      local n = k:lower()
      if n:sub(1, 6) == "x-jev-" and n ~= keep then drop[#drop + 1] = n end
    end
  end
  for _, n in ipairs(drop) do core.request.set_header(ctx, n, nil) end
end

function _M.access(conf, ctx)
  -- A global rule also runs for a request that matched no route, just before
  -- APISIX answers it 404. It never reaches a model: no judge call, no
  -- reputation charge, no headers.
  if ctx.conf_type == "global_rule" and not ctx.matched_route then return end
  -- Judged once per request. A second run (a global rule's instance, then a
  -- consumer's conf; two global rules) is not a second L2 call, reputation
  -- charge, sample or L3 job: it puts back the headers of the verdict
  -- already reached (a plugin in between may have changed them), or the
  -- fail-open ones, and that verdict's block. The first verdict stands.
  if ctx.jev_ran then
    set_request_headers(ctx, ctx.jev_headers)
    local b = ctx.jev_block
    if b then
      core.response.set_header("Content-Type", "application/json")
      for k, val in pairs(b.headers) do core.response.set_header(k, val) end
      return b.status, b.body
    end
    return
  end
  -- before anything can fail: a run that failed open is not repeated either
  ctx.jev_ran = true
  set_request_headers(ctx, nil)
  local rt = runtime_for(conf)

  local v
  local ok, err = pcall(function()
    local req = build_req(rt, ctx)
    local subj = subject_ctx(rt, req, ctx)
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
  pcall(sweep_inbound, ctx, type(conf) == "table" and conf.subject or nil)

  if not ok then
    core.log.error("jev-edge: access error, failing open: ", err)
    ctx.jev_headers = { ["X-Jev-Verdict"] = verdict.ERROR, ["X-Jev-Source"] = "adapter" }
    set_request_headers(ctx, ctx.jev_headers)
    return
  end

  ctx.jev = v
  local headers = verdict.headers(v)
  headers["X-Jev-Request-Id"] = ctx.var.request_id or ""
  ctx.jev_headers = headers
  set_request_headers(ctx, headers)

  if v.action == verdict.ACTION_BLOCK then
    local b = { status = rt.cfg.policy.block_status or 403, headers = verdict.headers(v),
                body = rt.cfg.policy.block_body or '{"error":"request rejected"}' }
    ctx.jev_block = b
    core.response.set_header("Content-Type", "application/json")
    for k, val in pairs(b.headers) do core.response.set_header(k, val) end
    return b.status, b.body
  end
end

--- Runs when APISIX loads the plugin: says so when jev_cache is missing, and
-- registers `$jev_log` for APISIX's logger plugins (http-logger,
-- file-logger, ...), the same JSON object the OpenResty adapter writes, so
-- `log_format: { jev: "$jev_log" }` works.
function _M.init()
  check_dict(DICT, "no verdict cache, breaker, max_inflight, max_async or reputation")
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
