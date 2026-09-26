-- kong/plugins/jev-edge/handler.lua
-- jev-edge as a Kong Gateway (3.x) plugin. Same core, same OpenResty modules
-- as the nginx adapter and the APISIX plugin (cache, provider HTTP client,
-- breaker, body reader, L3 timer); what this file adds is the Kong plugin
-- contract (schema.lua, phases, per-plugin-instance config) and the mapping
-- from Kong's PDK onto core's `req` table.
--
-- Install (see adapters/kong/README.md):
--   KONG_PLUGINS=bundled,jev-edge
--   KONG_LUA_PACKAGE_PATH=/opt/jev-edge/adapters/kong/?.lua;/opt/jev-edge/adapters/openresty/lib/?.lua;
--                         /opt/jev-edge/?.lua;/opt/jev-edge/?/init.lua;;   (one line)
--   KONG_NGINX_HTTP_LUA_SHARED_DICT="jev_cache 64m"
--   KONG_NGINX_MAIN_ENV=TYPESAFE_API_KEY          (or jev.api_key = "{vault://env/typesafe-api-key}")

require("resty.jev.loader")()

local jev_core  = require("jev.core")
local defaults  = require("jev.core.defaults")
local verdict   = require("jev.core.verdict")
local breaker_m = require("jev.core.breaker")
local rules_mod = require("jev.core.rules")
local sampling  = require("jev.core.sampling")
local subject_m = require("jev.core.subject")
local cache_m   = require("resty.jev.cache")
local http      = require("resty.jev.http")
local async     = require("resty.jev.async")
local body_m    = require("resty.jev.body")
local cjson     = require("cjson.safe")
local sha256    = require("resty.sha256")
local to_hex    = require("resty.string").to_hex

local kong = kong
local null = ngx.null

local DICT = "jev_cache"
local SUBJECT_DICT = "jev_subject"
local SUBJECT_REP_DICT = "jev_subject_rep"   -- subject reputation, apart from the trajectories
local HEADER_NAMES = { "X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id" }
local DEFAULT_BLOCK_BODY = '{"error":"request rejected"}'

local JevEdge = {
  VERSION  = "0.6.2",
  -- 905: after authentication (key-auth 1250, jwt 1450, basic-auth 1100, ...),
  -- ip-restriction (990), request-size-limiting (951), acl (950) and
  -- rate-limiting (910), so a request that is refused anyway never costs a
  -- judge call; before response-ratelimiting (900), request-transformer (801)
  -- and the ai-* plugins (770s), so the judged body is the one the client
  -- sent and ai-proxy only ever sees admitted requests. An auth plugin with
  -- hide_credentials = true has removed its header by then, so a
  -- `subject.from = "header"` naming it falls back to the credential Kong
  -- authenticated (subject_ctx).
  PRIORITY = 905,
}

-- ---------------------------------------------------------------------------
-- runtime per plugin conf (Kong hands the same conf table to every request
-- of a plugin instance until the config changes, so identity is the key,
-- along with the vault secrets resolved into it: runtime_for)
-- ---------------------------------------------------------------------------

local runtimes = setmetatable({}, { __mode = "k" })
local cache

-- Unset schema fields can arrive as ngx.null; core wants them absent.
local function strip_nulls(t)
  if type(t) ~= "table" then return t end
  local out = {}
  for k, v in pairs(t) do
    if v ~= null then out[k] = strip_nulls(v) end
  end
  return out
end

-- SHA-256 for fingerprints and subject ids, the same as every other adapter.
local function sha256_hex(s)
  local h = sha256:new()
  h:update(s)
  return to_hex(h:final())
end

-- The rules, and the ids of the ones that did not load (nil when all did).
-- A rule set missing from this node's disk passes schema validation on a
-- data plane (schema.lua); dropping it would leave the route judged by the
-- rest, or by none ("no rules", a pass even in enforce), with nothing said.
local function load_rules(specs)
  local out, failed = {}, {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, function(id)
      local ok, r = pcall(require, "jev.rules." .. id)
      if ok then return r end
      return nil, tostring(r)
    end)
    if rule then out[#out + 1] = rule
    else
      local id = type(spec) == "table" and (spec.id or spec.extends) or spec
      failed[#failed + 1] = tostring(id)
      kong.log.err("jev-edge: rules[", i, "] (", tostring(id), ") failed to load: ", tostring(err))
    end
  end
  if #failed == 0 then return out, nil end
  return out, table.concat(failed, ", ")
end

-- The verdict for a request on a conf whose rules did not all load: not
-- judged, so an error that fails open, or a block where the operator chose
-- policy.unjudgeable = "block" and the plugin enforces.
local function rules_failed(rt)
  local p = rt.cfg.policy
  local block = p.mode == "enforce" and p.unjudgeable == "block"
  return verdict.new({
    action = block and verdict.ACTION_BLOCK or verdict.ACTION_PASS,
    verdict = verdict.ERROR, source = "adapter", reason = "rules failed to load: " .. rt.rules_err,
  })
end

local function config_from(conf)
  local c = strip_nulls(conf)
  -- rules_json: the whole rules list (ids and inline tables), as in APISIX
  if c.rules_json then
    local specs = cjson.decode(c.rules_json)
    if type(specs) == "table" and #specs > 0 then c.rules = specs
    else kong.log.err("jev-edge: rules_json is not a JSON array, using rules") end
  end
  -- jev.questions_json: jev.questions as JSON (a map of maps Kong's schema
  -- cannot type); the schema has checked it
  if c.jev and c.jev.questions_json then
    local qs = cjson.decode(c.jev.questions_json)
    if type(qs) == "table" then c.jev.questions = qs
    else kong.log.err("jev-edge: jev.questions_json is not a JSON object, ignored") end
    c.jev.questions_json = nil
  end
  c.rules_json, c.log_line = nil, nil
  -- jev.extra_body_json: core's jev.extra_body, as a JSON object in a string
  if type(c.jev) == "table" and c.jev.extra_body_json then
    local eb = cjson.decode(c.jev.extra_body_json)
    if type(eb) == "table" then c.jev.extra_body = eb
    else kong.log.err("jev-edge: jev.extra_body_json is not a JSON object, ignored") end
    c.jev.extra_body_json = nil
  end
  return defaults.merge(defaults.config, c)
end

-- The referenceable fields as Kong has them now. A {vault://...} reference
-- is resolved in place on this same conf table on every request
-- (kong.vault.update), so a rotated secret never changes the table's
-- identity: the runtime keeps the values it was built from and is rebuilt
-- when they differ. Breaker, adaptive and in-flight state are in the shared
-- dict (under a prefix that names the key's hash), so a rebuild loses none.
local function secrets(conf)
  local j, s = conf.jev, conf.subject
  local key = type(j) == "table" and j.api_key or nil
  local salt = type(s) == "table" and s.salt or nil
  return key ~= null and key or nil, salt ~= null and salt or nil
end

local function runtime_for(conf)
  local key, salt = secrets(conf)
  local rt = runtimes[conf]
  if rt and rt.src_api_key == key and rt.src_salt == salt then return rt end
  local cfg = config_from(conf)
  -- a vault reference that did not resolve reads "": no key, so the env
  -- fallback and its warning apply rather than an empty bearer token
  if cfg.jev.api_key == "" then cfg.jev.api_key = nil end
  if not cfg.jev.api_key and cfg.jev.provider ~= "mock" then
    local env = cfg.jev.api_key_env or "TYPESAFE_API_KEY"
    cfg.jev.api_key = os.getenv(env)
    if not cfg.jev.api_key then
      kong.log.warn("jev-edge: env ", env, " is empty (declare it with KONG_NGINX_MAIN_ENV=", env, ")")
    end
  end
  cache = cache or cache_m.new(DICT)
  -- Breaker, adaptive timeout and in-flight counter: shared by the plugin
  -- instances that call the same provider, endpoint and model with the same
  -- key, max_inflight and breaker settings (resty.jev.http state_prefix), and
  -- only by them: an instance whose key is revoked or over quota, or whose
  -- breaker is tuned to trip early, opens its own breaker.
  local st = cache:prefixed(http.state_prefix(cfg, sha256_hex))
  local judge, err = http.new(cfg.jev, st)
  if not judge then
    kong.log.err("jev-edge: ", err)
    judge = { call = function() return nil, err end }
  end
  local rules, rules_err = load_rules(cfg.rules)
  rt = {
    cfg = cfg, rules = rules, rules_err = rules_err, judge = judge, state = st,
    breaker = breaker_m.new(st, ngx.now, cfg.breaker),
    log_line = conf.log_line == true,
    src_api_key = key, src_salt = salt,
  }
  runtimes[conf] = rt
  return rt
end

-- ---------------------------------------------------------------------------
-- request mapping
-- ---------------------------------------------------------------------------

local warned_long = false
local function subject_ctx(rt, req)
  local scfg = rt.cfg.subject
  if not scfg or not scfg.enabled then return nil end
  -- the raw Cookie header(s), not the cookie variable: nginx's $cookie_<name>
  -- is the first match, compared case-insensitively, quotes kept, while the
  -- backend may read another. Every candidate is an id (core/subject.lua
  -- cookie_values); reputation checks and charges each, ids[1] names the
  -- trajectory and the logs.
  local raws, long = subject_m.extract_all(scfg, {
    ip = req.client_ip,
    ipv6_prefix = rt.cfg.client_ip and rt.cfg.client_ip.ipv6_prefix,
    header = function(n) return req.headers[n] end,
    cookie_header = req.headers["cookie"],
  })
  -- No header: an auth plugin that ran first may have removed it
  -- (key-auth, basic-auth ... with hide_credentials = true), so the
  -- credential it authenticated is the subject. The credential, not the
  -- consumer: an anonymous consumer has no credential, and anonymous
  -- clients are never pooled into one reputation. Only where there would be
  -- no subject, so no existing id changes; not with `hashed`, where the
  -- header is an id another jev-edge computed.
  if #raws == 0 and not long and scfg.from == "header" and not scfg.hashed then
    local cred = kong.client.get_credential()
    if type(cred) == "table" and cred.id ~= nil and cred.id ~= null then
      raws = { "kong-credential:" .. tostring(cred.id) }
    end
  end
  if long and not warned_long then
    -- once per worker: a subject value past the limit names no trajectory
    warned_long = true
    kong.log.warn("jev-edge: ", long, ", dropped (subject.from = ", tostring(scfg.from), ")")
  end
  local ids = subject_m.hash_ids(scfg, raws, sha256_hex)
  local id = ids[1]
  if not id then return nil end
  local rep_on = type(scfg.reputation) == "table" and (tonumber(scfg.reputation.block_at) or 0) > 0
  local ring, rep = cache_m.subject_stores(SUBJECT_DICT, SUBJECT_REP_DICT, rep_on)
  return {
    id = id,
    ids = ids,
    history = subject_m.ring_load(ring, id, scfg.max_entries),
    -- never evicts: a full dict drops the new entry
    record = function(e)
      subject_m.ring_append(ring, id, e, scfg.max_entries, scfg.history_ttl)
    end,
    -- reputation counters and blocks (subject.reputation): incr is atomic in the dict
    store = rep,
  }
end

local function build_req(rt)
  -- 0 = no limit: past the default 100 the rest are dropped, and a
  -- Content-Type sent after 100 junk headers would read as absent.
  -- kong.request.get_headers() caps at 1000 and rejects 0, hence ngx.req.
  local headers = ngx.req.get_headers(0)
  local req = {
    method    = kong.request.get_method(),
    -- nginx's $uri: fully decoded and normalised, as the nginx adapter and
    -- APISIX match it. Not kong.request.get_path(), which keeps reserved
    -- escapes: /v1%2Fchat/completions would miss ^/v1/chat and be skipped,
    -- while a backend that decodes %2F (uvicorn/Starlette) serves the chat
    -- endpoint.
    path      = ngx.var.uri,
    headers   = headers,
    -- honours trusted_ips / real_ip_header / real_ip_recursive
    client_ip = kong.client.get_forwarded_ip(),
    body      = nil,
    body_size = tonumber(headers["content-length"]) or 0,
  }
  -- Whole up to max_body_bytes, head and tail past it, decoded. Not
  -- kong.request.get_raw_body(): it returns nil for a body nginx spooled to
  -- disk; resty.jev.body reads the file too.
  local max = 0
  for _, r in ipairs(rt.rules) do
    if rules_mod.path_matches(req.path, r.watch_paths, r.paths_case_sensitive) then
      max = math.max(max, r.max_body_bytes or rules_mod.MAX_BODY_BYTES)
    end
  end
  if max > 0 then body_m.fill(req, max) end
  return req
end

-- the byte span of the first match at or after byte init (from, to), which
-- places the hit in the judging window; nil when there is none. When PCRE
-- fails (a JIT stack or match limit, a pattern it refuses) ngx.re.find
-- returns nil, nil, err, passed on whole: core counts the pattern as a hit.
local function re_find(subject, pattern, init)
  if init and init > 1 then return ngx.re.find(subject, pattern, "ijo", { pos = init }) end
  return ngx.re.find(subject, pattern, "ijo")
end

local function maybe_async(rt, v, req)
  if not v.async then return end
  if rt.breaker:state() ~= breaker_m.CLOSED then return end
  -- the parts L2 judged, their prompts and cache keys (core.l3_job)
  local job = jev_core.l3_job(req, { config = rt.cfg, rules = rt.rules, hash = sha256_hex,
                                     json_decode = cjson.decode, re_find = re_find })
  if not job then return end
  async.schedule({ cfg = rt.cfg, cache = cache, state = rt.state, judge = rt.judge, job = job,
    client_ip = req.client_ip })
end

-- every route's samples go into the one jev_cache ring: each names its route
local warned_ring = false
local function maybe_sample(rt, v, req)
  if not sampling.should_sample(rt.cfg, v, math.random) then return end
  local ok, err = pcall(function()
    local s = sampling.build(rt.cfg, v, req, rules_mod.rule_for(req, rt.rules, { json_decode = cjson.decode }),
      { rid = ngx.var.request_id, ts = ngx.now(), json_decode = cjson.decode })
    local route = kong.router.get_route()
    s.route = route and (route.id or route.name) or nil
    local _, other = sampling.store(rt.cfg, cache, s)
    if other and not warned_ring then
      warned_ring = true
      kong.log.warn("jev-edge: sampling.max_samples differs from the ring's size in jev_cache; ",
        "samples go into the ring as its first writer sized it")
    end
    if rt.cfg.sampling.log then kong.log.info("jev-edge sample: ", cjson.encode(s)) end
  end)
  if not ok then kong.log.warn("jev-edge: sampling failed: ", err) end
end

-- ---------------------------------------------------------------------------
-- phases
-- ---------------------------------------------------------------------------

-- The subject header the config reads, lowercased: an X-Jev-* name there (a
-- thin Worker's X-Jev-Subject, read with hashed = true) is the deployment's
-- own and stays. scfg may be the raw plugin conf's (ngx.null for unset).
local function subject_header(scfg)
  if type(scfg) == "table" and scfg.from == "header" and type(scfg.name) == "string" then
    return scfg.name:lower()
  end
  return nil
end

-- Every other X-Jev-* header off the service request, once judging has read
-- what it needs (the mock score header, a subject header). The early strip
-- takes only the names jev-edge sets; X-Jev-Subject, X-Jev-Body-Partial or
-- any other X-Jev-* a client sent would reach the upstream as if jev-edge
-- had set it.
local function sweep_inbound(scfg)
  local keep = subject_header(scfg)
  for k in pairs(ngx.req.get_headers(0)) do
    if type(k) == "string" then
      local n = k:lower()
      if n:sub(1, 6) == "x-jev-" and n ~= keep then kong.service.request.clear_header(n) end
    end
  end
end

local function fail_open(err, conf)
  kong.log.err("jev-edge: access error, failing open: ", err)
  pcall(sweep_inbound, type(conf) == "table" and conf.subject or nil)
  pcall(kong.service.request.set_header, "X-Jev-Verdict", verdict.ERROR)
  pcall(kong.service.request.set_header, "X-Jev-Source", "adapter")
end

function JevEdge:access(conf)
  -- Strip first, outside the pcall: a client must never be able to hand the
  -- upstream its own verdict, whatever happens after.
  for _, h in ipairs(HEADER_NAMES) do kong.service.request.clear_header(h) end

  local rt, v
  local ok, err = pcall(function()
    rt = runtime_for(conf)
    if rt.rules_err then
      v = rules_failed(rt)
    else
      local req = build_req(rt)
      local subj = subject_ctx(rt, req)
      kong.ctx.plugin.subject = subj and subj.id or nil
      v = jev_core.evaluate(req, {
        config = rt.cfg, rules = rt.rules, cache = cache, trust = cache, judge = rt.judge, breaker = rt.breaker,
        subject = subj,
        clock = ngx.now, hash = sha256_hex,
        json_decode = cjson.decode, re_find = re_find,
        log = function(level, msg) if level == "error" then kong.log.err(msg) else kong.log.warn(msg) end end,
      })
      maybe_async(rt, v, req)
      maybe_sample(rt, v, req)
    end
    sweep_inbound(rt.cfg.subject)
    for k, val in pairs(verdict.headers(v)) do kong.service.request.set_header(k, val) end
    kong.service.request.set_header("X-Jev-Request-Id", ngx.var.request_id or "")
  end)

  if not ok then return fail_open(err, conf) end
  kong.ctx.plugin.verdict = v

  if v.action == verdict.ACTION_BLOCK then
    -- the client sees the verdict and the request id, never the score, the
    -- reason or the source (verdict.client_headers): those go to the log
    local headers = verdict.client_headers(v)
    headers["Content-Type"] = "application/json"
    headers["X-Jev-Request-Id"] = ngx.var.request_id or ""
    return kong.response.exit(rt.cfg.policy.block_status or 403,
      rt.cfg.policy.block_body or DEFAULT_BLOCK_BODY, headers)
  end
end

--- The decision goes to Kong's log serializer as `jev`, so http-log,
-- file-log, tcp-log, kafka-log ... carry it with no extra config; with
-- `log_line = true` it is also written as one JSON line to the error log
-- (NOTICE), the same object the OpenResty adapter puts in $jev_log.
function JevEdge:log(conf)
  local v = kong.ctx.plugin.verdict
  if not v then return end
  local ok, err = pcall(function()
    local entry = {
      rid = ngx.var.request_id, path = ngx.var.uri, ip = kong.client.get_forwarded_ip(),
      src = v.source, score = v.score, verdict = v.verdict, action = v.action,
      l2_ms = v.l2_ms, fp = v.fingerprint, reason = v.reason, subject = kong.ctx.plugin.subject,
    }
    kong.log.set_serialize_value("jev", entry)
    if conf.log_line == true then kong.log.notice("jev-edge: ", cjson.encode(entry)) end
  end)
  if not ok then kong.log.warn("jev-edge: log phase: ", err) end
end

return JevEdge
