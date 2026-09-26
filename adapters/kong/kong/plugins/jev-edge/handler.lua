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
local judge_mod = require("jev.core.judge")
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
local HEADER_NAMES = { "X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id" }
local DEFAULT_BLOCK_BODY = '{"error":"request rejected"}'

local JevEdge = {
  VERSION  = "0.6.1",
  -- 905: after authentication (key-auth 1250, jwt 1450, basic-auth 1100, ...),
  -- ip-restriction (990), request-size-limiting (951), acl (950) and
  -- rate-limiting (910), so a request that is refused anyway never costs a
  -- judge call and `subject.from = "header"` can key on a credential already
  -- checked; before response-ratelimiting (900), request-transformer (801)
  -- and the ai-* plugins (770s), so the judged body is the one the client
  -- sent and ai-proxy only ever sees admitted requests.
  PRIORITY = 905,
}

-- ---------------------------------------------------------------------------
-- runtime per plugin conf (Kong hands the same conf table to every request
-- of a plugin instance until the config changes, so identity is the key)
-- ---------------------------------------------------------------------------

local runtimes = setmetatable({}, { __mode = "k" })
local cache
local subject_store

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

local function load_rules(specs)
  local out = {}
  for i, spec in ipairs(specs or {}) do
    local rule, err = rules_mod.resolve(spec, function(id)
      local ok, r = pcall(require, "jev.rules." .. id)
      if ok then return r end
      return nil, tostring(r)
    end)
    if rule then out[#out + 1] = rule
    else kong.log.err("jev-edge: rules[", i, "] failed to load: ", tostring(err)) end
  end
  return out
end

local function config_from(conf)
  local c = strip_nulls(conf)
  -- rules_json: the whole rules list (ids and inline tables), as in APISIX
  if c.rules_json then
    local specs = cjson.decode(c.rules_json)
    if type(specs) == "table" and #specs > 0 then c.rules = specs
    else kong.log.err("jev-edge: rules_json is not a JSON array, using rules") end
  end
  c.rules_json, c.log_line = nil, nil
  return defaults.merge(defaults.config, c)
end

local function runtime_for(conf)
  local rt = runtimes[conf]
  if rt then return rt end
  local cfg = config_from(conf)
  if not cfg.jev.api_key and cfg.jev.provider ~= "mock" then
    local env = cfg.jev.api_key_env or "TYPESAFE_API_KEY"
    cfg.jev.api_key = os.getenv(env)
    if not cfg.jev.api_key then
      kong.log.warn("jev-edge: env ", env, " is empty (declare it with KONG_NGINX_MAIN_ENV=", env, ")")
    end
  end
  cache = cache or cache_m.new(DICT)
  -- Breaker, adaptive timeout and in-flight counters describe one provider:
  -- plugin instances calling the same provider, endpoint and model share
  -- them, one with another provider gets its own.
  local st = cache:prefixed("p:" .. sha256_hex(table.concat({
    tostring(cfg.jev.provider or ""), tostring(cfg.jev.endpoint or ""), tostring(cfg.jev.model or ""),
  }, "\n")):sub(1, 12) .. ":")
  local judge, err = http.new(cfg.jev, st)
  if not judge then
    kong.log.err("jev-edge: ", err)
    judge = { call = function() return nil, err end }
  end
  rt = {
    cfg = cfg, rules = load_rules(cfg.rules), judge = judge, state = st,
    breaker = breaker_m.new(st, ngx.now, cfg.breaker),
    log_line = conf.log_line == true,
  }
  runtimes[conf] = rt
  return rt
end

-- ---------------------------------------------------------------------------
-- request mapping
-- ---------------------------------------------------------------------------

local function subject_ctx(rt, req)
  local scfg = rt.cfg.subject
  if not scfg or not scfg.enabled then return nil end
  local raw = subject_m.extract(scfg, {
    ip = req.client_ip,
    header = function(n) return req.headers[n] end,
    cookie = function(n) return ngx.var["cookie_" .. tostring(n)] end,
  })
  local id = subject_m.hash_id(scfg, raw, sha256_hex)
  if not id then return nil end
  subject_store = subject_store or cache_m.new(SUBJECT_DICT)
  local store = subject_store
  return {
    id = id,
    history = subject_m.ring_load(store, id, scfg.max_entries),
    record = function(e)
      subject_m.ring_append(store, id, e, scfg.max_entries, scfg.history_ttl)
    end,
    -- reputation counters (subject.reputation): incr is atomic in the dict
    store = store,
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

local function re_find(subject, pattern)
  return ngx.re.find(subject, pattern, "ijo")
end

local function maybe_async(rt, v, req)
  if not v.async then return end
  if rt.breaker:state() ~= breaker_m.CLOSED then return end
  local rule = rules_mod.rule_for(req, rt.rules, { json_decode = cjson.decode })
  if not rule then return end
  local text = rules_mod.judged_text(req, rule, { json_decode = cjson.decode, re_find = re_find })
  if text == "" then return end
  local prompt = judge_mod.build(rule.templates, text, {
    path = req.path, method = req.method,
    deployment = rule.deployment_context or rt.cfg.jev.deployment_context or "",
  })
  if not prompt then return end
  async.schedule({ cfg = rt.cfg, cache = cache, state = rt.state, judge = rt.judge, prompt = prompt,
    fingerprint = v.fingerprint, client_ip = req.client_ip,
    cache_key = v.fingerprint ~= "" and jev_core.cache_key(v.fingerprint, rule, rt.cfg, sha256_hex) or nil })
end

local function maybe_sample(rt, v, req)
  if not sampling.should_sample(rt.cfg, v, math.random) then return end
  local ok, err = pcall(function()
    local s = sampling.build(rt.cfg, v, req, rules_mod.rule_for(req, rt.rules, { json_decode = cjson.decode }),
      { rid = ngx.var.request_id, ts = ngx.now(), json_decode = cjson.decode })
    sampling.store(rt.cfg, cache, s)
    if rt.cfg.sampling.log then kong.log.info("jev-edge sample: ", cjson.encode(s)) end
  end)
  if not ok then kong.log.warn("jev-edge: sampling failed: ", err) end
end

-- ---------------------------------------------------------------------------
-- phases
-- ---------------------------------------------------------------------------

local function fail_open(err)
  kong.log.err("jev-edge: access error, failing open: ", err)
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
    for k, val in pairs(verdict.headers(v)) do kong.service.request.set_header(k, val) end
    kong.service.request.set_header("X-Jev-Request-Id", ngx.var.request_id or "")
  end)

  if not ok then return fail_open(err) end
  kong.ctx.plugin.verdict = v

  if v.action == verdict.ACTION_BLOCK then
    local headers = verdict.headers(v)
    headers["Content-Type"] = "application/json"
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
