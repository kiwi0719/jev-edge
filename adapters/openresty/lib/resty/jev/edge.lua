-- resty/jev/edge.lua
-- OpenResty glue: init / init_worker / access / log / config_api / metrics.
-- Everything in access() is wrapped in pcall; any failure passes the request.

require("resty.jev.loader")()

local core      = require "jev.core"
local verdict   = require "jev.core.verdict"
local judge_mod = require "jev.core.judge"
local normalize = require "jev.core.normalize"
local breaker_m = require "jev.core.breaker"
local config    = require "resty.jev.config"
local cache_m   = require "resty.jev.cache"
local http      = require "resty.jev.http"
local async     = require "resty.jev.async"
local metrics   = require "resty.jev.metrics"
local cjson     = require "cjson.safe"

local _M = { _VERSION = core._VERSION }

local CACHE_DICT = "jev_cache"
local HEADER_NAMES = { "X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id" }

local cache, breaker, judge, judge_cfg

-- ---------------------------------------------------------------------------

function _M.init(conf_path, opts)
  config.init(conf_path, opts)
end

function _M.init_worker()
  cache = cache_m.new(CACHE_DICT)
  local interval = 2
  local ok, err = ngx.timer.every(interval, function(premature)
    if premature then return end
    local okr, e = pcall(config.reload)
    if not okr then ngx.log(ngx.ERR, "jev-edge: reload error: ", e) end
  end)
  if not ok then ngx.log(ngx.ERR, "jev-edge: cannot start reload timer: ", err) end
end

-- Judge and breaker are rebuilt whenever config is rebuilt (config.current()
-- returns a fresh table only on reload, so identity is a cheap change check).
local function ensure_runtime(cfg)
  if not cache then cache = cache_m.new(CACHE_DICT) end
  if cfg ~= judge_cfg then
    local j, err = http.new(cfg.jev, cache, metrics.usage)
    if not j then
      ngx.log(ngx.ERR, "jev-edge: ", err)
      judge = { call = function() return nil, err end }
    else
      judge = j
    end
    breaker = breaker_m.new(cache, ngx.now, cfg.breaker)
    judge_cfg = cfg
  end
end

local function re_find(subject, pattern)
  local from = ngx.re.find(subject, pattern, "ijo")
  return from ~= nil
end

local function build_req(rules)
  local headers = ngx.req.get_headers()
  local req = {
    method    = ngx.req.get_method(),
    path      = ngx.var.uri,
    headers   = headers,
    client_ip = ngx.var.remote_addr,
    body      = nil,
    body_size = tonumber(headers["content-length"]) or 0,
  }
  -- Only read the body when some rule could possibly want it.
  local max = 0
  for _, r in ipairs(rules) do
    local ok = false
    for _, p in ipairs(r.watch_paths or {}) do
      if req.path:find(p) then ok = true break end
    end
    if ok then max = math.max(max, r.max_body_bytes or 65536) end
  end
  if max > 0 and req.body_size <= max then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
      local file = ngx.req.get_body_file()
      if file then
        local f = io.open(file, "rb")
        if f then body = f:read("*a"); f:close() end
      end
    end
    req.body = body
    if body then req.body_size = #body end
  end
  return req
end

local function strip_inbound()
  for _, h in ipairs(HEADER_NAMES) do ngx.req.clear_header(h) end
end

local function set_headers(v)
  for k, val in pairs(verdict.headers(v)) do ngx.req.set_header(k, val) end
  ngx.req.set_header("X-Jev-Request-Id", ngx.var.request_id or "")
end

local function maybe_async(cfg, v, req, rules)
  if not v.async or not judge then return end
  -- rebuild the prompt from the request; core does not hand it back
  local rule
  for _, r in ipairs(rules) do
    for _, p in ipairs(r.watch_paths or {}) do
      if (req.path or ""):find(p) then rule = r break end
    end
    if rule then break end
  end
  if not rule then return end
  local ct = req.headers["content-type"] or ""
  local text = normalize.extract(req.body, ct, rule.text_fields, cjson.decode)
  if text == "" then return end
  local prompt = judge_mod.build(rule.templates, text, { path = req.path, method = req.method })
  if not prompt then return end
  local ok, err = async.schedule({
    cfg = cfg, cache = cache, judge = judge, prompt = prompt,
    fingerprint = v.fingerprint, client_ip = req.client_ip,
  })
  if not ok and err ~= "disabled" then metrics.incr_async_dropped() end
end

function _M.access()
  local cfg = config.current()
  local rules = config.rules()
  local v
  local ok, err = pcall(function()
    ensure_runtime(cfg)
    strip_inbound()
    local req = build_req(rules)
    v = core.evaluate(req, {
      config = cfg, rules = rules, cache = cache, judge = judge, breaker = breaker,
      clock = ngx.now, hash = function(s) return string.format("%08x", ngx.crc32_long(s)) end,
      json_decode = cjson.decode, re_find = re_find,
      log = function(level, msg) ngx.log(level == "error" and ngx.ERR or ngx.WARN, msg) end,
    })
    metrics.record(v)
    if breaker then metrics.set_breaker_state(breaker:state()) end
    set_headers(v)
    ngx.ctx.jev = v
    maybe_async(cfg, v, req, rules)
  end)

  if not ok then
    ngx.log(ngx.ERR, "jev-edge: access error, failing open: ", err)
    ngx.req.set_header("X-Jev-Verdict", verdict.ERROR)
    ngx.req.set_header("X-Jev-Source", "adapter")
    return
  end

  if v and v.action == verdict.ACTION_BLOCK then
    ngx.status = cfg.policy.block_status or 403
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cfg.policy.block_body or '{"error":"request rejected"}')
    return ngx.exit(ngx.HTTP_OK)
  end
end

--- log_by_lua: sets $jev_log if the variable is declared.
function _M.log()
  local v = ngx.ctx.jev
  if not v then return end
  local line = cjson.encode({
    rid = ngx.var.request_id, path = ngx.var.uri, ip = ngx.var.remote_addr,
    src = v.source, score = v.score, verdict = v.verdict, action = v.action,
    l2_ms = v.l2_ms, fp = v.fingerprint, reason = v.reason,
  })
  local ok = pcall(function() ngx.var.jev_log = line end)
  if not ok then ngx.log(ngx.INFO, "jev-edge: ", line) end
end

--- content_by_lua for /_jev/config (restrict with allow/deny in nginx.conf).
function _M.config_api()
  local method = ngx.req.get_method()
  ngx.header["Content-Type"] = "application/json"
  if method == "GET" then
    ngx.say(cjson.encode({ effective = config.current(), override = config.get_override() or cjson.null }))
    return
  elseif method == "PUT" then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local tbl = body and cjson.decode(body)
    if type(tbl) ~= "table" then
      ngx.status = 400
      ngx.say('{"error":"body must be a JSON object"}')
      return
    end
    local ok, err = config.set_override(tbl)
    if not ok then
      ngx.status = 422
      ngx.say(cjson.encode({ error = err }))
      return
    end
    ngx.say('{"ok":true}')
    return
  elseif method == "DELETE" then
    config.set_override(nil)
    ngx.say('{"ok":true}')
    return
  end
  ngx.status = 405
  ngx.say('{"error":"method not allowed"}')
end

--- content_by_lua for /_jev/metrics.
function _M.metrics()
  ngx.header["Content-Type"] = "text/plain; version=0.0.4"
  ngx.say(metrics.render())
end

return _M
