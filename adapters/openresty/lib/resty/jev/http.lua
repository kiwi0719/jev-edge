-- resty/jev/http.lua
-- Turns a provider into core's judge.call(prompt, timeout_ms). Owns the HTTP
-- client, timeouts and the in-flight cap. The breaker is wired in core.

local http_ok, resty_http = pcall(require, "resty.http")

local _M = {}

local providers = {}

function _M.load_provider(name)
  if providers[name] then return providers[name] end
  local ok, p = pcall(require, "resty.jev.providers." .. name:gsub("-", "_"))
  if not ok then
    return nil, "provider " .. name .. " not found: " .. tostring(p)
  end
  providers[name] = p
  return p
end

--- Build a judge object for the current config.
local adaptive_m = require "resty.jev.adaptive"

-- @param cfg      cfg.jev section (provider, endpoint, model, api_key, timeout_*, max_inflight)
-- @param inflight cache-like object with get/set/incr (shared dict); also backs the adaptive timeout
-- @param metrics  optional function(event, fields)
function _M.new(cfg, inflight, metrics)
  local provider, perr = _M.load_provider(cfg.provider or "jev")
  if not provider then return nil, perr end

  local adaptive = adaptive_m.new(inflight, cfg)
  local self = { cfg = cfg, provider = provider, inflight = inflight, metrics = metrics, adaptive = adaptive }

  local function now_ms() return ngx.now() * 1000 end

  -- core passes cfg.jev.timeout_ms; the adaptive estimate overrides it.
  function self.call(prompt, _requested_timeout)
    local timeout_ms = adaptive:current()

    -- Concurrency cap applies to every provider, mock included, so the limit
    -- is exercised by the soak test.
    local key = "inflight:l2"
    local max = tonumber(cfg.max_inflight) or 64
    if inflight then
      local n = inflight:incr(key, 1, 0)
      if n and n > max then
        inflight:incr(key, -1, 0)
        return nil, "max_inflight exceeded"
      end
    end

    if provider.local_only then
      local t0 = now_ms()
      local answers, err = provider.call(prompt, cfg, timeout_ms)
      if inflight then inflight:incr(key, -1, 0) end
      ngx.update_time()
      if answers then adaptive:success(now_ms() - t0)
      elseif tostring(err):find("timeout", 1, true) then adaptive:timeout(timeout_ms) end
      return answers, err
    end
    if not http_ok then
      if inflight then inflight:incr(key, -1, 0) end
      return nil, "lua-resty-http not installed"
    end

    local req = provider.build_request(prompt, cfg)
    -- Budget split: connect (TLS handshake on a cold keepalive pool) 30%,
    -- send 10%, read 60%. With keepalive the connect share is unused.
    local total = tonumber(timeout_ms) or 300
    local connect = math.max(10, math.floor(total * 0.3))
    local send = math.max(10, math.floor(total * 0.1))
    local read = math.max(10, total - connect - send)

    local client = resty_http.new()
    client:set_timeouts(connect, send, read)
    local t0 = now_ms()
    local res, err = client:request_uri(req.url, {
      method = req.method or "POST",
      headers = req.headers,
      body = req.body,
      ssl_verify = cfg.ssl_verify ~= false,
      keepalive_timeout = 60000,
      keepalive_pool = 16,
    })
    if inflight then inflight:incr(key, -1, 0) end
    ngx.update_time()
    local elapsed = now_ms() - t0

    if not res then
      if tostring(err):find("timeout", 1, true) then adaptive:timeout(timeout_ms) end
      return nil, tostring(err)
    end
    local answers, perr2, usage = provider.parse_response(res.status, res.body, cfg)
    if metrics and usage then metrics("usage", usage) end
    if not answers then return nil, perr2 end
    adaptive:success(elapsed)
    return answers
  end

  return self
end

return _M
