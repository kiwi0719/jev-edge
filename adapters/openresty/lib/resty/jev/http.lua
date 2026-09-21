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
-- @param cfg      cfg.jev section (provider, endpoint, model, api_key, timeout_ms, max_inflight)
-- @param inflight cache-like object with incr(key, by, ttl) for the concurrency cap (optional)
-- @param metrics  optional function(event, fields)
function _M.new(cfg, inflight, metrics)
  local provider, perr = _M.load_provider(cfg.provider or "jev")
  if not provider then return nil, perr end

  local self = { cfg = cfg, provider = provider, inflight = inflight, metrics = metrics }

  function self.call(prompt, timeout_ms)
    if provider.local_only then
      return provider.call(prompt, cfg, timeout_ms)
    end
    if not http_ok then
      return nil, "lua-resty-http not installed"
    end

    local key = "inflight:l2"
    local max = tonumber(cfg.max_inflight) or 64
    if inflight then
      local n = inflight:incr(key, 1, 0)
      if n and n > max then
        inflight:incr(key, -1, 0)
        return nil, "max_inflight exceeded"
      end
    end

    local req = provider.build_request(prompt, cfg)
    local total = tonumber(timeout_ms) or 300
    local connect = math.min(50, total)
    local send = math.min(50, total)
    local read = math.max(total - connect - send, 10)

    local client = resty_http.new()
    client:set_timeouts(connect, send, read)
    local res, err = client:request_uri(req.url, {
      method = req.method or "POST",
      headers = req.headers,
      body = req.body,
      ssl_verify = cfg.ssl_verify ~= false,
      keepalive_timeout = 60000,
      keepalive_pool = 16,
    })
    if inflight then inflight:incr(key, -1, 0) end

    if not res then
      return nil, tostring(err)
    end
    local answers, perr2, usage = provider.parse_response(res.status, res.body, cfg)
    if metrics and usage then metrics("usage", usage) end
    if not answers then return nil, perr2 end
    return answers
  end

  return self
end

return _M
