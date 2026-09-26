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

local adaptive_m = require "resty.jev.adaptive"
local judge      = require "jev.core.judge"

--- The prefix a gateway route (a Kong plugin instance, an APISIX conf) keeps
-- its breaker, adaptive timeout and in-flight counter under. Routes share
-- that state only when they call the same provider, endpoint and model with
-- the same credential and the same tuning (max_inflight, the breaker
-- settings): a route whose key is revoked or over quota, or whose breaker
-- trips on one failure, opens its own breaker and not every other route's,
-- and a max_inflight is only ever compared with calls made under that same
-- cap. The key goes in as a hash, never as it is.
-- @param cfg  merged config (cfg.jev with the key already read, cfg.breaker)
-- @param hash function(string) -> hex digest
function _M.state_prefix(cfg, hash)
  local j, b = cfg.jev or {}, cfg.breaker or {}
  local names = {}
  for k in pairs(b) do names[#names + 1] = k end
  table.sort(names, function(x, y) return tostring(x) < tostring(y) end)
  local tuning = {}
  for i, k in ipairs(names) do tuning[i] = tostring(k) .. "=" .. tostring(b[k]) end
  return "p:" .. hash(table.concat({
    tostring(j.provider or ""), tostring(j.endpoint or ""), tostring(j.model or ""),
    hash(tostring(j.api_key or "")), tostring(j.max_inflight or ""), table.concat(tuning, ","),
  }, "\n")):sub(1, 12) .. ":"
end

--- In-flight slots that come back on their own. A thread nginx kills
-- mid-call (lua_check_client_abort on and the client goes away, or a worker
-- past worker_shutdown_timeout) never runs its release, and a counter that
-- never expires kept that slot for good: after max_inflight such calls every
-- call was refused until the dict was flushed, HUP reloads included.
--
-- A slot is counted under the lease period it was taken in (now / lease) and
-- given back to that same period's counter, and a call is admitted against
-- this period's slots and the previous period's. No call that holds a slot
-- runs as long as a lease, so a slot two periods old belongs to a thread that
-- is gone, and stops counting: a lost release costs its slot for one to two
-- leases. One counter per period, rather than one counter that expires,
-- because the calls in flight when that one expired would give back slots
-- the new counter never counted, and under sustained load the cap would grow
-- by up to max_inflight at every expiry.
-- @param store cache-like object with get / set / incr(key, by, ttl)
-- @param name  counter name ("inflight:l2")
-- @param lease seconds, longer than any call that holds a slot
-- @return { take = function(max) -> slot or nil (over max), give = function(slot) }
function _M.slots(store, name, lease)
  lease = math.max(1, math.ceil(tonumber(lease) or 10))
  local ttl = 3 * lease
  local base = name .. ":" .. lease .. ":"
  local s = {}
  function s.give(slot)
    if not slot then return end
    local n = store:incr(slot, -1, ttl)
    -- an evicted or reset counter: clamp instead of letting the cap grow
    if n and n < 0 then store:set(slot, 0, ttl) end
  end
  function s.take(max)
    local p = math.floor(ngx.now() / lease)
    local slot = base .. p
    local n = store:incr(slot, 1, ttl)
    -- no counter (a missing or full dict): not counted, nothing to give back
    if not n then return false end
    local prev = tonumber(store:get(base .. (p - 1))) or 0
    if n + math.max(prev, 0) > max then
      s.give(slot)
      return nil
    end
    return slot
  end
  return s
end

--- Build a judge object for the current config.
-- @param cfg      cfg.jev section (provider, endpoint, model, api_key, timeout_*, max_inflight)
-- @param inflight cache-like object with get/set/incr (shared dict); also backs the adaptive timeout
-- @param metrics  optional function(usage): token usage the provider reported
function _M.new(cfg, inflight, metrics)
  local provider, perr = _M.load_provider(cfg.provider or "jev")
  if not provider then return nil, perr end

  local adaptive = adaptive_m.new(inflight, cfg)
  local self = { cfg = cfg, provider = provider, inflight = inflight, metrics = metrics, adaptive = adaptive }

  local function now_ms() return ngx.now() * 1000 end

  -- An L2 call, or /_jev/health's, runs at most timeout_max_ms (the
  -- adaptive ceiling) plus the connect; the lease leaves 5 s over that.
  local lease = math.ceil(math.max(tonumber(cfg.timeout_max_ms) or 1000, 5000) / 1000) + 5
  local l2 = inflight and _M.slots(inflight, "inflight:l2", lease)

  -- core passes cfg.jev.timeout_ms and the adaptive estimate (floor..ceiling)
  -- overrides it. A caller asking for MORE than the estimate (L3 with the
  -- ceiling, /_jev/health) gets what it asked for, and such a call does not
  -- feed the adaptive estimate: it is not an L2 sample.
  local function do_call(prompt, requested)
    local est = adaptive:current()
    local req_ms = tonumber(requested)
    local timeout_ms = (req_ms and req_ms > est) and req_ms or est
    local is_l2 = timeout_ms == est

    if provider.local_only then
      local t0 = now_ms()
      local answers, err, kind = provider.call(prompt, cfg, timeout_ms)
      ngx.update_time()
      if is_l2 then
        if answers then adaptive:success(now_ms() - t0)
        elseif tostring(err):find("timeout", 1, true) then adaptive:timeout(timeout_ms) end
      end
      if not answers then return nil, err, kind end
      return answers
    end
    if not http_ok then
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
    ngx.update_time()
    local elapsed = now_ms() - t0

    if not res then
      -- no answer at all; the cosocket names a timeout "timeout"
      local timed_out = tostring(err):find("timeout", 1, true)
      if is_l2 and timed_out then adaptive:timeout(timeout_ms) end
      return nil, tostring(err), timed_out and judge.TIMEOUT or judge.TRANSPORT
    end
    -- req.ctx: per-call state the provider needs to read its own answer
    -- (openai-compat's question set); never stored on the shared cfg table.
    local answers, perr2, usage = provider.parse_response(res.status, res.body, cfg, req.ctx)
    if metrics and usage then metrics(usage) end
    -- Classified by the status, for every provider, custom ones included: a
    -- 200 the provider could not read and a 4xx the judged text provoked are
    -- not the provider failing, and must not trip the breaker (judge.counts).
    if not answers then return nil, perr2, judge.status_kind(res.status) end
    if is_l2 then adaptive:success(elapsed) end
    return answers
  end

  function self.call(prompt, requested_timeout)
    -- Concurrency cap applies to every provider, mock included, so the limit
    -- is exercised by the soak test. The slot is given back after a return
    -- or a Lua error; a thread killed mid-call (a client abort under
    -- lua_check_client_abort, a worker shutdown) never gets there, and its
    -- slot comes back with the lease (_M.slots).
    local slot
    if l2 then
      slot = l2.take(tonumber(cfg.max_inflight) or 64)
      if slot == nil then return nil, judge.BUSY end
    end
    local ok, answers, err, kind = pcall(do_call, prompt, requested_timeout)
    if slot then l2.give(slot) end
    if not ok then return nil, "judge error: " .. tostring(answers) end
    return answers, err, kind
  end

  --- Several prompts at once, one light thread each (text judged in chunks,
  -- core's judge_chunks): the wall time is the slowest call, not the sum.
  -- Each call takes its own in-flight slot. Returns
  -- { { answers, err, kind }, ... } in prompt order.
  function self.call_many(prompts, requested_timeout)
    local results = {}
    if not (ngx and ngx.thread) or #prompts < 2 then
      for i, p in ipairs(prompts) do results[i] = { self.call(p, requested_timeout) } end
      return results
    end
    local threads = {}
    for i, p in ipairs(prompts) do
      local th, serr = ngx.thread.spawn(self.call, p, requested_timeout)
      threads[i] = th or false
      if not th then results[i] = { nil, "thread: " .. tostring(serr) } end
    end
    for i, th in ipairs(threads) do
      if th then
        local ok, answers, err, kind = ngx.thread.wait(th)
        results[i] = ok and { answers, err, kind } or { nil, "judge error: " .. tostring(answers) }
      end
    end
    return results
  end

  return self
end

return _M
