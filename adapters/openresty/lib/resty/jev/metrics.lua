-- resty/jev/metrics.lua
-- Counters and an L2 latency histogram in a shared dict, rendered as
-- Prometheus text. Missing dict → all calls are no-ops.

local _M = {}

local DICT = "jev_metrics"
local BUCKETS = { 25, 50, 100, 200, 300, 500, 1000 }

local function dict() return ngx.shared[DICT] end

local function incr(key, by)
  local d = dict()
  if d then d:incr(key, by or 1, 0) end
end

function _M.record(v)
  incr("req:" .. v.source .. ":" .. v.verdict)
  incr("action:" .. v.action)
  if v.source == "cache" then incr("cache_hit:fp") end
  -- a watched request nobody could read, by why; a score for a window only
  local unj = v.reason:match("^unjudgeable: (%a[%a%-]*)")
  if unj then incr("unjudged:" .. unj) end
  if v.reason:find("(window)", 1, true) then incr("window") end
  if v.source == "l2" then
    incr("l2_count")
    incr("l2_sum_ms", math.floor(v.l2_ms))
    for _, b in ipairs(BUCKETS) do
      if v.l2_ms <= b then incr("l2_le:" .. b) end
    end
    incr("l2_le:inf")
  end
end

function _M.usage(u)
  if type(u) ~= "table" then return end
  incr("tokens:input", tonumber(u.input_tokens) or 0)
  incr("tokens:output", tonumber(u.output_tokens) or 0)
end

function _M.set_breaker_state(s)
  local d = dict()
  if d then d:set("breaker_state", s) end
end

function _M.incr_async_dropped() incr("async_dropped") end

function _M.set_l2_timeout(ms)
  local d = dict()
  if d then d:set("l2_timeout_ms", ms) end
end

function _M.render()
  local d = dict()
  if not d then return "# jev_metrics shared dict not defined\n" end
  local out = {}
  local function line(s) out[#out + 1] = s end
  line("# TYPE jev_requests_total counter")
  line("# TYPE jev_actions_total counter")
  line("# TYPE jev_cache_hits_total counter")
  line("# TYPE jev_l2_latency_ms histogram")
  line("# TYPE jev_tokens_total counter")
  line("# TYPE jev_breaker_state gauge")
  line("# TYPE jev_async_dropped_total counter")
  line("# TYPE jev_l2_timeout_ms gauge")
  line("# TYPE jev_unjudged_total counter")
  line("# TYPE jev_window_total counter")
  for _, key in ipairs(d:get_keys(0)) do
    local val = d:get(key)
    local src, verdict = key:match("^req:([^:]+):(.+)$")
    if src then
      line(string.format('jev_requests_total{source="%s",verdict="%s"} %d', src, verdict, val))
    elseif key:match("^action:") then
      line(string.format('jev_actions_total{action="%s"} %d', key:sub(8), val))
    elseif key:match("^cache_hit:") then
      line(string.format('jev_cache_hits_total{kind="%s"} %d', key:sub(11), val))
    elseif key:match("^l2_le:") then
      line(string.format('jev_l2_latency_ms_bucket{le="%s"} %d', key:sub(7) == "inf" and "+Inf" or key:sub(7), val))
    elseif key == "l2_sum_ms" then
      line("jev_l2_latency_ms_sum " .. val)
    elseif key == "l2_count" then
      line("jev_l2_latency_ms_count " .. val)
    elseif key:match("^tokens:") then
      line(string.format('jev_tokens_total{direction="%s"} %d', key:sub(8), val))
    elseif key == "breaker_state" then
      line("jev_breaker_state " .. val)
    elseif key == "async_dropped" then
      line("jev_async_dropped_total " .. val)
    elseif key == "l2_timeout_ms" then
      line("jev_l2_timeout_ms " .. val)
    elseif key:match("^unjudged:") then
      line(string.format('jev_unjudged_total{reason="%s"} %d', key:sub(10), val))
    elseif key == "window" then
      line("jev_window_total " .. val)
    end
  end
  return table.concat(out, "\n") .. "\n"
end

return _M
