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
  if v.reason == "subject reputation" then incr("subject_blocks") end
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

-- An async (L3) job that ran, by what it got (resty.jev.async on_result, a
-- fixed set): ok | failed | busy | no_scores | error.
local ASYNC_RESULTS = { ok = true, failed = true, busy = true, no_scores = true, error = true }
function _M.incr_async_result(result)
  if not ASYNC_RESULTS[result] then result = "error" end
  incr("async:" .. result)
end

-- /_jev/authz events a relay's answer hides (a fixed set, so the label
-- cannot be minted by traffic):
--   no_client_ip  neither x-envoy-external-address nor X-Forwarded-For
--                 named the client (no header, or fewer X-Forwarded-For
--                 hops than client_ip.trusted_hops): no IP reputation, no
--                 subject = "ip"
--   cut_at_cap    a body at or past max_body_bytes the gateway did not flag
--                 as cut, taken as cut. It counts what jev-edge did, cut or
--                 not: a body Envoy cut there and called whole, and a whole
--                 one of that size (or larger, where the gateway's cap is
--                 higher). Behind a gateway that answers 413 past its cap
--                 (Envoy Gateway, allow_partial_message: false) every count
--                 is a whole body.
local AUTHZ_EVENTS = { no_client_ip = true, cut_at_cap = true }
function _M.incr_authz(event)
  if AUTHZ_EVENTS[event] then incr("authz:" .. event) end
end

-- A request the adapter failed open on because judging threw (a bad override
-- or rule, a bug): it passed unjudged, and nothing else counts it. entry is
-- the handler it came through, a fixed set so traffic cannot mint labels. It
-- is also counted as jev_requests_total{source="adapter",verdict="error"},
-- so the request-rate queries see that traffic.
local ADAPTER_ENTRIES = { access = true, authz = true, forward_auth = true }
function _M.incr_adapter_error(entry)
  if not ADAPTER_ENTRIES[entry] then entry = "other" end
  incr("adapter_error:" .. entry)
  incr("req:adapter:error")
end

-- The effective adaptive L2 timeout and, when given, the ceiling it is
-- clamped to (jev.timeout_max_ms after adaptive.lua's defaulting), so an
-- alert can tell "pinned at the ceiling" from "high but adapting".
function _M.set_l2_timeout(ms, max_ms)
  local d = dict()
  if not d then return end
  d:set("l2_timeout_ms", ms)
  if max_ms then d:set("l2_timeout_max_ms", max_ms) end
end

-- Operator feedback (POST /_jev/feedback), counted after the token check.
-- label is the normalized label; anything outside the known set is folded
-- into "other" so a caller cannot mint label values. result is what the
-- endpoint did: trusted | refused | revoked | invalid.
local FEEDBACK_LABELS = { benign = true, attack = true }
local FEEDBACK_RESULTS = { trusted = true, refused = true, revoked = true, invalid = true }

function _M.incr_feedback(label, result)
  if not FEEDBACK_LABELS[label] then label = "other" end
  if not FEEDBACK_RESULTS[result] then result = "invalid" end
  incr("feedback:" .. label .. ":" .. result)
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
  line("# TYPE jev_subject_blocks_total counter")
  line("# TYPE jev_l2_timeout_max_ms gauge")
  line("# TYPE jev_feedback_total counter")
  line("# TYPE jev_authz_events_total counter")
  line("# TYPE jev_adapter_errors_total counter")
  line("# TYPE jev_async_total counter")
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
    elseif key:match("^async:") then
      line(string.format('jev_async_total{result="%s"} %d', key:sub(7), val))
    elseif key == "l2_timeout_ms" then
      line("jev_l2_timeout_ms " .. val)
    elseif key:match("^unjudged:") then
      line(string.format('jev_unjudged_total{reason="%s"} %d', key:sub(10), val))
    elseif key == "window" then
      line("jev_window_total " .. val)
    elseif key == "subject_blocks" then
      line("jev_subject_blocks_total " .. val)
    elseif key == "l2_timeout_max_ms" then
      line("jev_l2_timeout_max_ms " .. val)
    elseif key:match("^adapter_error:") then
      line(string.format('jev_adapter_errors_total{entry="%s"} %d', key:sub(15), val))
    elseif key:match("^authz:") then
      line(string.format('jev_authz_events_total{event="%s"} %d', key:sub(7), val))
    elseif key:match("^feedback:") then
      local label, result = key:match("^feedback:([^:]+):(.+)$")
      line(string.format('jev_feedback_total{label="%s",result="%s"} %d', label, result, val))
    end
  end
  return table.concat(out, "\n") .. "\n"
end

return _M
