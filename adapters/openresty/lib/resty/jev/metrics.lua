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

-- Families in the order render() emits them. Each is its TYPE line followed
-- at once by all of its samples: Prometheus 3 (and OpenMetrics parsers)
-- want a family in one block, and the native-histogram conversion (NHCB)
-- skips a histogram whose lines are interleaved with other families.
local FAMILIES = {
  { "jev_requests_total", "counter" },
  { "jev_actions_total", "counter" },
  { "jev_cache_hits_total", "counter" },
  { "jev_l2_latency_ms", "histogram" },
  { "jev_tokens_total", "counter" },
  { "jev_breaker_state", "gauge" },
  { "jev_async_dropped_total", "counter" },
  { "jev_l2_timeout_ms", "gauge" },
  { "jev_unjudged_total", "counter" },
  { "jev_window_total", "counter" },
  { "jev_subject_blocks_total", "counter" },
  { "jev_l2_timeout_max_ms", "gauge" },
  { "jev_feedback_total", "counter" },
  { "jev_authz_events_total", "counter" },
  { "jev_adapter_errors_total", "counter" },
  { "jev_async_total", "counter" },
}

-- One dict key as { family, sample line }, or nil for a key render() emits
-- by itself (the histogram's) or does not know.
local function sample_of(key, val)
  local src, verdict = key:match("^req:([^:]+):(.+)$")
  if src then
    return "jev_requests_total", string.format('jev_requests_total{source="%s",verdict="%s"} %d', src, verdict, val)
  elseif key:match("^action:") then
    return "jev_actions_total", string.format('jev_actions_total{action="%s"} %d', key:sub(8), val)
  elseif key:match("^cache_hit:") then
    return "jev_cache_hits_total", string.format('jev_cache_hits_total{kind="%s"} %d', key:sub(11), val)
  elseif key:match("^tokens:") then
    return "jev_tokens_total", string.format('jev_tokens_total{direction="%s"} %d', key:sub(8), val)
  elseif key == "breaker_state" then
    return "jev_breaker_state", "jev_breaker_state " .. val
  elseif key == "async_dropped" then
    return "jev_async_dropped_total", "jev_async_dropped_total " .. val
  elseif key:match("^async:") then
    return "jev_async_total", string.format('jev_async_total{result="%s"} %d', key:sub(7), val)
  elseif key == "l2_timeout_ms" then
    return "jev_l2_timeout_ms", "jev_l2_timeout_ms " .. val
  elseif key:match("^unjudged:") then
    return "jev_unjudged_total", string.format('jev_unjudged_total{reason="%s"} %d', key:sub(10), val)
  elseif key == "window" then
    return "jev_window_total", "jev_window_total " .. val
  elseif key == "subject_blocks" then
    return "jev_subject_blocks_total", "jev_subject_blocks_total " .. val
  elseif key == "l2_timeout_max_ms" then
    return "jev_l2_timeout_max_ms", "jev_l2_timeout_max_ms " .. val
  elseif key:match("^adapter_error:") then
    return "jev_adapter_errors_total", string.format('jev_adapter_errors_total{entry="%s"} %d', key:sub(15), val)
  elseif key:match("^authz:") then
    return "jev_authz_events_total", string.format('jev_authz_events_total{event="%s"} %d', key:sub(7), val)
  elseif key:match("^feedback:") then
    local label, result = key:match("^feedback:([^:]+):(.+)$")
    if label then
      return "jev_feedback_total",
        string.format('jev_feedback_total{label="%s",result="%s"} %d', label, result, val)
    end
  end
  return nil
end

-- The L2 latency histogram, complete: every bucket in ascending le, +Inf,
-- then _sum and _count. record() creates a bucket key only for a call that
-- fell in it, so a bucket below the fastest call has no key; it is 0, not
-- absent (a histogram missing buckets is dropped or misread).
local function histogram_lines(d, out)
  local count = d:get("l2_count")
  if not count then return end
  for _, b in ipairs(BUCKETS) do
    out[#out + 1] = string.format('jev_l2_latency_ms_bucket{le="%d"} %d', b, d:get("l2_le:" .. b) or 0)
  end
  out[#out + 1] = string.format('jev_l2_latency_ms_bucket{le="+Inf"} %d', d:get("l2_le:inf") or count)
  out[#out + 1] = "jev_l2_latency_ms_sum " .. (d:get("l2_sum_ms") or 0)
  out[#out + 1] = "jev_l2_latency_ms_count " .. count
end

function _M.render()
  local d = dict()
  if not d then return "# jev_metrics shared dict not defined\n" end
  -- one pass over the dict, samples grouped by family (sorted within one,
  -- so a scrape does not depend on the dict's key order)
  local by = {}
  for _, key in ipairs(d:get_keys(0)) do
    local val = d:get(key)
    if val ~= nil then
      local fam, line = sample_of(key, val)
      if fam then
        by[fam] = by[fam] or {}
        by[fam][#by[fam] + 1] = line
      end
    end
  end
  local out = {}
  for _, f in ipairs(FAMILIES) do
    local name, kind = f[1], f[2]
    out[#out + 1] = "# TYPE " .. name .. " " .. kind
    if kind == "histogram" then
      histogram_lines(d, out)
    elseif by[name] then
      table.sort(by[name])
      for _, line in ipairs(by[name]) do out[#out + 1] = line end
    end
  end
  return table.concat(out, "\n") .. "\n"
end

return _M
