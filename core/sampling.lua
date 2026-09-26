-- core/sampling.lua
-- Decision sampling: keep a share of judged requests (normalized text,
-- fingerprint, score, verdict) so an operator can replay and label them
-- later. Pure: the adapter supplies randomness, the clock and the store.
-- The raw body is never kept; `text` is normalize.normalize() of the
-- extracted text, truncated to sampling.text_bytes, and `tools` the same of
-- the tool definitions (rule.tool_fields), when the request has any: they
-- are judged as a part of their own and may be what scored it. JSON the
-- decoder refused is scanned for them, as L1 scans it.

local normalize = require "jev.core.normalize"
local verdict   = require "jev.core.verdict"
local rules_mod = require "jev.core.rules"

local _M = {}

local RANK = { [verdict.SKIPPED] = -1, [verdict.ERROR] = 0, [verdict.SAFE] = 1,
               [verdict.SUSPICIOUS] = 2, [verdict.MALICIOUS] = 3 }

--- Should this verdict be sampled?
-- @param cfg  merged config (uses cfg.sampling)
-- @param v    verdict
-- @param rand fn() -> [0,1)
function _M.should_sample(cfg, v, rand)
  local sm = cfg.sampling
  if not sm or not sm.enabled then return false end
  if v.source == verdict.SRC_L1 and v.verdict ~= verdict.MALICIOUS then return false end
  local min = RANK[sm.min_verdict or "suspicious"] or 2
  if (RANK[v.verdict] or -1) < min then return false end
  local rate = tonumber(sm.rate) or 0
  if rate <= 0 then return false end
  if rate >= 1 then return true end
  return (rand or math.random)() < rate
end

--- Build the sample record for a verdict.
-- @param cfg   merged config
-- @param v     verdict
-- @param req   core req table
-- @param rule  the rule that matched (for text_fields)
-- @param extra { rid = ..., ts = ..., json_decode = fn }
function _M.build(cfg, v, req, rule, extra)
  extra = extra or {}
  local text, tools = "", nil
  if rule and req and req.body then
    local n = cfg.sampling.text_bytes or 512
    local raw, kind, _, decoded = normalize.extract(req.body, rules_mod.content_type(req.headers), rule.text_fields,
      extra.json_decode)
    text = normalize.normalize(raw, { prefix_bytes = n })
    if type(rule.tool_fields) == "table" and #rule.tool_fields > 0 then
      local ttext = ""
      if type(decoded) == "table" then
        ttext = normalize.extract_tools(decoded, rule.tool_fields, extra.json_decode)
      elseif kind == "scan" then
        ttext = table.concat(normalize.scan_tools(req.body, normalize.field_keys(rule.tool_fields), {}), "\n")
      end
      if ttext ~= "" then tools = normalize.normalize(ttext, { prefix_bytes = n }) end
    end
  end
  return {
    ts = extra.ts or 0, rid = extra.rid or "", path = req and req.path or "", ip = req and req.client_ip or "",
    method = req and req.method or "", fp = v.fingerprint, score = v.score, verdict = v.verdict,
    action = v.action, source = v.source, reason = v.reason, l2_ms = v.l2_ms, text = text, tools = tools,
    -- the rule that judged it: Kong and APISIX routes, and tenants, share
    -- one ring
    rule = rule and rule.id or nil,
  }
end

-- The ring's size, pinned in the store by its first writer ("sample:size"),
-- and the caller's own max_samples. Every writer of one store (Kong and
-- APISIX routes, tenants) shares one "sample:n": a slot each computed with
-- its own size interleaved rings of different sizes, and dump() read stale
-- slots and missed live ones.
local function ring_size(cfg, store, pin)
  local want = math.max(1, math.floor(tonumber(cfg.sampling.max_samples) or 1000))
  local size = tonumber(store:get("sample:size"))
  if not size and pin then
    if store.add then store:add("sample:size", want, 0) else store:set("sample:size", want, 0) end
    size = tonumber(store:get("sample:size"))
  end
  size = size and math.floor(size) or 0
  if size < 1 then size = want end
  return size, want
end

--- Store a sample in the ring: max_samples slots, as the store's first
-- writer set it (see ring_size).
-- store: { get = fn(self,k), set = fn(self,k,v,ttl), incr = fn(self,k,by,ttl),
--          add = fn(self,k,v,ttl) (optional) }
-- @return ok, and true when the caller's max_samples is not the ring's size
--         (its samples go into the pinned ring; the adapter says so once)
function _M.store(cfg, store, sample)
  local sm = cfg.sampling
  local size, want = ring_size(cfg, store, true)
  local n = store:incr("sample:n", 1, 0)
  if not n then return false end
  local slot = (n - 1) % size
  return store:set("sample:" .. slot, sample, sm.ttl or 86400), size ~= want
end

--- Read every live sample from the ring, newest first.
function _M.dump(cfg, store)
  local max = ring_size(cfg, store, false)
  local n = tonumber(store:get("sample:n")) or 0
  local out = {}
  local count = math.min(n, max)
  for i = 0, count - 1 do
    local slot = (n - 1 - i) % max
    local s = store:get("sample:" .. slot)
    if type(s) == "table" then out[#out + 1] = s end
  end
  return out, n
end

--- Clear the ring, and its pinned size: the next writer pins it again.
function _M.clear(cfg, store)
  local size, want = ring_size(cfg, store, false)
  for i = 0, math.max(size, want) - 1 do store:set("sample:" .. i, nil, 0) end
  store:set("sample:n", nil, 0)
  store:set("sample:size", nil, 0)
end

return _M
