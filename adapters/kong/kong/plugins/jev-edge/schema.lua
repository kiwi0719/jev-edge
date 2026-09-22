-- kong/plugins/jev-edge/schema.lua
-- Plugin config for Kong 3.x. Same keys as the Lua config file and the APISIX
-- plugin (jev, rules, policy, cache, breaker, async, subject, sampling), in
-- Kong's schema DSL. No field carries a default here: an unset field stays
-- unset and core's defaults (core/defaults.lua) fill it, so the three
-- adapters cannot drift on a default.
--
-- One deviation: Kong's typedefs cannot express "a string or a table" in one
-- array, so rules come in two fields:
--   rules       array of rule set ids under rules/ ("llm-endpoints", ...)
--   rules_json  the full rules list as JSON, ids and inline rules mixed,
--               exactly the APISIX / Lua-config `rules` value; when set it
--               replaces `rules`.

require("resty.jev.loader")()

local typedefs  = require("kong.db.schema.typedefs")
local defaults  = require("jev.core.defaults")
local rules_mod = require("jev.core.rules")
local cjson     = require("cjson.safe")

local null = ngx.null

-- Kong hands unset fields to validators as ngx.null; core expects them absent.
local function strip_nulls(t)
  if type(t) ~= "table" then return t end
  local out = {}
  for k, v in pairs(t) do
    if v ~= null then out[k] = strip_nulls(v) end
  end
  return out
end

local function load_rule(id)
  local ok, r = pcall(require, "jev.rules." .. id)
  if ok then return r end
  -- the require error lists every searched path; the id is what matters
  return nil, "rule set '" .. tostring(id) .. "' not found (jev.rules." .. tostring(id) .. ")"
end

local function decode_rules_json(s)
  local specs, err = cjson.decode(s)
  if type(specs) ~= "table" or #specs == 0 then
    return nil, "rules_json must be a non-empty JSON array" .. (err and (": " .. err) or "")
  end
  return specs
end

local function check_rules_json(s)
  local specs, err = decode_rules_json(s)
  if not specs then return nil, err end
  local _, rerr = rules_mod.resolve_all(specs, load_rule)
  if rerr then return nil, rerr end
  return true
end

local function check_rule_ids(ids)
  local _, err = rules_mod.resolve_all(ids, load_rule)
  if err then return nil, err end
  return true
end

local unit = { 0, 1 }

return {
  name = "jev-edge",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        { jev = {
          type = "record",
          fields = {
            { provider           = { type = "string", one_of = { "jev", "openai-compat", "mock" } } },
            { endpoint           = { type = "string" } },
            { model              = { type = "string" } },
            -- a {vault://env/...} reference works here too
            { api_key            = { type = "string", referenceable = true } },
            { api_key_env        = { type = "string" } },
            { deployment_context = { type = "string" } },
            { timeout_ms         = { type = "integer", gt = 0 } },
            { timeout_max_ms     = { type = "integer", gt = 0 } },
            { timeout_adaptive   = { type = "boolean" } },
            { max_inflight       = { type = "integer", gt = 0 } },
            -- mock provider knobs, for tests
            { mock_score         = { type = "number", between = unit } },
            { mock_header        = { type = "string" } },
            { mock_delay_ms      = { type = "integer", between = { 0, 60000 } } },
            { mock_fail_ratio    = { type = "number", between = unit } },
          },
        } },
        { rules = {
          type = "array", len_min = 1,
          elements = { type = "string", match = "^[%w_%-]+$" },
          custom_validator = check_rule_ids,
        } },
        { rules_json = { type = "string", custom_validator = check_rules_json } },
        { subject = {
          type = "record",
          fields = {
            { enabled     = { type = "boolean" } },
            { from        = { type = "string", one_of = { "ip", "header", "cookie" } } },
            { name        = { type = "string" } },
            { salt        = { type = "string", referenceable = true } },
            { hashed      = { type = "boolean" } },
            { history_ttl = { type = "number", gt = 0 } },
            { max_entries = { type = "integer", gt = 0 } },
          },
        } },
        { sampling = {
          type = "record",
          fields = {
            { enabled     = { type = "boolean" } },
            { rate        = { type = "number", between = unit } },
            { min_verdict = { type = "string", one_of = { "safe", "suspicious", "malicious" } } },
            { max_samples = { type = "integer", gt = 0 } },
            { ttl         = { type = "number", between = { 0, 31536000 } } },
            { text_bytes  = { type = "integer", gt = 0 } },
            { log         = { type = "boolean" } },
          },
        } },
        { policy = {
          type = "record",
          fields = {
            { mode              = { type = "string", one_of = { "monitor", "enforce" } } },
            { block_threshold   = { type = "number", between = unit } },
            { suspect_threshold = { type = "number", between = unit } },
            { block_status      = { type = "integer", between = { 200, 599 } } },
            { block_body        = { type = "string" } },
            { unjudgeable       = { type = "string", one_of = { "pass", "block" } } },
          },
        } },
        { cache = {
          type = "record",
          fields = {
            { fp_ttl          = { type = "number", gt = 0 } },
            { rep_ttl         = { type = "number", gt = 0 } },
            { fp_prefix_bytes = { type = "integer", gt = 0 } },
          },
        } },
        { breaker = {
          type = "record",
          fields = {
            { window_s    = { type = "number", gt = 0 } },
            { min_samples = { type = "integer", gt = 0 } },
            { fail_ratio  = { type = "number", between = unit } },
            { open_s      = { type = "number", gt = 0 } },
          },
        } },
        { async = {
          type = "record",
          fields = {
            { enabled         = { type = "boolean" } },
            { max_async       = { type = "integer", between = { 0, 100000 } } },
            { rep_block_after = { type = "integer", between = { 0, 100000 } } },
            { rep_block_ttl   = { type = "number", gt = 0 } },
          },
        } },
        -- Kong-only: also write the decision as one JSON line to the error
        -- log (it always goes to the serializer as `jev` for the log plugins).
        { log_line = { type = "boolean" } },
      },
    } },
  },
  entity_checks = {
    -- cross-field checks (thresholds order, timeout_max_ms >= timeout_ms,
    -- subject salt, ...) are core's, run on the merged config
    { custom_entity_check = {
      field_sources = { "config" },
      fn = function(entity)
        local conf = strip_nulls(entity.config)
        local merged = defaults.merge(defaults.config, conf)
        local ok, err = defaults.validate(merged)
        if not ok then return nil, err end
        return true
      end,
    } },
  },
}
