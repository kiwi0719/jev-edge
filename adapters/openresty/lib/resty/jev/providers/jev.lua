-- resty/jev/providers/jev.lua
-- TypeSafe System One HTTP API. One Noul question per template.
-- https://docs.typesafe.ai/api
--
-- The request and response shape is the System One protocol; other servers
-- that speak it (providers/laya.lua) reuse `system_one` with their own name,
-- default model and endpoint. conformance/ checks a server against it.

local cjson = require "cjson.safe"

local _M = { name = "jev" }

-- cfg.questions[name] overrides fields of the bundled template for this
-- provider only: question wording validated on one judge is not validated on
-- another. Only the four wording fields; anything else is ignored.
local WORDING = { "instructions", "criteria", "instructions_ctx", "criteria_ctx" }

local function question(name, t, cfg, deployment)
  local over = type(cfg.questions) == "table" and cfg.questions[name]
  if type(over) == "table" then
    local merged = {}
    for k, v in pairs(t) do merged[k] = v end
    for _, k in ipairs(WORDING) do
      if over[k] ~= nil then merged[k] = over[k] end
    end
    t = merged
  end
  local instr = (deployment and t.instructions_ctx) or t.instructions
  local crit  = (deployment and t.criteria_ctx) or t.criteria
  local q = { type = "noul", instructions = instr }
  if crit then
    -- templates key criteria by boolean; config overrides may use strings
    q.criteria = { ["true"] = crit[true] or crit["true"], ["false"] = crit[false] or crit["false"] }
  end
  return q
end

--- A System One provider.
-- @param name     provider name (error messages)
-- @param defaults { model, url }
function _M.system_one(name, defaults)
  local p = { name = name }

  function p.build_request(prompt, cfg)
    local deployment = prompt.context and prompt.context.deployment
    if deployment == "" then deployment = nil end
    local questions = {}
    for qname, t in pairs(prompt.questions) do
      questions[qname] = question(qname, t, cfg, deployment)
    end
    -- With a deployment context the state is an object, so the question can
    -- refer to `assistant` and `user_message` by name.
    local state = prompt.text
    if deployment then
      state = { assistant = deployment, user_message = prompt.text }
    end
    local body = cjson.encode({
      model     = cfg.model or defaults.model,
      state     = state,
      questions = questions,
    })
    return {
      method  = "POST",
      url     = cfg.endpoint or defaults.url,
      headers = {
        ["Content-Type"]  = "application/json",
        ["Authorization"] = cfg.api_key and ("Bearer " .. cfg.api_key) or nil,
      },
      body = body,
    }
  end

  function p.parse_response(status, body)
    if status ~= 200 then
      return nil, name .. " http " .. tostring(status)
    end
    local decoded = cjson.decode(body)
    if type(decoded) ~= "table" or type(decoded.answers) ~= "table" then
      return nil, name .. ": malformed response"
    end
    local answers = {}
    for qname, a in pairs(decoded.answers) do
      if type(a) == "table" and type(a.noul) == "number" then
        answers[qname] = a.noul
      end
    end
    local usage = type(decoded.usage) == "table" and decoded.usage or nil
    return answers, nil, usage
  end

  return p
end

local jev = _M.system_one("jev", { model = "jev-latest", url = "https://api.typesafe.ai/v1/systemone" })
_M.build_request  = jev.build_request
_M.parse_response = jev.parse_response

return _M
