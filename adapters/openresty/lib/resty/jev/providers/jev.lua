-- resty/jev/providers/jev.lua
-- TypeSafe System One HTTP API. One Noul question per template.
-- https://docs.typesafe.ai/api

local cjson = require "cjson.safe"

local _M = { name = "jev" }

function _M.build_request(prompt, cfg)
  local questions = {}
  for name, t in pairs(prompt.questions) do
    local q = { type = "noul", instructions = t.instructions }
    if t.criteria then
      q.criteria = { ["true"] = t.criteria[true], ["false"] = t.criteria[false] }
    end
    questions[name] = q
  end
  local body = cjson.encode({
    model     = cfg.model or "jev-latest",
    state     = prompt.text,
    questions = questions,
  })
  return {
    method  = "POST",
    url     = cfg.endpoint or "https://api.typesafe.ai/v1/systemone",
    headers = {
      ["Content-Type"]  = "application/json",
      ["Authorization"] = cfg.api_key and ("Bearer " .. cfg.api_key) or nil,
    },
    body = body,
  }
end

function _M.parse_response(status, body)
  if status ~= 200 then
    return nil, "jev http " .. tostring(status)
  end
  local decoded = cjson.decode(body)
  if type(decoded) ~= "table" or type(decoded.answers) ~= "table" then
    return nil, "jev: malformed response"
  end
  local answers = {}
  for name, a in pairs(decoded.answers) do
    if type(a) == "table" and type(a.noul) == "number" then
      answers[name] = a.noul
    end
  end
  local usage = type(decoded.usage) == "table" and decoded.usage or nil
  return answers, nil, usage
end

return _M
