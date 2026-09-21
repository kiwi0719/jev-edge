-- resty/jev/providers/openai_compat.lua
-- Any OpenAI-compatible chat endpoint (vLLM, Ollama, cloud APIs).
-- The model is asked to answer every question with a probability and to
-- reply with a single JSON object; anything else is treated as an error.

local cjson = require "cjson.safe"

local _M = { name = "openai-compat" }

local function system_prompt(questions)
  local lines = {
    "You are a security classifier for an API gateway.",
    "For each question below, estimate the probability (0.0 to 1.0) that the answer is YES",
    "for the user input that follows. Reply with ONLY a JSON object whose keys are exactly the",
    "question ids and whose values are numbers between 0 and 1. No other keys, no prose.",
    "",
  }
  local example = {}
  for name, t in pairs(questions) do
    lines[#lines + 1] = "question id \"" .. name .. "\": " .. t.instructions
    if t.criteria then
      lines[#lines + 1] = "  YES when: " .. (t.criteria[true] or "")
      lines[#lines + 1] = "  NO when: " .. (t.criteria[false] or "")
    end
    example[#example + 1] = '"' .. name .. '": 0.0'
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Example reply: {" .. table.concat(example, ", ") .. "}"
  return table.concat(lines, "\n")
end

function _M.build_request(prompt, cfg)
  local wanted = {}
  for name in pairs(prompt.questions) do wanted[name] = true end
  cfg._questions = wanted
  local endpoint = (cfg.endpoint or "http://127.0.0.1:11434/v1"):gsub("/+$", "")
  local body = cjson.encode({
    model = cfg.model or "gpt-4o-mini",
    temperature = 0,
    max_tokens = 200,
    response_format = { type = "json_object" },
    messages = {
      { role = "system", content = system_prompt(prompt.questions) },
      { role = "user",   content = prompt.text },
    },
  })
  return {
    method  = "POST",
    url     = endpoint .. "/chat/completions",
    headers = {
      ["Content-Type"]  = "application/json",
      ["Authorization"] = cfg.api_key and ("Bearer " .. cfg.api_key) or nil,
    },
    body = body,
  }
end

function _M.parse_response(status, body, cfg)
  if status ~= 200 then
    return nil, "openai-compat http " .. tostring(status)
  end
  local decoded = cjson.decode(body)
  local content = decoded and decoded.choices and decoded.choices[1]
    and decoded.choices[1].message and decoded.choices[1].message.content
  if type(content) ~= "string" then
    return nil, "openai-compat: no content"
  end
  -- tolerate fenced or prefixed output
  local json = content:match("{.*}")
  local answers = json and cjson.decode(json)
  if type(answers) ~= "table" then
    return nil, "openai-compat: content is not JSON"
  end
  -- Tolerate small models: numeric strings, and a lone "probability"/"score"
  -- key when exactly one question was asked.
  local out, n = {}, 0
  local wanted = cfg and cfg._questions
  for k, v in pairs(answers) do
    local num = tonumber(v)
    if num and (not wanted or wanted[k]) then out[k] = num; n = n + 1 end
  end
  if n == 0 and wanted then
    local only, count = nil, 0
    for k in pairs(wanted) do only = k; count = count + 1 end
    if count == 1 then
      local v = tonumber(answers.probability or answers.score or answers.p or answers[only])
      if v then out[only] = v; n = 1 end
    end
  end
  if n == 0 then return nil, "openai-compat: no numeric answers in " .. content:sub(1, 120) end
  local usage = type(decoded.usage) == "table"
    and { input_tokens = decoded.usage.prompt_tokens, output_tokens = decoded.usage.completion_tokens }
    or nil
  return out, nil, usage
end

return _M
