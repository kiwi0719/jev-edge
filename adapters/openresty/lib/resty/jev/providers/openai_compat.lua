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
    "for the user input that follows. Reply with ONLY a JSON object mapping question id to probability.",
    "",
  }
  for name, t in pairs(questions) do
    lines[#lines + 1] = name .. ": " .. t.instructions
    if t.criteria then
      lines[#lines + 1] = "  YES when: " .. (t.criteria[true] or "")
      lines[#lines + 1] = "  NO when: " .. (t.criteria[false] or "")
    end
  end
  return table.concat(lines, "\n")
end

function _M.build_request(prompt, cfg)
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

function _M.parse_response(status, body)
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
  local out = {}
  for k, v in pairs(answers) do
    if type(v) == "number" then out[k] = v end
  end
  local usage = type(decoded.usage) == "table"
    and { input_tokens = decoded.usage.prompt_tokens, output_tokens = decoded.usage.completion_tokens }
    or nil
  return out, nil, usage
end

return _M
