-- resty/jev/providers/mock.lua
-- No network. Returns a configurable score, with optional delay and failure
-- rate, for tests and bench. Config keys (under `jev`):
--   mock_score      number 0..1 (default 0.1)
--   mock_delay_ms   number       (default 0)
--   mock_fail_ratio number 0..1  (default 0)
--   mock_header     string: if set, X-Jev-Mock-Score request header overrides
--                   mock_score (used by Test::Nginx cases)

local _M = { name = "mock", local_only = true }

-- Emulates the HTTP client's hard timeout: a delay longer than timeout_ms
-- sleeps for timeout_ms and then fails, exactly like a read timeout would.
function _M.call(prompt, cfg, timeout_ms)
  local delay = tonumber(cfg.mock_delay_ms) or 0
  local limit = tonumber(timeout_ms) or math.huge
  if delay > 0 then
    if delay > limit then
      ngx.sleep(limit / 1000)
      return nil, "timeout (mock)"
    end
    ngx.sleep(delay / 1000)
  end

  local ratio = tonumber(cfg.mock_fail_ratio) or 0
  if ratio > 0 and math.random() < ratio then
    return nil, "mock failure"
  end

  local score = tonumber(cfg.mock_score) or 0.1
  if cfg.mock_header and ngx.get_phase() ~= "timer" then
    local h = ngx.req.get_headers()[cfg.mock_header]
    if h == "fail" then return nil, "mock failure (header)" end
    if h == "slow" then ngx.sleep(1) end
    local n = tonumber(h)
    if n then score = n end
  end

  local answers = {}
  for name in pairs(prompt.questions) do answers[name] = score end
  return answers, nil, { input_tokens = #(prompt.text or ""), output_tokens = 0 }
end

return _M
