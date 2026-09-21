-- Example jev-edge.conf.lua. Copy to /etc/nginx/ and edit.
return {
  jev = {
    provider    = "jev",                 -- "jev" | "openai-compat" | "mock"
    endpoint    = "https://api.typesafe.ai/v1/systemone",
    model       = "jev-latest",
    api_key_env = "TYPESAFE_API_KEY",    -- needs `env TYPESAFE_API_KEY;` in nginx.conf
    timeout_ms  = 300,
    max_inflight = 64,
  },
  rules  = { "llm-endpoints" },
  policy = {
    mode = "monitor",                    -- switch to "enforce" after reviewing a week of logs
    block_threshold   = 0.85,
    suspect_threshold = 0.5,
  },
  cache   = { fp_ttl = 300, rep_ttl = 600, fp_prefix_bytes = 2048 },
  async   = { enabled = true, max_async = 32, rep_block_after = 3, rep_block_ttl = 600 },
  breaker = { window_s = 60, min_samples = 20, fail_ratio = 0.5, open_s = 30 },
}
