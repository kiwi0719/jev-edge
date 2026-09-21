-- Example jev-edge.conf.lua. Copy to /etc/nginx/ and edit.
return {
  jev = {
    provider    = "jev",                 -- "jev" | "openai-compat" | "mock"
    endpoint    = "https://api.typesafe.ai/v1/systemone",
    model       = "jev-latest",
    api_key_env = "TYPESAFE_API_KEY",    -- needs `env TYPESAFE_API_KEY;` in nginx.conf
    -- L2 timeout: starts at timeout_ms and adapts to observed latency
    -- (headroom x (mean + 2 sd)), never below timeout_ms, never above
    -- timeout_max_ms. Measured from a laptop: jev-latest p50 ~270 ms, p95 ~315 ms.
    timeout_ms       = 400,
    timeout_max_ms   = 1000,
    timeout_headroom = 1.5,
    timeout_adaptive = true,
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
