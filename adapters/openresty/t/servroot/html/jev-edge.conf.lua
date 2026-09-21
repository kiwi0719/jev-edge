return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.1, timeout_ms = 300 },
  rules = { "llm-endpoints" },
  policy = { mode = "monitor", block_threshold = 0.85, suspect_threshold = 0.5 },
  async = { enabled = true, max_async = 8, rep_block_after = 1, rep_block_ttl = 60 },
  breaker = { window_s = 60, min_samples = 2, fail_ratio = 0.5, open_s = 30 },
  
}
