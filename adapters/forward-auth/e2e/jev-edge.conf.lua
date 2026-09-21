return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.2, timeout_ms = 300 },
  rules = { "llm-endpoints" },
  policy = { mode = "enforce", block_threshold = 0.7, suspect_threshold = 0.5 },
  cache = { fp_ttl = 0.001 },
}
