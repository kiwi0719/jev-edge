return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.2, timeout_ms = 300 },
  rules = { "llm-endpoints" },
  policy = { mode = "enforce", block_threshold = 0.7, suspect_threshold = 0.5 },
  cache = { fp_ttl = 0.001 },
  -- L1 honours a rep:<ip> block only under a config that blocks by IP
  -- reputation; high enough that the checks' own attacks never add one, so
  -- the only block is the one run.sh writes (/_e2e/poison)
  async = { rep_block_after = 1000 },
}
