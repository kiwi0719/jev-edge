-- Demo config. `mock` answers locally with a fixed score, so the pipeline
-- (L1 rules, cache, policy, headers, hot reload) runs end to end with no key.
-- Export TYPESAFE_API_KEY and the same config judges with the real Jev.
local api_key = os.getenv("TYPESAFE_API_KEY")

return {
  jev = {
    provider = api_key and "jev" or "mock",
    api_key  = api_key,
    model    = "jev-latest",
    -- mock only: the X-Jev-Mock-Score request header overrides the score,
    -- so `-H 'X-Jev-Mock-Score: 0.95'` shows a block without a real model.
    mock_score  = 0.2,
    mock_header = "x-jev-mock-score",
    -- One paragraph on what the protected assistant is for. Only read by the
    -- real provider; it is the setting that decides accuracy.
    deployment_context = "A support assistant on Acme's billing website. It answers customers' "
      .. "questions about invoices, subscription plans, refunds and payment methods. "
      .. "Users are Acme customers. It does not write code, adopt personas, discuss "
      .. "other companies' products, or produce essays, stories or marketing copy.",
  },
  rules  = { "llm-endpoints" },
  -- enforce so the demo can show a 403; production starts in "monitor".
  policy = { mode = "enforce", block_threshold = 0.7, suspect_threshold = 0.5 },
}
