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
  -- Rule sets by id, or inline rules for one gateway that fronts several
  -- assistants. An inline rule starts from `extends` and overrides what it
  -- names; list tenant rules before the general one (first match wins):
  --   rules = {
  --     { id = "billing", extends = "llm-endpoints", watch_paths = { "^/v1/billing" },
  --       deployment_context = "A support assistant for Acme's billing product. ..." },
  --     "llm-endpoints",
  --   },
  rules  = { "llm-endpoints" },
  policy = {
    mode = "monitor",                    -- switch to "enforce" after reviewing a week of logs
    block_threshold   = 0.7,       -- with a deployment_context: 0% FP, 13% miss on deepset; 0.5 = 0.8% FP, 5% miss
    suspect_threshold = 0.5,
  },
  -- fp_prefix_bytes bounds sampled / logged text only; the fingerprint always covers the whole text.
  cache   = { fp_ttl = 300, rep_ttl = 600, fp_prefix_bytes = 2048 },
  async   = { enabled = true, max_async = 32, rep_block_after = 0, rep_block_ttl = 600 },
  -- Who a trajectory belongs to. Off by default. The raw header or cookie is a
  -- credential: it is hashed with `salt` before it is stored or logged, so set
  -- a per-deployment secret. Needs `lua_shared_dict jev_subject` in nginx.conf.
  -- subject = { enabled = true, from = "header", name = "x-api-key", salt = os.getenv("JEV_SUBJECT_SALT"),
  --             history_ttl = 3600, max_entries = 20 },
  -- Decision sampling for replay and labelling: a share of suspicious-and-up
  -- decisions with their normalized text (never the raw body), readable at
  -- /_jev/samples. Turn on during the monitor week, feed the labels to `make calibrate`.
  sampling = { enabled = false, rate = 0.05, min_verdict = "suspicious",
               max_samples = 1000, ttl = 86400, text_bytes = 512 },
  -- False-positive loop: an operator POSTs a fingerprint to /_jev/feedback and
  -- every later request with that exact text passes without an L2 call. Trust
  -- always expires (trust_ttl) and traffic may extend it at most max_renewals
  -- times (~5 weeks), after which the false positive comes back on purpose --
  -- by then it is a rule or deployment_context bug, not a label. The token is
  -- required: this endpoint writes bypasses.
  feedback = { enabled = false, trust_ttl = 604800, max_renewals = 4, token = os.getenv("JEV_FEEDBACK_TOKEN") },
  breaker = { window_s = 60, min_samples = 20, fail_ratio = 0.5, open_s = 30 },
  -- Retrieved content (tool results, and any `fields` path) judged on its own
  -- with the `untrusted` question, in a parallel call; one more provider call
  -- per request that carries it. README, "Retrieved content".
  untrusted = { enabled = false, tool_results = true, fields = {} },
}
