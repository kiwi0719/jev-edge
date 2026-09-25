-- jev-edge config profile for a fine-tuned Laya model behind laya-server.
-- Copy to /etc/nginx/jev-edge.conf.lua and edit. Everything not set here is
-- the jev default (core/defaults.lua); the values below are the ones that
-- must NOT be the jev default for Laya.
--
-- The base Laya model is not usable for this task without fine-tuning, so no
-- benchmark numbers and no thresholds ship for it (README.md, "Laya").
return {
  jev = {
    provider    = "laya",                -- own cache entries and log field, apart from jev
    endpoint    = "http://laya-server:8080/v1/systemone",
    model       = "laya",                -- change with each fine-tuned build: the verdict
                                         -- cache is keyed by it, and calibrate splits on it
    api_key_env = "LAYA_API_KEY",        -- needs `env LAYA_API_KEY;` in nginx.conf; drop if unset

    -- L2 timeout. jev's 400 ms floor / 1000 ms ceiling are sized for a
    -- ~300 ms remote API. Laya is reported at ~33 ms per window; with that
    -- floor a Laya server ten times slower than normal would never time out,
    -- and the slowdown would show up late. Measure yours with
    --   make conformance ENDPOINT=... BUDGET_MS=...
    -- (p50 / p99 over 50 requests) and set the floor to ~2-3x p99, the
    -- ceiling to what one request may add to your latency. laya-server
    -- scores all windows of a long text in one batch, so a long text costs
    -- about one model call, not one per window.
    timeout_ms       = 100,
    timeout_max_ms   = 300,
    timeout_headroom = 1.5,
    timeout_adaptive = true,
    -- laya-server's listen backlog (LAYA_BACKLOG, default 1024) must be at
    -- least the sum of max_inflight over every gateway that calls it. The
    -- kernel drops connections past the backlog, each dropped connection is
    -- an L2 timeout, and once half the calls in the breaker's window fail,
    -- L2 is off for every tenant. conformance/run.py opens --concurrency
    -- (64) connections at once to check it.
    max_inflight = 64,

    -- Question wording for this provider only. The bundled wording was
    -- validated against jev (jev-sec-bench), not against Laya. Leave these out
    -- to send the bundled wording; if you fine-tune on other wording, put it
    -- here so the gateway sends what the model learned. Any field of a
    -- template can be replaced: instructions, criteria, instructions_ctx,
    -- criteria_ctx. conformance/questions.json has the bundled wording.
    -- questions = {
    --   injection = { instructions = "...", criteria = { ["true"] = "...", ["false"] = "..." } },
    -- },
  },

  -- The judging window. An L2 error always passes the request (fail open),
  -- so laya-server must never have to refuse a text as too long: that would
  -- make "send a long text" a bypass. laya-server judges long text in
  -- overlapping windows (LAYA_MAX_TOKENS, default 1024, per window; at most
  -- LAYA_MAX_WINDOWS, default 8) and refuses beyond that with 413.
  --
  -- max_judge_bytes = 4096 keeps every text inside that limit even at one
  -- byte per token, the worst a hostile text can force a byte-level
  -- tokenizer into: with ~400 tokens taken by the question and a short
  -- deployment_context, 8 windows cover ~4300 tokens. Longer deployment
  -- contexts leave less room per window: lower max_judge_bytes, or raise
  -- LAYA_MAX_WINDOWS, until `make conformance` and your own longest texts
  -- pass. Text past max_judge_bytes is handled by the gateway as for jev
  -- (window around the suspicious part, or max_judge_chunks), and that
  -- shows up in the verdict reason, never silently.
  rules = {
    { extends = "llm-endpoints", max_judge_bytes = 4096 },
  },

  policy = {
    -- Monitor until thresholds come from your own traffic. The jev defaults
    -- (0.7 / 0.5) were set on jev's score distribution and mean nothing for
    -- Laya. After a monitor period:
    --   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv PROVIDER=laya MODEL=laya
    -- and put its recommended values here before switching to "enforce".
    mode = "monitor",
    block_threshold   = 0.7,   -- placeholder, NOT calibrated for Laya
    suspect_threshold = 0.5,   -- placeholder, NOT calibrated for Laya
  },

  -- Keep samples during the monitor period: they are what you label.
  sampling = { enabled = true, rate = 0.05, min_verdict = "safe",
               max_samples = 1000, ttl = 86400, text_bytes = 512 },
}
