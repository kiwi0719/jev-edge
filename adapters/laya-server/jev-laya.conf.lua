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

    -- L2 timeout. Under steady traffic the adaptive timeout sits at its
    -- floor (timeout_ms), so the floor must cover the slowest text a client
    -- can send, not the typical one: a timeout passes the request unjudged
    -- and counts toward the breaker. On CPU a text split in N windows costs
    -- about N model calls (laya-server batches the windows, which saves the
    -- per-call overhead, not the compute). At max_judge_bytes = 4096 a text
    -- of punctuation and rare letters, about one token per byte, needs ~6
    -- windows with the deployment-context wording: ~200 ms at the ~33 ms per
    -- window Laya is reported at on CPU, and 500 ms is 2.5x that, for one
    -- at a time. A client can also send max_inflight of them at once. Measure
    -- yours with
    --   make conformance ENDPOINT=... BUDGET_MS=<timeout_ms>
    -- It times a short text and that worst case, alone and max_inflight
    -- (--concurrency) at once, passes a p99 of at most half of timeout_ms
    -- (the gateway reads for 60% of it), and prints the timeout_ms to set:
    -- 2-3x the worst-case p99 at max_inflight, or the max_inflight the
    -- server holds in time. Size the floor from that line, never from the
    -- short-text p99, which can be 30x smaller. If the result is more than
    -- one request may add to your latency, lower max_judge_bytes (below) or
    -- max_inflight and measure again, add CPUs, or run the model on a GPU
    -- (LAYA_ORT_PROVIDERS), which runs the windows of a batch in parallel.
    -- laya-server's queue wait (LAYA_QUEUE_MS, 50 ms) is sized for this
    -- floor: a 503 must come while the gateway still reads. The ceiling is
    -- what one request may add when the server as a whole slows down.
    timeout_ms       = 500,
    timeout_max_ms   = 800,
    timeout_headroom = 1.5,
    timeout_adaptive = true,
    -- laya-server's listen backlog (LAYA_BACKLOG, default 1024) must be at
    -- least the sum of max_inflight over every gateway that calls it. The
    -- kernel drops connections past the backlog, each dropped connection is
    -- an L2 timeout, and once half the calls in the breaker's window fail,
    -- L2 is off for every tenant. conformance/run.py opens --concurrency
    -- (64) connections at once to check it, and sends that many worst-case
    -- texts at once: a server that cannot score them in time answers some
    -- with 503, which also passes the request and counts toward the breaker.
    -- Lower max_inflight to what the run says the server holds, or add CPUs.
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
  -- pass. It also sets the worst-case latency above: fewer bytes, fewer
  -- windows. Text past max_judge_bytes is handled by the gateway as for
  -- jev (window around the suspicious part, or max_judge_chunks), and that
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
