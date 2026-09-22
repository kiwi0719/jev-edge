local D = require "jev.core.defaults"

describe("defaults.merge", function()
  it("deep merges tables and replaces lists", function()
    local c = D.merge(D.config, { policy = { mode = "enforce" }, rules = { "a", "b" } })
    assert.equals("enforce", c.policy.mode)
    assert.equals(0.7, c.policy.block_threshold)
    assert.same({ "a", "b" }, c.rules)
    assert.equals("monitor", D.config.policy.mode) -- base untouched
  end)
end)

describe("defaults.validate", function()
  it("accepts defaults", function()
    assert.is_true((D.validate(D.merge(D.config))))
  end)

  it("rejects bad mode", function()
    local ok, err = D.validate(D.merge(D.config, { policy = { mode = "yolo" } }))
    assert.is_nil(ok)
    assert.matches("mode", err)
  end)

  it("rejects inverted thresholds", function()
    local ok = D.validate(D.merge(D.config, { policy = { suspect_threshold = 0.9 } }))
    assert.is_nil(ok)
  end)

  it("rejects configs that make a gate degenerate", function()
    for _, over in ipairs({
      { policy = { block_threshold = 5, suspect_threshold = 2 } },
      { policy = { block_status = 42 } },
      { breaker = { window_s = 0 } },
      { breaker = { min_samples = 0 } },
      { breaker = { fail_ratio = 0 } },
      { sampling = { max_samples = 0 } },
      { cache = { fp_ttl = 0 } },
      { async = { max_async = -1 } },
    }) do
      assert.is_nil((D.validate(D.merge(D.config, over))))
    end
  end)

  it("rejects zero timeout", function()
    local ok = D.validate(D.merge(D.config, { jev = { timeout_ms = 0 } }))
    assert.is_nil(ok)
  end)
end)

describe("defaults.validate timeouts", function()
  it("rejects a ceiling below the floor", function()
    local ok, err = D.validate(D.merge(D.config, { jev = { timeout_ms = 500, timeout_max_ms = 300 } }))
    assert.is_nil(ok)
    assert.matches("timeout_max_ms", err)
  end)
end)
