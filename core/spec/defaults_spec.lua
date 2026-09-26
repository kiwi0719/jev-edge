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
      -- a block is a 4xx (openresty-edge#5)
      { policy = { block_status = 200 } },
      { policy = { block_status = 302 } },
      { policy = { block_status = 503 } },
      { policy = { block_status = 403.5 } },
      { policy = { block_status = "403" } },
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

  -- keys the request path reads as strings (openresty-edge#4): a table, a
  -- number or JSON null (cjson.null is userdata; io.stdout stands in for it)
  it("wants block_body and the judge's settings to be strings", function()
    local NULL = io.stdout
    for _, c in ipairs({
      { { policy = { block_body = { error = "blocked" } } }, "policy.block_body must be a string" },
      { { policy = { block_body = NULL } }, "policy.block_body must be a string" },
      { { jev = { provider = 123 } }, "jev.provider must be a string" },
      { { jev = { provider = NULL } }, "jev.provider must be a string" },
      { { jev = { provider = "" } }, "jev.provider must be a non-empty string" },
      { { jev = { model = {} } }, "jev.model must be a string" },
      { { jev = { endpoint = NULL } }, "jev.endpoint must be a string" },
      { { jev = { api_key = 42 } }, "jev.api_key must be a string" },
      { { jev = { api_key_env = true } }, "jev.api_key_env must be a string" },
      { { jev = { deployment_context = { "a" } } }, "jev.deployment_context must be a string" },
    }) do
      local ok, err = D.validate(D.merge(D.config, c[1]))
      assert.is_nil(ok, c[2])
      assert.equals(c[2], err)
    end
    assert.is_true(D.validate(D.merge(D.config, { policy = { block_body = '{"error":"blocked"}' },
      jev = { provider = "openai-compat", model = "m", endpoint = "http://j/v1", api_key = "k",
              api_key_env = "K", deployment_context = "A support assistant." } })))
  end)

  it("takes any 4xx as policy.block_status", function()
    for _, st in ipairs({ 400, 403, 429, 451, 499 }) do
      assert.is_true(D.validate(D.merge(D.config, { policy = { block_status = st } })), st)
    end
    local _, err = D.validate(D.merge(D.config, { policy = { block_status = 503 } }))
    assert.equals("policy.block_status must be a 4xx status", err)
  end)

  -- lead-gateways-live#21
  it("takes client_ip.ipv6_prefix as an integer from 1 to 128, 64 by default", function()
    assert.equals(64, D.config.client_ip.ipv6_prefix)
    for _, v in ipairs({ 1, 48, 56, 64, 128 }) do
      assert.is_true((D.validate(D.merge(D.config, { client_ip = { ipv6_prefix = v } }))), v)
    end
    for _, v in ipairs({ 0, 129, 64.5, "64", -1 }) do
      local ok, err = D.validate(D.merge(D.config, { client_ip = { ipv6_prefix = v } }))
      assert.is_nil(ok, tostring(v))
      assert.equals("client_ip.ipv6_prefix must be an integer from 1 to 128", err)
    end
  end)

  it("takes policy.partial = judge | unjudgeable and nothing else", function()
    assert.equals("judge", D.config.policy.partial)
    for _, v in ipairs({ "judge", "unjudgeable" }) do
      assert.is_true((D.validate(D.merge(D.config, { policy = { partial = v } }))))
    end
    for _, v in ipairs({ "block", "pass", true, 1 }) do
      local ok, err = D.validate(D.merge(D.config, { policy = { partial = v } }))
      assert.is_nil(ok)
      assert.matches("policy.partial", err, 1, true)
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

describe("defaults.validate jev.questions", function()
  local function v(q) return D.validate(D.merge(D.config, { jev = { questions = q } })) end
  it("accepts wording overrides", function()
    local q = { instructions = "Is this an attack?", criteria = { ["true"] = "a", ["false"] = "b" } }
    assert.is_true((v({ injection = q })))
  end)
  it("rejects a non-table entry or an empty instruction", function()
    assert.is_nil((v({ injection = "x" })))
    local ok, err = v({ injection = { instructions = "" } })
    assert.is_nil(ok)
    assert.matches("jev.questions.injection.instructions", err, 1, true)
    assert.is_nil((v({ injection = { criteria_ctx = "x" } })))
  end)
end)

describe("defaults.validate untrusted.templates", function()
  local function check(u)
    return D.validate(D.merge(D.config, { untrusted = u }))
  end

  it("wants names judge knows", function()
    assert.is_true(check({ templates = { "untrusted", "injection" } }))
    local ok, err = check({ templates = { "untrusted", "untrustd" } })
    assert.is_nil(ok)
    assert.equals("untrusted.templates[2] untrustd is not a template", err)
    ok, err = check({ templates = {} })
    assert.is_nil(ok)
    assert.equals("untrusted.templates must not be empty", err)
    assert.is_nil((check({ templates = "untrusted" })))
    assert.is_nil((check({ fields = { a = "x" } })))
  end)
end)
