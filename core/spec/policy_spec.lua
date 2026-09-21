local P = require "jev.core.policy"
local V = require "jev.core.verdict"

describe("policy.decide", function()
  local enforce = { mode = "enforce", block_threshold = 0.85, suspect_threshold = 0.5 }
  local monitor = { mode = "monitor", block_threshold = 0.85, suspect_threshold = 0.5 }

  it("blocks in enforce mode above block threshold", function()
    local a, l, async = P.decide(0.9, enforce)
    assert.equals(V.ACTION_BLOCK, a)
    assert.equals(V.MALICIOUS, l)
    assert.is_false(async)
  end)

  it("never blocks in monitor mode", function()
    local a, l = P.decide(0.99, monitor)
    assert.equals(V.ACTION_PASS, a)
    assert.equals(V.MALICIOUS, l)
  end)

  it("flags suspicious band for async", function()
    local a, l, async = P.decide(0.6, enforce)
    assert.equals(V.ACTION_PASS, a)
    assert.equals(V.SUSPICIOUS, l)
    assert.is_true(async)
  end)

  it("passes safe", function()
    local a, l, async = P.decide(0.1, enforce)
    assert.equals(V.ACTION_PASS, a)
    assert.equals(V.SAFE, l)
    assert.is_false(async)
  end)

  it("treats thresholds as inclusive", function()
    assert.equals(V.MALICIOUS, select(2, P.decide(0.85, enforce)))
    assert.equals(V.SUSPICIOUS, select(2, P.decide(0.5, enforce)))
  end)

  it("always passes on error and skipped", function()
    assert.equals(V.ACTION_PASS, (P.on_error()))
    assert.equals(V.ERROR, select(2, P.on_error()))
    assert.equals(V.ACTION_PASS, (P.on_skipped()))
    assert.equals(V.SKIPPED, select(2, P.on_skipped()))
  end)
end)

describe("verdict", function()
  it("fills defaults and clamps score", function()
    local v = V.new({ score = 7 })
    assert.equals(1, v.score)
    assert.equals(V.SKIPPED, v.verdict)
    assert.equals("", v.reason)
    assert.is_false(v.async)
  end)

  it("is flat", function()
    for _, val in pairs(V.new({ reason = "x" })) do
      assert.not_equals("table", type(val))
    end
  end)

  it("encodes reasons for headers", function()
    assert.equals("injection+0.91", V.encode_reason("injection 0.91"))
    assert.equals("a%2Fb", V.encode_reason("a/b"))
    assert.equals(200, #V.encode_reason(string.rep("a", 500)))
  end)

  it("renders headers", function()
    local h = V.headers(V.new({ verdict = V.SAFE, score = 0.123, source = V.SRC_L2 }))
    assert.equals("safe", h["X-Jev-Verdict"])
    assert.equals("0.12", h["X-Jev-Score"])
    assert.equals("l2", h["X-Jev-Source"])
  end)
end)
