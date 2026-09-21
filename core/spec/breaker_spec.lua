local H = require "core.spec.helper"
local B = require "jev.core.breaker"

describe("breaker", function()
  local store, clock, b
  before_each(function()
    store = H.store()
    clock = H.clock(1000)
    b = B.new(store, clock.now, { window_s = 60, min_samples = 4, fail_ratio = 0.5, open_s = 30 })
  end)

  it("starts closed and allows", function()
    assert.equals(B.CLOSED, b:state())
    assert.is_true(b:allow())
  end)

  it("stays closed under min_samples", function()
    b:failure(); b:failure(); b:failure()
    assert.equals(B.CLOSED, b:state())
  end)

  it("trips once fail ratio is reached", function()
    b:success(); b:failure(); b:failure(); b:failure()
    assert.equals(B.OPEN, b:state())
    assert.is_false(b:allow())
  end)

  it("goes half-open after open_s and admits exactly one probe", function()
    b:trip()
    clock.advance(31)
    assert.equals(B.HALF_OPEN, b:state())
    assert.is_true(b:allow())
    assert.is_false(b:allow())
  end)

  it("closes on a successful probe", function()
    b:trip(); clock.advance(31)
    assert.is_true(b:allow())
    b:success()
    assert.equals(B.CLOSED, b:state())
    assert.is_true(b:allow())
  end)

  it("re-opens on a failed probe", function()
    b:trip(); clock.advance(31)
    assert.is_true(b:allow())
    b:failure()
    assert.equals(B.OPEN, b:state())
  end)

  it("uses a fresh window after window_s", function()
    b:failure(); b:failure(); b:failure()
    clock.advance(61)
    b:failure()
    assert.equals(B.CLOSED, b:state())
  end)
end)
