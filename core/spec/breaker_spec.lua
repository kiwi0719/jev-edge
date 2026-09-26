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

  it("claims the probe with the store's atomic add when it has one", function()
    local adds = 0
    local add = store.add
    store.add = function(...) adds = adds + 1; return add(...) end
    b:trip(); clock.advance(31)
    -- a get + set store would let a second worker in between the two calls
    store.get = (function(get) return function(st, k)
      if k:find("probe", 1, true) then return nil end
      return get(st, k)
    end end)(store.get)
    assert.is_true(b:allow())
    assert.is_false(b:allow())
    assert.equals(2, adds)
  end)

  it("still admits one probe on a store without add", function()
    store.add = nil
    b:trip(); clock.advance(31)
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

  it("does not re-trip on the success that follows a probe inside the same window", function()
    -- t = 960 sits at the start of bucket 960..1019, so the probe at t = 991
    -- lands in the window that tripped the breaker.
    local c2 = H.clock(960)
    local b2 = B.new(store, c2.now, { window_s = 60, min_samples = 4, fail_ratio = 0.5, open_s = 30 })
    b2:success(); b2:failure(); b2:failure(); b2:failure()
    assert.equals(B.OPEN, b2:state())
    c2.advance(31)
    assert.is_true(b2:allow())
    b2:success()
    assert.equals(B.CLOSED, b2:state())
    b2:success()
    assert.equals(B.CLOSED, b2:state(), "a success after closing must not trip on the old failures")
  end)

  it("re-opens on a failed probe", function()
    b:trip(); clock.advance(31)
    assert.is_true(b:allow())
    b:failure()
    assert.equals(B.OPEN, b:state())
  end)

  it("a released probe neither re-opens nor closes, and the next request probes", function()
    b:trip(); clock.advance(31)
    assert.is_true(b:allow())
    assert.is_false(b:allow())
    b:release()
    assert.equals(B.HALF_OPEN, b:state())
    assert.is_true(b:allow(), "the probe is free again")
    assert.is_false(b:allow(), "still one probe at a time")
    b:success()
    assert.equals(B.CLOSED, b:state())
  end)

  it("release counts nothing and leaves closed and open alone", function()
    b:success(); b:failure(); b:failure()
    for _ = 1, 10 do b:release() end
    assert.equals(B.CLOSED, b:state())
    b:failure()
    assert.equals(B.OPEN, b:state(), "the window holds the same 1 ok / 3 fail as without the releases")
    b:release()
    assert.equals(B.OPEN, b:state())
    assert.is_false(b:allow())
  end)

  it("uses a fresh window after window_s", function()
    b:failure(); b:failure(); b:failure()
    clock.advance(61)
    b:failure()
    assert.equals(B.CLOSED, b:state())
  end)
end)
