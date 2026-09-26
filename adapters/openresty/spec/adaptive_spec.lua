local H = require "core.spec.helper"

-- adaptive.lua has no ngx dependency, so it is unit-tested here.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path
local A = require "resty.jev.adaptive"

describe("adaptive timeout", function()
  local cache
  before_each(function() cache = H.store() end)

  it("uses the floor until warmup", function()
    local a = A.new(cache, { timeout_ms = 300, timeout_max_ms = 900, timeout_warmup = 3 })
    a:success(800); a:success(800)
    assert.equals(300, a:current())
    a:success(800)
    assert.is_true(a:current() > 300)
  end)

  it("estimates headroom over mean + 2 sd and clamps to the ceiling", function()
    local a = A.new(cache, { timeout_ms = 100, timeout_max_ms = 500, timeout_warmup = 1, timeout_headroom = 1.5 })
    for _ = 1, 50 do a:success(200) end
    assert.equals(300, a:current())          -- 1.5 * 200, sd ~ 0
    for _ = 1, 50 do a:success(2000) end
    assert.equals(500, a:current())          -- ceiling
  end)

  it("never goes below the floor", function()
    local a = A.new(cache, { timeout_ms = 300, timeout_max_ms = 900, timeout_warmup = 1 })
    for _ = 1, 20 do a:success(20) end
    assert.equals(300, a:current())
  end)

  it("climbs on censored timeout samples", function()
    local a = A.new(cache, { timeout_ms = 50, timeout_max_ms = 500, timeout_warmup = 1 })
    local before = a:current()
    for _ = 1, 30 do a:timeout(a:current()) end
    assert.is_true(a:current() > before)
    assert.is_true(a:current() <= 500)
  end)

  it("is a no-op when disabled or without a store", function()
    local a = A.new(cache, { timeout_ms = 300, timeout_adaptive = false, timeout_warmup = 1 })
    for _ = 1, 20 do a:success(900) end
    assert.equals(300, a:current())
    local b = A.new(nil, { timeout_ms = 250 })
    b:success(900)
    assert.equals(250, b:current())
  end)

  it("defaults the ceiling to 2.5x the floor", function()
    local a = A.new(cache, { timeout_ms = 200, timeout_warmup = 1 })
    for _ = 1, 50 do a:success(5000) end
    assert.equals(500, a:current())
  end)
end)

describe("adaptive timeout: a fractional floor", function()
  it("is never undercut by the whole-ms estimate", function()
    local a = A.new(H.store(), { timeout_ms = 300.5, timeout_max_ms = 900, timeout_warmup = 1, timeout_headroom = 1 })
    for _ = 1, 50 do a:success(300.7) end   -- estimate 300.7: floored, 300 < 300.5
    assert.is_true(a:current() >= 300.5)
    assert.equals(300.5, a:current())
    local b = A.new(H.store(), { timeout_ms = 300.5, timeout_max_ms = 900, timeout_warmup = 1, timeout_headroom = 1 })
    for _ = 1, 50 do b:success(400.7) end   -- above the floor: whole ms
    assert.equals(400, b:current())
  end)
end)
