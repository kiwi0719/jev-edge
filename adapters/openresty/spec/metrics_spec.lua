-- resty/jev/metrics.lua over a stubbed ngx.shared dict: what an L2 error
-- verdict ran into is counted by kind, from a fixed label set.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path
local verdict = require "jev.core.verdict"

describe("metrics: L2 errors by kind", function()
  local saved_ngx, metrics

  local function dict()
    local data = {}
    return {
      incr = function(_, k, by, init) data[k] = (data[k] or init or 0) + (by or 1); return data[k] end,
      set = function(_, k, v) data[k] = v end,
      get = function(_, k) return data[k] end,
      get_keys = function()
        local keys = {}
        for k in pairs(data) do keys[#keys + 1] = k end
        table.sort(keys)
        return keys
      end,
    }
  end

  before_each(function()
    saved_ngx = _G.ngx
    _G.ngx = { shared = { jev_metrics = dict() } }
    package.loaded["resty.jev.metrics"] = nil
    metrics = require "resty.jev.metrics"
  end)
  after_each(function()
    _G.ngx = saved_ngx
    package.loaded["resty.jev.metrics"] = nil
  end)

  local function err(kind)
    return verdict.new({ verdict = verdict.ERROR, source = verdict.SRC_L2, reason = "x", error_kind = kind })
  end

  it("counts each kind an L2 error verdict names", function()
    local kinds = { "transport", "timeout", "unavailable", "unavailable", "rejected", "unusable", "busy", "other" }
    for _, k in ipairs(kinds) do metrics.record(err(k)) end
    local out = metrics.render()
    assert.matches("# TYPE jev_l2_errors_total counter", out, 1, true)
    assert.matches('jev_l2_errors_total{kind="unavailable"} 2', out, 1, true)
    for _, k in ipairs({ "transport", "timeout", "rejected", "unusable", "busy", "other" }) do
      assert.matches('jev_l2_errors_total{kind="' .. k .. '"} 1', out, 1, true)
    end
    assert.matches('jev_requests_total{source="l2",verdict="error"} 8', out, 1, true)
  end)

  it("folds a kind outside the set into other, and counts no other verdict", function()
    metrics.record(err("made-up"))
    metrics.record(err(""))
    metrics.record(verdict.new({ verdict = verdict.SAFE, source = verdict.SRC_L2, reason = "injection 0.10" }))
    metrics.record(verdict.new({ verdict = verdict.SKIPPED, source = verdict.SRC_BREAKER, reason = "breaker open" }))
    local out = metrics.render()
    assert.matches('jev_l2_errors_total{kind="other"} 2', out, 1, true)
    local n = 0
    for _ in out:gmatch("jev_l2_errors_total{") do n = n + 1 end
    assert.equals(1, n)
  end)
end)
