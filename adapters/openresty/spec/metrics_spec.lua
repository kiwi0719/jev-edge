-- resty/jev/metrics.lua against a stand-in jev_metrics dict.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path

describe("metrics: async results", function()
  local metrics, saved_ngx, data
  setup(function()
    saved_ngx = _G.ngx
    package.loaded["resty.jev.metrics"] = nil
  end)
  teardown(function()
    _G.ngx = saved_ngx
    package.loaded["resty.jev.metrics"] = nil
  end)
  before_each(function()
    data = {}
    local keys = {}
    local dict = {
      incr = function(_, k, by, init)
        if data[k] == nil then
          if init == nil then return nil, "not found" end
          data[k] = init
          keys[#keys + 1] = k
        end
        data[k] = data[k] + by
        return data[k]
      end,
      set = function(_, k, v) if data[k] == nil then keys[#keys + 1] = k end; data[k] = v end,
      get = function(_, k) return data[k] end,
      get_keys = function() return keys end,
    }
    _G.ngx = { shared = { jev_metrics = dict } }
    package.loaded["resty.jev.metrics"] = nil
    metrics = require "resty.jev.metrics"
  end)

  it("counts each L3 outcome as jev_async_total{result}", function()
    metrics.incr_async_result("ok")
    metrics.incr_async_result("ok")
    metrics.incr_async_result("failed")
    metrics.incr_async_result("busy")
    metrics.incr_async_result("no_scores")
    metrics.incr_async_result("error")
    local out = metrics.render()
    assert.truthy(out:find("# TYPE jev_async_total counter\n", 1, true))
    assert.truthy(out:find('\njev_async_total{result="ok"} 2\n', 1, true))
    for _, r in ipairs({ "failed", "busy", "no_scores", "error" }) do
      assert.truthy(out:find('\njev_async_total{result="' .. r .. '"} 1\n', 1, true), r)
    end
  end)

  it("folds a result outside the fixed set into error, so no label is minted", function()
    metrics.incr_async_result('x"} 1\nforged')
    metrics.incr_async_result(nil)
    local out = metrics.render()
    assert.truthy(out:find('\njev_async_total{result="error"} 2\n', 1, true))
    assert.is_nil(out:find("forged", 1, true))
  end)

  it("keeps jev_async_dropped_total apart", function()
    metrics.incr_async_dropped()
    metrics.incr_async_result("ok")
    local out = metrics.render()
    assert.truthy(out:find("\njev_async_dropped_total 1\n", 1, true))
    assert.truthy(out:find('\njev_async_total{result="ok"} 1\n', 1, true))
  end)
end)
