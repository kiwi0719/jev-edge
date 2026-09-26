-- resty/jev/metrics.lua against a stand-in jev_metrics dict.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path
local V = require "jev.core.verdict"

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

describe("metrics: exposition layout", function()
  local metrics, saved_ngx, data, keys
  setup(function() saved_ngx = _G.ngx end)
  teardown(function()
    _G.ngx = saved_ngx
    package.loaded["resty.jev.metrics"] = nil
  end)
  before_each(function()
    data, keys = {}, {}
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

  local function v(source, verdict, l2_ms)
    return { source = source, verdict = verdict, action = "pass", reason = "injection 0.20", l2_ms = l2_ms }
  end

  -- family of a sample line: its metric name, less a histogram suffix
  local function family(line)
    local name = line:match("^([%w_]+)")
    return (name:gsub("_bucket$", ""):gsub("_sum$", ""):gsub("_count$", ""))
  end

  it("emits each family as its TYPE line followed at once by all of its samples", function()
    -- keys created interleaved, as traffic creates them in the dict
    metrics.record(v("l2", "safe", 120))
    metrics.set_breaker_state(0)
    metrics.record(v("cache", "safe", 0))
    metrics.set_l2_timeout(300, 1000)
    metrics.record(v("l2", "suspicious", 40))
    metrics.usage({ input_tokens = 5, output_tokens = 1 })
    metrics.incr_async_result("ok")
    local out = metrics.render()
    local seen, cur = {}, nil
    for line in out:gmatch("[^\n]+") do
      local fam = line:match("^# TYPE (%S+) ")
      if fam then
        assert.is_nil(seen[fam], "TYPE twice: " .. fam)
        seen[fam], cur = true, fam
      else
        assert.equals(cur, family(line), "sample outside its family's block: " .. line)
      end
    end
    assert.truthy(seen.jev_l2_latency_ms)
    assert.truthy(seen.jev_requests_total)
  end)

  it("emits every L2 bucket in ascending le, then +Inf, _sum and _count", function()
    -- one call of 120 ms: no key for le=25, 50 or 100 was ever created
    metrics.record(v("l2", "safe", 120))
    local out = metrics.render()
    local hist = {}
    for line in out:gmatch("[^\n]+") do
      if line:match("^jev_l2_latency_ms") then hist[#hist + 1] = line end
    end
    assert.same({
      'jev_l2_latency_ms_bucket{le="25"} 0',
      'jev_l2_latency_ms_bucket{le="50"} 0',
      'jev_l2_latency_ms_bucket{le="100"} 0',
      'jev_l2_latency_ms_bucket{le="200"} 1',
      'jev_l2_latency_ms_bucket{le="300"} 1',
      'jev_l2_latency_ms_bucket{le="500"} 1',
      'jev_l2_latency_ms_bucket{le="1000"} 1',
      'jev_l2_latency_ms_bucket{le="2000"} 1',
      'jev_l2_latency_ms_bucket{le="3000"} 1',
      'jev_l2_latency_ms_bucket{le="5000"} 1',
      'jev_l2_latency_ms_bucket{le="10000"} 1',
      'jev_l2_latency_ms_bucket{le="30000"} 1',
      'jev_l2_latency_ms_bucket{le="+Inf"} 1',
      "jev_l2_latency_ms_sum 120",
      "jev_l2_latency_ms_count 1",
    }, hist)
  end)

  local function bucket(out, le)
    return tonumber(out:match('\njev_l2_latency_ms_bucket{le="' .. le:gsub("%+", "%%+") .. '"} (%d+)\n'))
  end

  it("puts an L2 call slower than a second in a bucket below +Inf", function()
    -- jev.timeout_max_ms may be raised past 1000: a 1.5 s call is not only +Inf
    metrics.record(v("l2", "safe", 1500))
    metrics.record(v("l2", "safe", 4000))
    metrics.record(v("l2", "safe", 45000))
    local out = metrics.render()
    assert.equals(0, bucket(out, "1000"))
    assert.equals(1, bucket(out, "2000"))
    assert.equals(1, bucket(out, "3000"))
    assert.equals(2, bucket(out, "5000"))
    assert.equals(2, bucket(out, "10000"))
    assert.equals(2, bucket(out, "30000"))
    assert.equals(3, bucket(out, "+Inf"))
  end)

  it("never emits a bucket below the one under it, after an upgrade added buckets", function()
    -- a dict that survived a HUP reload: the old buckets are filled, the new
    -- ones have no key yet
    data["l2_count"], data["l2_sum_ms"], data["l2_le:inf"] = 5, 900, 5
    data["l2_le:500"], data["l2_le:1000"] = 3, 4
    for _, k in ipairs({ "l2_count", "l2_sum_ms", "l2_le:inf", "l2_le:500", "l2_le:1000" }) do
      keys[#keys + 1] = k
    end
    local out = metrics.render()
    assert.equals(4, bucket(out, "1000"))
    assert.equals(4, bucket(out, "2000"))
    assert.equals(4, bucket(out, "30000"))
    assert.equals(5, bucket(out, "+Inf"))
    metrics.record(v("l2", "safe", 1500))
    out = metrics.render()
    assert.equals(4, bucket(out, "1000"))
    assert.equals(4, bucket(out, "2000"))
    assert.equals(6, bucket(out, "+Inf"))
    local prev = -1
    for n in out:gmatch('jev_l2_latency_ms_bucket{le="[^"]+"} (%d+)') do
      assert.is_true(tonumber(n) >= prev)
      prev = tonumber(n)
    end
  end)

  it("emits no histogram samples before the first L2 call, and no bucket twice", function()
    metrics.record(v("cache", "safe", 0))
    local out = metrics.render()
    assert.truthy(out:find("# TYPE jev_l2_latency_ms histogram\n", 1, true))
    assert.is_nil(out:find("jev_l2_latency_ms_", 1, true))
    metrics.record(v("l2", "safe", 20))
    metrics.record(v("l2", "safe", 20))
    out = metrics.render()
    local _, n = out:gsub('jev_l2_latency_ms_bucket{le="25"}', "")
    assert.equals(1, n)
    assert.truthy(out:find('jev_l2_latency_ms_bucket{le="25"} 2\n', 1, true))
  end)
end)

-- what an L2 error verdict ran into is counted by kind, from a fixed label set
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
    return V.new({ verdict = V.ERROR, source = V.SRC_L2, reason = "x", error_kind = kind })
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
    metrics.record(V.new({ verdict = V.SAFE, source = V.SRC_L2, reason = "injection 0.10" }))
    metrics.record(V.new({ verdict = V.SKIPPED, source = V.SRC_BREAKER, reason = "breaker open" }))
    local out = metrics.render()
    assert.matches('jev_l2_errors_total{kind="other"} 2', out, 1, true)
    local n = 0
    for _ in out:gmatch("jev_l2_errors_total{") do n = n + 1 end
    assert.equals(1, n)
  end)

  -- ops#1: a verdict max_inflight turned away made no call; its ~0 ms is
  -- not an L2 latency. A cache verdict (every part a per-part hit) is none.
  it("leaves a busy verdict and a cache verdict out of the L2 latency histogram", function()
    local busy = V.new({ verdict = V.ERROR, source = V.SRC_L2, reason = "max_inflight exceeded",
      error_kind = "busy" })
    metrics.record(busy)
    metrics.record(busy)
    metrics.record(V.new({ verdict = V.SAFE, source = V.SRC_CACHE, reason = "injection 0.10" }))
    metrics.record(V.new({ verdict = V.SAFE, source = V.SRC_L2, reason = "injection 0.10",
      l2_ms = 180 }))
    metrics.record(V.new({ verdict = V.ERROR, source = V.SRC_L2, reason = "timeout",
      error_kind = "timeout", l2_ms = 300 }))
    local out = metrics.render()
    assert.matches('jev_l2_errors_total{kind="busy"} 2', out, 1, true)
    assert.matches("jev_l2_latency_ms_count 2\n", out, 1, true)
    assert.matches("jev_l2_latency_ms_sum 480\n", out, 1, true)
    -- the busy verdicts' 0 ms would have filled the lowest bucket (emitted
    -- at 0: render() writes every bucket)
    assert.matches('jev_l2_latency_ms_bucket{le="25"} 0\n', out, 1, true)
    assert.matches('jev_l2_latency_ms_bucket{le="200"} 1', out, 1, true)
    assert.matches('jev_l2_latency_ms_bucket{le="+Inf"} 2', out, 1, true)
    assert.matches('jev_cache_hits_total{kind="fp"} 1', out, 1, true)
    assert.matches('jev_requests_total{source="l2",verdict="error"} 3', out, 1, true)
  end)
end)
