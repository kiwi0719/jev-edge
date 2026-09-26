local H = require "core.spec.helper"
local sampling = require "jev.core.sampling"
local defaults = require "jev.core.defaults"

-- g2-cache-scope-and-cross-instance-state#4: Kong and APISIX routes (and
-- tenants) with their own sampling.max_samples write one ring in one store
local function cfg(max)
  return defaults.merge(defaults.config, { sampling = { enabled = true, rate = 1, max_samples = max } })
end

describe("sampling ring", function()
  it("pins the ring's size on first use, and every writer uses it", function()
    local store = H.store()
    local big, small = cfg(1000), cfg(3)
    local _, other = sampling.store(big, store, { rid = "1" })
    assert.falsy(other)
    assert.equals(1000, store:get("sample:size"))
    -- a writer with another size writes into the pinned ring and is told
    for i = 2, 5 do
      _, other = sampling.store(small, store, { rid = tostring(i) })
      assert.is_true(other)
    end
    -- newest first, whoever reads: nothing overwritten, nothing stale
    for _, c in ipairs({ big, small }) do
      local list, n = sampling.dump(c, store)
      assert.equals(5, n)
      local rids = {}
      for i, s in ipairs(list) do rids[i] = s.rid end
      assert.same({ "5", "4", "3", "2", "1" }, rids)
    end
  end)

  it("a small first writer's size holds for a bigger one", function()
    local store = H.store()
    for i = 1, 5 do sampling.store(i == 1 and cfg(3) or cfg(1000), store, { rid = tostring(i) }) end
    local list, n = sampling.dump(cfg(1000), store)
    assert.equals(5, n)
    local rids = {}
    for i, s in ipairs(list) do rids[i] = s.rid end
    assert.same({ "5", "4", "3" }, rids)
  end)

  it("clear resets the ring and its size", function()
    local store = H.store()
    sampling.store(cfg(3), store, { rid = "1" })
    sampling.clear(cfg(1000), store)
    assert.is_nil(store:get("sample:size"))
    assert.is_nil(store:get("sample:0"))
    assert.same({}, (sampling.dump(cfg(1000), store)))
    sampling.store(cfg(1000), store, { rid = "2" })
    assert.equals(1000, store:get("sample:size"))
  end)

  it("records the rule that judged the sample", function()
    local rule = require "jev.rules.llm-endpoints"
    local body = '{"messages":[{"role":"user","content":"Summarise the report for me please."}]}'
    local s = sampling.build(cfg(10), { fingerprint = "f", score = 0.9, verdict = "malicious" },
      { method = "POST", path = "/v1/chat/completions", headers = { ["content-type"] = "application/json" },
        body = body }, rule, { json_decode = H.body_decode })
    assert.equals("llm-endpoints", s.rule)
    assert.is_nil(sampling.build(cfg(10), { fingerprint = "f" }, { path = "/x" }, nil, {}).rule)
  end)
end)
