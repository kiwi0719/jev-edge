local H = require "core.spec.helper"
local T = require "jev.core.trust"
local core = require "jev.core"
local V = require "jev.core.verdict"

local DAY = 86400
local FB = { enabled = true, token = "s3cret", trust_ttl = 7 * DAY, max_renewals = 4 }

describe("core.trust", function()
  local store
  before_each(function() store = H.store() end)

  it("grants trust with a TTL and remembers who asked", function()
    local rec = T.grant(store, "abc", 1000, FB, { by = "alice", rid = "r1" })
    assert.equals(1000 + 7 * DAY, rec.trusted_until)
    assert.equals(0, rec.renewals)
    assert.equals("alice", rec.by)
    assert.same(rec, T.get(store, "abc", 1000))
  end)

  it("expires", function()
    T.grant(store, "abc", 1000, FB, {})
    assert.is_table(T.get(store, "abc", 1000 + 7 * DAY - 1))
    assert.is_nil(T.get(store, "abc", 1000 + 7 * DAY))
  end)

  it("counts repeat reports as renewals and stops at the cap", function()
    local now = 1000
    T.grant(store, "abc", now, FB, {})
    for i = 1, 4 do
      local rec = T.grant(store, "abc", now + i, FB, {})
      assert.equals(i, rec.renewals)
      assert.equals(1000, rec.first_seen)
    end
    local rec, err = T.grant(store, "abc", now + 5, FB, {})
    assert.is_nil(rec)
    assert.matches("renewal cap", err)
    -- the existing grant is left alone, so it still expires on its own schedule
    assert.is_table(T.get(store, "abc", now + 5))
  end)

  it("a lapsed fingerprint starts over", function()
    T.grant(store, "abc", 1000, { enabled = true, trust_ttl = 10, max_renewals = 0 }, {})
    local rec = T.grant(store, "abc", 2000, { enabled = true, trust_ttl = 10, max_renewals = 0 }, {})
    assert.equals(0, rec.renewals)
    assert.equals(2000, rec.first_seen)
  end)

  it("touch extends only past half life, and only up to the cap", function()
    local rec = T.grant(store, "abc", 1000, FB, {})
    assert.is_false((T.touch(store, "abc", rec, 1000 + DAY, FB)))
    local ok, out = T.touch(store, "abc", rec, 1000 + 4 * DAY, FB)
    assert.is_true(ok)
    assert.equals(1, out.renewals)
    local capped = { trusted_until = 9e9, renewals = 4, first_seen = 1 }
    local ok2, why = T.touch(store, "abc", capped, 1000, FB)
    assert.is_false(ok2)
    assert.equals("renewal cap", why)
  end)

  it("revokes", function()
    T.grant(store, "abc", 1000, FB, {})
    T.revoke(store, "abc")
    assert.is_nil(T.get(store, "abc", 1000))
  end)

  it("is off unless explicitly enabled", function()
    assert.is_false(T.enabled(nil))
    assert.is_false(T.enabled({}))
    assert.is_true(T.enabled({ enabled = true }))
  end)
end)

describe("core.evaluate with a trusted fingerprint", function()
  local LONG = "Please write a detailed summary of the attached quarterly report."

  local function ctx_with(over)
    local calls = 0
    local ctx = H.ctx({
      config = { feedback = FB },
      judge = { call = function() calls = calls + 1; return { injection = 0.9 } end },
    })
    for k, v in pairs(over or {}) do ctx[k] = v end
    return ctx, function() return calls end
  end

  it("passes without calling L2, and says who trusted it", function()
    local ctx, calls = ctx_with()
    local fp = core.evaluate(H.chat_req(LONG), ctx).fingerprint
    ctx.cache:set(T.key(fp), { trusted_until = ctx.clock() + 7 * DAY, renewals = 0, by = "alice" })
    local v = core.evaluate(H.chat_req(LONG), ctx)
    assert.equals(V.SRC_TRUST, v.source)
    assert.equals(V.SAFE, v.verdict)
    assert.equals(V.ACTION_PASS, v.action)
    assert.equals(0, v.score)
    assert.equals("fingerprint trusted by alice", v.reason)
    assert.equals(1, calls())   -- only the first, untrusted request
  end)

  it("beats a malicious verdict cached for the same text", function()
    local ctx = ctx_with()
    local v0 = core.evaluate(H.chat_req(LONG), ctx)
    assert.equals(V.SRC_L2, v0.source)
    ctx.cache:set("fp:" .. v0.fingerprint, { score = 0.9, reason = "injection 0.90" })
    ctx.cache:set(T.key(v0.fingerprint), { trusted_until = ctx.clock() + 7 * DAY, renewals = 0 })
    assert.equals(V.SRC_TRUST, core.evaluate(H.chat_req(LONG), ctx).source)
  end)

  it("stays off when feedback is not enabled", function()
    local ctx = H.ctx()
    local fp = core.evaluate(H.chat_req(LONG), ctx).fingerprint
    ctx.cache:set(T.key(fp), { trusted_until = ctx.clock() + 7 * DAY })
    assert.equals(V.SRC_CACHE, core.evaluate(H.chat_req(LONG), ctx).source)
  end)

  it("lets traffic refresh trust a bounded number of times", function()
    local ctx = ctx_with()
    local fp = core.evaluate(H.chat_req(LONG), ctx).fingerprint
    ctx.cache:set(T.key(fp), { trusted_until = ctx.clock() + 7 * DAY, renewals = 0, first_seen = ctx.clock() })
    -- every 6 days the record is past half its life and gets pushed out again
    for _ = 1, 5 do
      ctx._clock.advance(6 * DAY)
      assert.equals(V.SRC_TRUST, core.evaluate(H.chat_req(LONG), ctx).source)
    end
    assert.equals(4, ctx.cache:get(T.key(fp)).renewals)
    -- the fifth window is the last one: no more renewals, so it ages out and
    -- the request is judged again (here: the score cached on the first pass)
    ctx._clock.advance(8 * DAY)
    assert.is_nil(T.get(ctx.cache, fp, ctx.clock()))
    assert.not_equals(V.SRC_TRUST, core.evaluate(H.chat_req(LONG), ctx).source)
  end)

  it("uses ctx.trust when the adapter splits the stores", function()
    local trust_store = H.store()
    local ctx = ctx_with({ trust = trust_store })
    local fp = core.evaluate(H.chat_req(LONG), ctx).fingerprint
    trust_store:set(T.key(fp), { trusted_until = ctx.clock() + 7 * DAY })
    assert.equals(V.SRC_TRUST, core.evaluate(H.chat_req(LONG), ctx).source)
  end)
end)
