local H = require "core.spec.helper"

-- resty/jev/http.lua classifies every failed call (judge.TRANSPORT, TIMEOUT,
-- UNAVAILABLE, REJECTED, UNUSABLE) for core's breaker. ngx and resty.http are
-- stubbed; dkjson stands in for cjson.safe, as in openai_compat_spec.lua.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path
package.preload["cjson.safe"] = function()
  return {
    encode = function(v) return H.json.encode(v) end,
    decode = function(s)
      local ok, v = pcall(H.json.decode, s, 1, H.json.null)
      if ok then return v end
      return nil
    end,
  }
end
local J = require "jev.core.judge"

describe("http judge: error kinds", function()
  local saved_ngx, http, reply
  setup(function()
    saved_ngx = _G.ngx
    _G.ngx = { now = function() return 1000 end, update_time = function() end, log = function() end, WARN = 5 }
    package.loaded["resty.http"] = { new = function()
      return { set_timeouts = function() end, request_uri = function() return reply() end }
    end }
    package.loaded["resty.jev.http"] = nil
    http = require "resty.jev.http"
  end)
  teardown(function()
    _G.ngx = saved_ngx
    package.loaded["resty.http"] = nil
    package.loaded["resty.jev.http"] = nil
  end)

  local function call(provider, res, err)
    reply = function() return res, err end
    local j = assert(http.new({ provider = provider, endpoint = "http://judge/v1", timeout_ms = 400 }, H.store()))
    local p = J.build({ "injection" }, "some judged text", { path = "/v1/chat/completions", method = "POST" })
    return j.call(p, 400)
  end
  local function chat(content)
    local message = { role = "assistant", content = content }
    return { status = 200, body = H.json.encode({ choices = { { message = message } } }) }
  end

  it("a 200 the provider could not read is unusable, for every provider", function()
    local a, err, kind = call("openai-compat", { status = 200, body = '{"choices":[{"message":{"content":null}}]}' })
    assert.is_nil(a)
    assert.equals("openai-compat: no content", err)
    assert.equals(J.UNUSABLE, kind)
    assert.equals(J.UNUSABLE, select(3, call("openai-compat", chat('{"status":"ok"}'))))
    assert.equals(J.UNUSABLE, select(3, call("openai-compat", chat("I cannot help with that."))))
    assert.equals(J.UNUSABLE, select(3, call("laya", { status = 200, body = "<html>" })))
    assert.equals(J.UNUSABLE, select(3, call("jev", { status = 200, body = '{"result":"ok"}' })))
  end)

  it("a 4xx is rejected; 5xx and 429 are unavailable", function()
    local filtered = { status = 400, body = '{"error":{"code":"content_filter"}}' }
    assert.same({ "openai-compat http 400", J.REJECTED }, { select(2, call("openai-compat", filtered)) })
    assert.same({ "laya http 400", J.REJECTED }, { select(2, call("laya", { status = 400, body = "" })) })
    assert.same({ "laya http 503", J.UNAVAILABLE }, { select(2, call("laya", { status = 503, body = "" })) })
    local limited = { status = 429, body = "" }
    assert.same({ "openai-compat http 429", J.UNAVAILABLE }, { select(2, call("openai-compat", limited)) })
  end)

  it("no HTTP answer is transport, or timeout", function()
    assert.same({ "connection refused", J.TRANSPORT }, { select(2, call("laya", nil, "connection refused")) })
    assert.same({ "timeout", J.TIMEOUT }, { select(2, call("openai-compat", nil, "timeout")) })
  end)

  it("an answer carries no kind", function()
    local a, err, kind = call("openai-compat", chat('{"injection": 0.3}'))
    assert.same({ injection = 0.3 }, a)
    assert.is_nil(err)
    assert.is_nil(kind)
  end)
end)

-- Kong and APISIX key a route's breaker, adaptive timeout and in-flight
-- counter by state_prefix: one route's key or tuning must not reach another.
describe("http.state_prefix", function()
  local http
  setup(function()
    package.loaded["resty.jev.http"] = nil
    http = require "resty.jev.http"
  end)
  teardown(function() package.loaded["resty.jev.http"] = nil end)

  -- a stand-in digest (the adapters pass SHA-256)
  local function hash(s)
    local a, b = 7, 11
    for i = 1, #s do
      a = (a * 31 + s:byte(i)) % 4294967296
      b = (b * 131 + s:byte(i)) % 4294967291
    end
    return string.format("%08x%08x", a, b)
  end
  local function cfg(jev, breaker)
    local j = { provider = "jev", endpoint = "https://judge/v1", model = "m", api_key = "sk-route-a",
                max_inflight = 64 }
    for k, v in pairs(jev or {}) do j[k] = v end
    local b = { window_s = 60, min_samples = 20, fail_ratio = 0.5, open_s = 30 }
    for k, v in pairs(breaker or {}) do b[k] = v end
    return { jev = j, breaker = b }
  end

  it("is the same for the same provider, endpoint, model, key and tuning", function()
    assert.equals(http.state_prefix(cfg(), hash), http.state_prefix(cfg(), hash))
    assert.matches("^p:%x+:$", http.state_prefix(cfg(), hash))
  end)

  it("differs with the key, max_inflight or any breaker setting", function()
    local base = http.state_prefix(cfg(), hash)
    assert.not_equals(base, http.state_prefix(cfg({ api_key = "sk-route-b" }), hash))
    assert.not_equals(base, http.state_prefix(cfg({ api_key = false }), hash))
    assert.not_equals(base, http.state_prefix(cfg({ max_inflight = 4 }), hash))
    assert.not_equals(base, http.state_prefix(cfg(nil, { min_samples = 1 }), hash))
    assert.not_equals(base, http.state_prefix(cfg(nil, { fail_ratio = 0.01 }), hash))
    assert.not_equals(base, http.state_prefix(cfg(nil, { open_s = 3600 }), hash))
    assert.not_equals(base, http.state_prefix(cfg({ endpoint = "https://other/v1" }), hash))
  end)

  it("takes the key only as a hash", function()
    local seen
    http.state_prefix(cfg(), function(s)
      if s:find("\n", 1, true) then seen = s end
      return hash(s)
    end)
    assert.is_nil(seen:find("sk-route-a", 1, true))
    assert.truthy(seen:find(hash("sk-route-a"), 1, true))
  end)
end)

-- In-flight slots are leases: a thread killed mid-call never gives its slot
-- back (openresty-io#5), and the slot must stop counting on its own.
describe("http.slots", function()
  local http, saved_ngx, t
  setup(function()
    saved_ngx = _G.ngx
    t = 1000
    _G.ngx = { now = function() return t end }
    package.loaded["resty.jev.http"] = nil
    http = require "resty.jev.http"
  end)
  teardown(function()
    _G.ngx = saved_ngx
    package.loaded["resty.jev.http"] = nil
  end)
  before_each(function() t = 1000 end)

  it("refuses past max and takes again once a slot is given back", function()
    local s = http.slots(H.store(), "inflight:l2", 10)
    local a, b = s.take(2), s.take(2)
    assert.truthy(a); assert.truthy(b)
    assert.is_nil(s.take(2))
    s.give(a)
    assert.truthy(s.take(2))
  end)

  it("stops counting a slot nobody gave back after two lease periods, not before", function()
    local s = http.slots(H.store(), "inflight:l2", 10)
    assert.truthy(s.take(1))              -- a thread killed mid-call: never given back
    assert.is_nil(s.take(1))
    t = t + 10                            -- the next period still counts it
    assert.is_nil(s.take(1))
    t = t + 10                            -- two periods on it is gone
    local c = s.take(1)
    assert.truthy(c)
    assert.is_nil(s.take(1))
    s.give(c)
    assert.truthy(s.take(1))
  end)

  it("a slot given back in a later period frees exactly that slot", function()
    local store = H.store()
    local s = http.slots(store, "inflight:l2", 10)
    local old = { s.take(2), s.take(2) }
    t = t + 10
    assert.is_nil(s.take(2))              -- both still in flight
    s.give(old[1]); s.give(old[2])
    local x, y = s.take(2), s.take(2)
    assert.truthy(x); assert.truthy(y)
    assert.is_nil(s.take(2))              -- the cap holds: no slot counted twice or lost
    -- a release long after its counter expired never offsets a later call
    t = t + 100
    store:set(old[1], nil)                -- the dict dropped the old period's counter
    s.give(old[1])
    assert.truthy(s.take(1))
    assert.is_nil(s.take(1))
  end)

  it("admits every call when there is no counter (a missing dict)", function()
    local s = http.slots({ incr = function() return nil end, get = function() end, set = function() end },
      "inflight:l2", 10)
    assert.equals(false, s.take(1))
    assert.equals(false, s.take(1))
    s.give(false)
  end)
end)
