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
