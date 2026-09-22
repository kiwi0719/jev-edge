local H = require "core.spec.helper"

-- providers/jev.lua and providers/laya.lua (System One protocol). dkjson
-- stands in for cjson.safe, as in openai_compat_spec.lua.
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
local jev  = require "resty.jev.providers.jev"
local laya = require "resty.jev.providers.laya"
local judge = require "jev.core.judge"

local function prompt(text, names, deployment)
  return assert(judge.build(names or { "injection" }, text, { deployment = deployment or "" }))
end

describe("System One providers", function()
  it("laya sends the jev request with its own default model and endpoint", function()
    local r = laya.build_request(prompt("hello"), {})
    local b = H.json.decode(r.body)
    assert.equals("http://127.0.0.1:8080/v1/systemone", r.url)
    assert.equals("laya", b.model)
    assert.equals("hello", b.state)
    assert.equals("noul", b.questions.injection.type)
    local j = H.json.decode(jev.build_request(prompt("hello"), {}).body)
    assert.same(j.questions, b.questions)
    assert.equals("jev-latest", j.model)
  end)

  it("puts a deployment context in an object state and uses the _ctx wording", function()
    local b = H.json.decode(laya.build_request(prompt("hi", nil, "A billing assistant."), {}).body)
    assert.same({ assistant = "A billing assistant.", user_message = "hi" }, b.state)
    assert.equals(judge.get("injection").instructions_ctx, b.questions.injection.instructions)
  end)

  it("names itself in errors", function()
    local a, err = laya.parse_response(413, "")
    assert.is_nil(a)
    assert.equals("laya http 413", err)
    assert.equals("jev: malformed response", select(2, jev.parse_response(200, "{}")))
  end)

  it("cfg.questions replaces the wording of that question only", function()
    local cfg = { questions = { injection = { instructions = "Custom?",
      criteria = { ["true"] = "yes-case", ["false"] = "no-case" } } } }
    local b = H.json.decode(laya.build_request(prompt("x", { "injection", "abuse" }), cfg).body)
    assert.equals("Custom?", b.questions.injection.instructions)
    assert.same({ ["true"] = "yes-case", ["false"] = "no-case" }, b.questions.injection.criteria)
    assert.are_not.equal("Custom?", b.questions.abuse.instructions)
    -- the bundled template itself is untouched
    assert.are_not.equal("Custom?", judge.get("injection").instructions)
  end)
end)
