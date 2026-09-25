-- Tool calls: what the golden vectors leave out (bounds a vector cannot
-- reach, rule resolution). Twin of adapters/js/test/tools.test.ts.
local H = require "core.spec.helper"
local normalize = require "jev.core.normalize"
local rules_mod = require "jev.core.rules"

local ARGS = { "messages[*].tool_calls[*].function.arguments.**" }

local function with_args(v)
  return { messages = { { role = "assistant", tool_calls = { { ["function"] = { name = "f", arguments = v } } } } } }
end

local function load(id) return require("jev.rules." .. id) end

describe("tool-call arguments (\"**\" paths)", function()
  local saved_depth, saved_nodes
  before_each(function() saved_depth, saved_nodes = normalize.DEEP_DEPTH, normalize.DEEP_NODES end)
  after_each(function() normalize.DEEP_DEPTH, normalize.DEEP_NODES = saved_depth, saved_nodes end)

  it("reads a string of JSON decoded and anything else as it is", function()
    local text = normalize.extract_json(with_args('{"b":"two","a":"one"}'), ARGS, H.body_decode)
    assert.equals("a\none\nb\ntwo", text)
    assert.equals("{not json", (normalize.extract_json(with_args("{not json"), ARGS, H.body_decode)))
    -- no decoder: the string as it is
    assert.equals('{"a":"one"}', (normalize.extract_json(with_args('{"a":"one"}'), ARGS)))
  end)

  it("stops at the node bound and says so", function()
    normalize.DEEP_NODES = 3
    local _, out, cut = normalize.extract_json(with_args({ "a", "b", "c", "d" }), ARGS, H.body_decode)
    assert.same({ "a", "b", "c" }, out)
    assert.is_true(cut)
    -- an object with more keys than the budget left is not read at all: its
    -- keys would have to be sorted first, and that is the cost the bound caps
    _, out, cut = normalize.extract_json(with_args({ k1 = "v", k2 = "v", k3 = "v", k4 = "v" }), ARGS, H.body_decode)
    assert.same({}, out)
    assert.is_true(cut)
  end)

  it("stops at the depth bound and says so", function()
    normalize.DEEP_DEPTH = 2
    local _, out, cut = normalize.extract_json(with_args({ a = { b = { c = "deep" } } }), ARGS, H.body_decode)
    assert.same({ "a", "b" }, out)
    assert.is_true(cut)
  end)

  it("counts neither empty tables nor a decoder's null against the bounds", function()
    normalize.DEEP_DEPTH = 1
    local _, out, cut = normalize.extract_json(with_args({ x = {}, y = H.json.null, z = "v" }), ARGS, H.body_decode)
    assert.same({ "x", "y", "z", "v" }, out)
    assert.is_falsy(cut)
  end)

  it("marks the text windowed when a bound cut it", function()
    normalize.DEEP_NODES = 2
    local b = H.json.encode({ messages = { { role = "user", content = "Please summarise the attached report." },
      { role = "assistant", tool_calls = { { ["function"] = { name = "f", arguments = { "a", "b", "c" } } } } } } })
    local r, _, reason = rules_mod.evaluate({ method = "POST", path = "/v1/chat/completions",
      headers = { ["content-type"] = "application/json" }, body = b, body_size = #b }, load("llm-endpoints"), H.ctx())
    assert.equals(rules_mod.SUSPECT, r)
    assert.equals("natural language (window)", reason)
  end)

  it("reads the arguments key past max_body_bytes too", function()
    assert.is_true(normalize.field_keys({ "messages[*].tool_calls[*].function.arguments.**" }).arguments)
  end)
end)

describe("rules.resolve: field paths", function()
  it("fills in the tool-call argument paths for an inline rule", function()
    local r = assert(rules_mod.resolve({ id = "x", watch_paths = {} }, load))
    assert.same(load("llm-endpoints").text_fields, r.text_fields)
  end)

  it("rejects a path \"**\" is not the last segment of, and paths that are not strings", function()
    local r, err = rules_mod.resolve({ id = "x", extends = "llm-endpoints", text_fields = { "a.**.b" } }, load)
    assert.is_nil(r)
    assert.equals('rule x: text_fields[1] "**" must be the last segment', err)
    r, err = rules_mod.resolve({ id = "x", extends = "llm-endpoints", text_fields = { "prompt", 3 } }, load)
    assert.is_nil(r)
    assert.equals("rule x: text_fields[2] must be a non-empty string", err)
    r, err = rules_mod.resolve({ id = "x", extends = "llm-endpoints", text_fields = "prompt" }, load)
    assert.is_nil(r)
    assert.equals("rule x: text_fields must be a list of paths", err)
  end)
end)
