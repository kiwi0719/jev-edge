-- Replays core/golden/*.json against the Lua core. This is the consumer side
-- of the parity contract: any implementation of core must pass the same
-- files the same way. core/golden/README.md documents the input semantics
-- this spec implements (how to build ctx from `input`).
local H = require "core.spec.helper"
local core      = require "jev.core"
local normalize = require "jev.core.normalize"
local rules_mod = require "jev.core.rules"
local policy    = require "jev.core.policy"
local verdict   = require "jev.core.verdict"
local defaults  = require "jev.core.defaults"
local breaker_m = require "jev.core.breaker"
local json = require "dkjson"

local function load(name)
  local f = assert(io.open("core/golden/" .. name .. ".json", "rb"), "missing golden file " .. name)
  local doc = assert(json.decode(f:read("*a")))
  f:close()
  assert.equals(2, doc.format_version, "unknown golden format version")
  return doc
end

-- dkjson turns [] and {} both into empty tables; compare structurally.
local function same(exp, got, path)
  path = path or "expect"
  if type(exp) == "table" then
    assert.equals("table", type(got), path)
    for k, v in pairs(exp) do same(v, got[k], path .. "." .. tostring(k)) end
    for k in pairs(got) do
      assert.not_nil(exp[k], path .. "." .. tostring(k) .. " is extra")
    end
  else
    assert.same(exp, got, path)
  end
end

local function store_from(map)
  local s = H.store()
  for k, v in pairs(map or {}) do s:set(k, v) end
  return s
end

describe("golden: normalize", function()
  for _, c in ipairs(load("normalize").cases) do
    it(c.name, function()
      same(c.expect.normalized, normalize.normalize(c.input.text, c.input.opts))
      same(c.expect.fingerprint, normalize.fingerprint(c.input.text, c.input.opts, normalize.djb2))
    end)
  end
end)

describe("golden: extract", function()
  for _, c in ipairs(load("extract").cases) do
    it(c.name, function()
      local text, kind, _, decoded, cut, ids = normalize.extract(c.input.body, c.input.content_type, c.input.fields,
        H.body_decode)
      local tools
      if c.input.tool_fields then
        local ttext, _, capped = normalize.extract_tools(decoded, c.input.tool_fields, H.body_decode)
        tools = { text = ttext, capped = capped or nil }
      end
      same(c.expect, { text = text, kind = kind, cut = cut or nil, token_ids = ids or nil, tools = tools })
    end)
  end
end)

describe("golden: rules", function()
  for _, c in ipairs(load("rules").cases) do
    it(c.name, function()
      -- a rule set id, or an inline spec resolved the way a config's `rules` list is
      local rule = type(c.input.rule) == "table"
        and assert(rules_mod.resolve(c.input.rule, function(x) return require("jev.rules." .. x) end))
        or require("jev.rules." .. c.input.rule)
      local ctx = {
        cache = store_from(c.input.cache), clock = function() return c.input.clock end,
        json_decode = H.body_decode, re_find = H.re_find,
      }
      local r, text, reason, _, _, _, _, tools = rules_mod.evaluate(c.input.req, rule, ctx)
      same(c.expect, { result = r, text = text, reason = reason,
        tools = tools and { text = tools.text, windowed = tools.windowed, hit = tools.hit, only = tools.only } })
    end)
  end
end)

describe("golden: policy", function()
  for _, c in ipairs(load("policy").cases) do
    it(c.name, function()
      local action, label, async
      if c.input.event == "error" then action, label, async = policy.on_error()
      elseif c.input.event == "skipped" then action, label, async = policy.on_skipped()
      else action, label, async = policy.decide(c.input.score, c.input.policy) end
      same(c.expect, { action = action, label = label, async = async })
    end)
  end
end)

describe("golden: verdict", function()
  for _, c in ipairs(load("verdict").cases) do
    it(c.name, function()
      local v = verdict.new(c.input)
      same(c.expect, { verdict = v, headers = verdict.headers(v) })
    end)
  end
end)

describe("golden: evaluate", function()
  for _, c in ipairs(load("evaluate").cases) do
    it(c.name, function()
      local inp = c.input
      local cache = store_from(inp.cache)
      local writes, calls, seen = {}, 0, nil
      local rules = {}
      for _, spec in ipairs(inp.rules) do
        if type(spec) == "table" then
          rules[#rules + 1] = assert(rules_mod.resolve(spec, function(id) return require("jev.rules." .. id) end))
        else
          rules[#rules + 1] = require("jev.rules." .. spec)
        end
      end
      local breaker, brk, brk_calls
      if inp.breaker then
        local bstore = H.store()
        local st = inp.breaker == "closed" and breaker_m.CLOSED or breaker_m.OPEN
        bstore:set("brk:state", { state = st, until_ts = inp.breaker == "half-open" and inp.clock or inp.clock + 30 })
        brk = breaker_m.new(bstore, function() return inp.clock end, {})
        brk_calls, breaker = {}, {}
        for _, m in ipairs({ "allow", "success", "failure", "release" }) do
          breaker[m] = function() brk_calls[#brk_calls + 1] = m; return brk[m](brk) end
        end
      end
      local recorded, subject_ctx, swrites
      if inp.subject then
        local sstore = store_from(inp.subject.store)
        swrites = {}
        subject_ctx = { id = inp.subject.id, ids = inp.subject.ids, history = inp.subject.history,
                        record = function(e) recorded = e end,
                        store = {
                          get = function(_, k) return sstore:get(k) end,
                          set = function(_, k, v, ttl) swrites[k] = { value = v, ttl = ttl }; sstore:set(k, v, ttl) end,
                          incr = function(_, k, by, ttl)
                            local n = sstore:incr(k, by, ttl)
                            swrites[k] = { value = n, ttl = ttl }
                            return n
                          end,
                        } }
      end
      local ctx = {
        config = defaults.merge(defaults.config, inp.config), rules = rules, breaker = breaker,
        subject = subject_ctx,
        cache = {
          get = function(_, k) return cache:get(k) end,
          set = function(_, k, v, ttl) writes[k] = { value = v, ttl = ttl }; cache:set(k, v, ttl) end,
        },
        clock = function() return inp.clock end,
        hash = normalize.djb2, json_decode = H.body_decode, re_find = H.re_find,
        judge = { call = function(prompt)
          calls = calls + 1; seen = prompt
          if inp.judge.error then return nil, inp.judge.error, inp.judge.kind end
          if inp.judge.by_question then
            local a = {}
            for n in pairs(prompt.questions) do a[n] = inp.judge.by_question[n] end
            return a
          end
          return inp.judge.answers
        end },
        log = function() end,
      }
      local v = core.evaluate(inp.req, ctx)
      local prompt
      if seen then
        local names = {}
        for n in pairs(seen.questions) do names[#names + 1] = n end
        table.sort(names)
        prompt = { text = seen.text, context = seen.context, questions = names }
      end
      same(c.expect, { verdict = v, headers = verdict.headers(v), judge_calls = calls,
        prompt = prompt, cache_writes = writes, subject_record = recorded, subject_store_writes = swrites,
        breaker = brk and { calls = brk_calls, state = brk:state() } })
    end)
  end
end)

describe("golden: utf8", function()
  local judge = require "jev.core.judge"
  for _, c in ipairs(load("utf8").cases) do
    it(c.name, function()
      local bytes = c.input.hex:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end)
      same(c.expect, { text = judge.build({ "injection" }, bytes, {}).text })
    end)
  end
end)
