-- bench/tools/run.lua
-- False positives of the tool-definitions part: the shipped core, end to end,
-- over bench/datasets/tools-fp-v1.jsonl (real tool sets, no attack text) with
-- the real judge. Protocol, budget and the decision rule: bench/tools/README.md.
--
--   docker run --rm -e TYPESAFE_API_KEY -v "$PWD":/work jev-edge-test resty \
--     --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
--     -I /work/adapters/openresty/lib -I /work /work/bench/tools/run.lua
--   DRY=1 (no key needed): a fake judge answers 0.01, nothing leaves the machine.
--
-- Every body carries the same 16-character user message, under the rule's
-- min_text_chars, so core judges the tools part alone: one judge call per body.
-- Two passes, each record with a fresh cache:
--   injection  as shipped: the tools part asks the rule's templates ("injection")
--   untrusted  the harness swaps that one part's question for "untrusted" by
--              wrapping jev.core.judge.build when the prompt text is the tools
--              text L1 extracted for the record. Nothing else changes.
-- Every provider attempt counts against MAX_CALLS (66), across resumed runs
-- too; at the cap the judge answers an error without calling.
-- Output: bench/datasets/live-tools-fp-<model>.jsonl, one line per record and
-- pass (no key, no body). bench/tools/report.lua reads it.

require("resty.jev.loader")()
local core      = require "jev.core"
local judge_mod = require "jev.core.judge"
local rules_mod = require "jev.core.rules"
local defaults  = require "jev.core.defaults"
local normalize = require "jev.core.normalize"
local cjson     = require "cjson.safe"

local MAX_CALLS = 66
local DRY = os.getenv("DRY") == "1"
local MODEL = os.getenv("TYPESAFE_MODEL") or "jev-latest"

local provider
if not DRY then
  local http = require "resty.jev.http"
  provider = assert(http.new({
    provider = "jev",
    endpoint = os.getenv("TYPESAFE_ENDPOINT") or "https://api.typesafe.ai/v1/systemone",
    model    = MODEL,
    api_key  = assert(os.getenv("TYPESAFE_API_KEY"), "TYPESAFE_API_KEY not set"),
    timeout_ms = 15000,
  }))
end
local rule = require "jev.rules.llm-endpoints"
local cfg = defaults.merge(defaults.config, { jev = { model = MODEL, timeout_ms = 15000, timeout_max_ms = 15000 } })
assert(cfg.policy.suspect_threshold == 0.5 and cfg.policy.block_threshold == 0.7, "shipped thresholds changed")
assert(#rule.templates == 1 and rule.templates[1] == "injection", "rule templates changed")

local in_path  = "/work/bench/datasets/tools-fp-v1.jsonl"
local out_path = DRY and "/work/bench/out/tools-fp-dry.jsonl" or ("/work/bench/datasets/live-tools-fp-" .. MODEL .. ".jsonl")
os.execute("mkdir -p /work/bench/out")

-- resume: what is done, and what the earlier runs spent
local done, calls = {}, 0
do
  local f = io.open(out_path, "r")
  if f then
    for l in f:lines() do
      local r = cjson.decode(l)
      if r then
        calls = calls + (tonumber(r.judge_calls) or 0)
        if r.verdict ~= "error" then done[r.id .. "|" .. r.pass] = true end
      end
    end
    f:close()
  end
end

local function store()
  local d = {}
  return { get = function(_, k) return d[k] end, set = function(_, k, v) d[k] = v end }
end

local function now_ms() ngx.update_time(); return ngx.now() * 1000 end

-- the part being judged: set per record before core.evaluate
local expect = nil   -- { text = tools text, pass = "injection" | "untrusted" }
local seen = nil     -- what build was asked: { templates = ..., n = builds }
local orig_build = judge_mod.build
judge_mod.build = function(names, text, context)
  seen.n = seen.n + 1
  if not expect or text ~= expect.text then
    return nil, "harness: a part other than the tool definitions was judged"
  end
  if expect.pass == "untrusted" then
    -- asked the way the untrusted question is asked of retrieved content:
    -- no deployment context
    names = { "untrusted" }
    context = { path = context and context.path or "", method = context and context.method or "", deployment = "" }
  end
  seen.templates = table.concat(names, ",")
  return orig_build(names, text, context)
end

local rec_calls, rec_ms
local function call(prompt, timeout)
  local a, e, kind
  for attempt = 1, 2 do
    if calls >= MAX_CALLS then return nil, "budget: " .. MAX_CALLS .. " calls spent" end
    calls = calls + 1
    rec_calls = rec_calls + 1
    local t0 = now_ms()
    if DRY then
      a = {}
      for name in pairs(prompt.questions) do a[name] = 0.01 end
    else
      a, e, kind = provider.call(prompt, timeout)
    end
    rec_ms[#rec_ms + 1] = math.floor(now_ms() - t0)
    if a then return a end
    io.stderr:write("attempt ", attempt, " failed: ", tostring(e), "\n")
    ngx.sleep(2)
  end
  return nil, e, kind
end

local function ctx_for()
  return {
    config = cfg, rules = { rule }, cache = store(),
    judge = { call = call },
    clock = function() ngx.update_time(); return ngx.now() end,
    hash = normalize.djb2, json_decode = cjson.decode,
    re_find = function(s, p) return ngx.re.find(s, p, "joi") end,
  }
end

local function one(r, pass)
  local body = cjson.encode(r.body)
  local req = { method = "POST", path = "/v1/chat/completions", headers = { ["content-type"] = "application/json" },
                body = body, body_size = #body, client_ip = "203.0.113.7" }
  -- what L1 hands over, read the way core reads it
  local lr, text, l1_reason, _, _, _, _, untrusted, tools = rules_mod.evaluate_all(req, { rule }, ctx_for())
  assert(lr == rules_mod.SUSPECT, "L1 did not pass the body on: " .. tostring(l1_reason))
  assert(tools and tools.only and not untrusted, "expected the tools part alone")
  assert(#text < (rule.min_text_chars or 20), "the user message is judged too")
  expect, seen, rec_calls, rec_ms = { text = tools.text, pass = pass }, { n = 0 }, 0, {}
  local t0 = now_ms()
  local v = core.evaluate(req, ctx_for())
  local wall = math.floor(now_ms() - t0)
  expect = nil
  return {
    id = r.id, pass = pass, kind = r.kind, n_tools = r.n_tools,
    tools_bytes = #tools.text, windowed = tools.windowed, l1_reason = l1_reason, l1_hit = tools.hit,
    asked = seen.templates, builds = seen.n,
    verdict = v.verdict, score = v.score, reason = v.reason, source_layer = v.source,
    judge_calls = rec_calls, call_ms = rec_ms, l2_ms = v.l2_ms and math.floor(v.l2_ms) or nil, wall_ms = wall,
  }
end

local recs = {}
for line in io.lines(in_path) do recs[#recs + 1] = assert(cjson.decode(line)) end

local w = assert(io.open(out_path, "a"))
local errs, ran = 0, 0
for _, pass in ipairs({ "injection", "untrusted" }) do
  for _, r in ipairs(recs) do
    if not done[r.id .. "|" .. pass] then
      local ok, row = pcall(one, r, pass)
      if not ok then
        row = { id = r.id, pass = pass, verdict = "error", reason = tostring(row), judge_calls = rec_calls or 0 }
      end
      rec_calls = 0
      if row.verdict == "error" then errs = errs + 1 end
      ran = ran + 1
      w:write(cjson.encode(row), "\n"); w:flush()
      io.stderr:write(string.format("%-10s %-34s %-10s %s  calls %d/%d\n", pass, r.id, tostring(row.verdict),
        row.score and string.format("%.3f", row.score) or "-", calls, MAX_CALLS))
    end
  end
end
w:close()
io.write(cjson.encode({ ran = ran, errors = errs, calls_total = calls, max_calls = MAX_CALLS, out = out_path, dry = DRY }), "\n")
