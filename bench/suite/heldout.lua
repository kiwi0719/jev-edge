-- bench/suite/heldout.lua
-- The shipped core, end to end, over bench/datasets/heldout-v1.jsonl with the
-- real judge: every record once with `untrusted` off (today's behaviour) and
-- once with it on. Not a replay of the experiment's calls: core.evaluate does
-- the extraction, the parts, call_many, the reduce and the policy.
--
--   docker run --rm --env-file .env -v "$PWD":/work jev-edge-test resty \
--     --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
--     -I /work/adapters/openresty/lib -I /work /work/bench/suite/heldout.lua
--   (make suite-heldout)
--
-- Each record gets a fresh cache, so no record is scored from another's.
-- Output: bench/datasets/live-heldout-<model>.jsonl, one line per record and
-- mode; resumes an interrupted run. bench/suite/heldout_report.lua reads it.

require("resty.jev.loader")()
local http      = require "resty.jev.http"
local core      = require "jev.core"
local defaults  = require "jev.core.defaults"
local normalize = require "jev.core.normalize"
local cjson     = require "cjson.safe"

local key = assert(os.getenv("TYPESAFE_API_KEY"), "TYPESAFE_API_KEY not set")
local jcfg = {
  provider = "jev",
  endpoint = os.getenv("TYPESAFE_ENDPOINT") or "https://api.typesafe.ai/v1/systemone",
  model    = os.getenv("TYPESAFE_MODEL") or "jev-latest",
  api_key  = key, timeout_ms = 15000,
}
local provider = assert(http.new(jcfg))
local rule = require "jev.rules.llm-endpoints"

local function store()
  local d = {}
  return { get = function(_, k) return d[k] end, set = function(_, k, v) d[k] = v end }
end

local MODES = {
  off = defaults.merge(defaults.config, { jev = { model = jcfg.model, timeout_ms = 15000, timeout_max_ms = 15000 } }),
  on  = defaults.merge(defaults.config, { jev = { model = jcfg.model, timeout_ms = 15000, timeout_max_ms = 15000 },
                                          untrusted = { enabled = true } }),
}

local out_path = "/work/bench/datasets/live-heldout-" .. jcfg.model .. ".jsonl"
local done = {}
do
  local f = io.open(out_path, "r")
  if f then
    for l in f:lines() do
      local r = cjson.decode(l)
      if r and r.verdict ~= "error" then done[r.id .. "|" .. r.mode] = true end
    end
    f:close()
  end
end
local w = assert(io.open(out_path, "a"))

local function one(r, mode)
  local calls = 0
  local judge = {
    call = function(p, t)
      calls = calls + 1
      local a, e
      for attempt = 1, 3 do
        a, e = provider.call(p, t)
        if a then break end
        ngx.sleep(attempt)
      end
      return a, e
    end,
  }
  judge.call_many = function(prompts, t)
    local th, res = {}, {}
    for i, p in ipairs(prompts) do th[i] = ngx.thread.spawn(function() return judge.call(p, t) end) end
    for i, t2 in ipairs(th) do
      local _, a, e = ngx.thread.wait(t2)
      res[i] = { a, e }
    end
    return res
  end
  local body = cjson.encode(r.body)
  local req = { method = "POST", path = "/v1/chat/completions", headers = { ["content-type"] = "application/json" },
                body = body, body_size = #body, client_ip = "203.0.113.7" }
  local ctx = {
    config = MODES[mode], rules = { rule }, cache = store(), judge = judge,
    clock = function() ngx.update_time(); return ngx.now() end,
    hash = normalize.djb2, json_decode = cjson.decode,
    re_find = function(s, p) return ngx.re.find(s, p, "joi") end,
  }
  local v = core.evaluate(req, ctx)
  return { id = r.id, mode = mode, label = r.label, source = r.source, category = r.category, carrier = r.carrier,
           verdict = v.verdict, score = v.score, source_layer = v.source, reason = v.reason, judge_calls = calls,
           l2_ms = v.l2_ms and math.floor(v.l2_ms) or nil }
end

local todo = {}
for line in io.lines("/work/bench/datasets/heldout-v1.jsonl") do
  local r = cjson.decode(line)
  for _, mode in ipairs({ "off", "on" }) do
    if r and not done[r.id .. "|" .. mode] then todo[#todo + 1] = { r, mode } end
  end
end
io.stderr:write(#todo, " runs to do -> ", out_path, "\n")

local i, errs = 0, 0
local function worker()
  while true do
    i = i + 1
    local t = todo[i]
    if not t then return end
    local ok, row = pcall(one, t[1], t[2])
    if not ok then row = { id = t[1].id, mode = t[2], verdict = "error", reason = tostring(row) } end
    if row.verdict == "error" then errs = errs + 1 end
    w:write(cjson.encode(row), "\n"); w:flush()
  end
end
local th = {}
for _ = 1, 6 do th[#th + 1] = ngx.thread.spawn(worker) end
for _, t in ipairs(th) do ngx.thread.wait(t) end
w:close()
io.write(cjson.encode({ ran = #todo, errors = errs, out = out_path }), "\n")
