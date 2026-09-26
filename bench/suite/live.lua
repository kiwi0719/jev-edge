-- bench/suite/live.lua
-- Every record of bench/datasets/suite-v1.jsonl through L1 (the shipped
-- llm-endpoints rule set: extraction over every role, judging window) and,
-- when L1 sends it on, the real judge. One JSON line per record, appended as
-- it finishes, so an interrupted run resumes where it stopped.
--
--   docker run --rm --env-file .env -v "$PWD":/work jev-edge-test resty \
--     --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;" \
--     -I /work/adapters/openresty/lib -I /work /work/bench/suite/live.lua [--ctx] [--limit N]
--
-- --ctx    send each record's `deployment` string as the deployment context
--          (written with the suite, before any result was seen)
-- --limit  first N records only (a pilot)
-- Environment: TYPESAFE_API_KEY [TYPESAFE_ENDPOINT, TYPESAFE_MODEL], SUITE_CONCURRENCY (default 6),
--   SUITE (default suite-v1: reads bench/datasets/<SUITE>.jsonl)
-- Output: /work/bench/datasets/live-suite-<model>-<bare|ctx>.jsonl for suite-v1 (bench/suite/report.lua
--   reads it), live-<SUITE>-<model>-<bare|ctx>.jsonl for any other SUITE

require("resty.jev.loader")()
local http  = require "resty.jev.http"
local judge = require "jev.core.judge"
local rules_mod = require "jev.core.rules"
local llm = require "jev.rules.llm-endpoints"
local cjson = require "cjson.safe"

local use_ctx, limit = false, nil
do
  local i = 1
  while i <= #arg do
    if arg[i] == "--ctx" then use_ctx = true
    elseif arg[i] == "--limit" then limit = tonumber(arg[i + 1]); i = i + 1 end
    i = i + 1
  end
end

local key = assert(os.getenv("TYPESAFE_API_KEY"), "TYPESAFE_API_KEY not set")
local cfg = {
  provider = "jev",
  endpoint = os.getenv("TYPESAFE_ENDPOINT") or "https://api.typesafe.ai/v1/systemone",
  model    = os.getenv("TYPESAFE_MODEL") or "jev-latest",
  api_key  = key, timeout_ms = 15000,
}
local usage_in, usage_out = 0, 0
local j = assert(http.new(cfg, nil, function(ev, u)
  if ev == "usage" then usage_in = usage_in + (u.input_tokens or 0); usage_out = usage_out + (u.output_tokens or 0) end
end))

local records = {}
local suite = os.getenv("SUITE") or "suite-v1"
local tag = suite == "suite-v1" and "suite" or suite
for line in io.lines("/work/bench/datasets/" .. suite .. ".jsonl") do
  if line:match("%S") then records[#records + 1] = assert(cjson.decode(line)) end
  if limit and #records >= limit then break end
end

local out_path = string.format("/work/bench/datasets/live-%s-%s-%s.jsonl", tag, cfg.model, use_ctx and "ctx" or "bare")
local done = {}
do
  local f = io.open(out_path, "r")
  if f then
    for line in f:lines() do
      local r = cjson.decode(line)
      if r and r.id and not r.err then done[r.id] = true end
    end
    f:close()
  end
end
local w = assert(io.open(out_path, "a"))

local function store()
  local d = {}
  return { get = function(_, k) return d[k] end, set = function(_, k, v) d[k] = v end }
end
local function re_find(s, p, init) return ngx.re.find(s, p, "joi", init and init > 1 and { pos = init } or nil) end
local function now() ngx.update_time(); return ngx.now() * 1000 end

local function one(r)
  local body = cjson.encode(r.body)
  local req = {
    method = "POST", path = "/v1/chat/completions",
    headers = { ["content-type"] = "application/json" },
    body = body, body_size = #body, client_ip = "203.0.113.7",
  }
  local ctx = { cache = store(), clock = function() return 1000 end, json_decode = cjson.decode, re_find = re_find }
  local res, text, reason, windowed = rules_mod.evaluate(req, llm, ctx)
  local row = {
    id = r.id, label = r.label, source = r.source, category = r.category, shape = r.shape, lang = r.lang,
    l1 = res, reason = reason, windowed = windowed and true or false,
    body_bytes = #body, judged_bytes = text and #text or 0,
  }
  if res ~= rules_mod.SUSPECT then return row end
  local p = judge.build({ "injection", "abuse" }, text, { deployment = use_ctx and r.deployment or nil })
  local ans, err
  for attempt = 1, 4 do
    local t0 = now()
    ans, err = j.call(p, cfg.timeout_ms)
    if ans then row.ms = math.floor(now() - t0); break end
    ngx.sleep(1.5 * attempt)
  end
  if ans then
    row.injection, row.abuse = tonumber(ans.injection), tonumber(ans.abuse)
  else
    row.err = tostring(err)
  end
  return row
end

local todo = {}
for _, r in ipairs(records) do if not done[r.id] then todo[#todo + 1] = r end end
io.stderr:write(string.format("%d records, %d already done, %d to run -> %s\n", #records, #records - #todo, #todo, out_path))

local next_i, finished, errs = 0, 0, 0
local t_start = now()
local function worker()
  while true do
    next_i = next_i + 1
    local r = todo[next_i]
    if not r then return end
    local ok, row = pcall(one, r)
    if not ok then row = { id = r.id, label = r.label, category = r.category, shape = r.shape, lang = r.lang, err = tostring(row) } end
    if row.err then errs = errs + 1 end
    w:write(cjson.encode(row), "\n"); w:flush()
    finished = finished + 1
    if finished % 100 == 0 then
      io.stderr:write(string.format("%d/%d  errors=%d  %.0fs  tokens in=%d out=%d\n",
        finished, #todo, errs, (now() - t_start) / 1000, usage_in, usage_out))
    end
  end
end

local threads = {}
for _ = 1, tonumber(os.getenv("SUITE_CONCURRENCY") or "6") do threads[#threads + 1] = ngx.thread.spawn(worker) end
for _, t in ipairs(threads) do ngx.thread.wait(t) end
w:close()
io.write(cjson.encode({ ran = finished, errors = errs, wall_s = (now() - t_start) / 1000,
  input_tokens = usage_in, output_tokens = usage_out, out = out_path }), "\n")
