-- bench/live_full.lua
-- Full live run: every dataset sample through the real provider with BOTH
-- bundled templates in one request. Writes bench/datasets/live-<model>.json
-- with the live probabilities so accuracy can be recomputed offline.
--
--   docker run --rm --env-file .env -v "$PWD":/work jev-edge-test resty \
--     --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;" \
--     -I /work/adapters/openresty/lib -I /work /work/bench/live_full.lua

require("resty.jev.loader")()
local http  = require "resty.jev.http"
local judge = require "jev.core.judge"
local cjson = require "cjson.safe"

local key = assert(os.getenv("TYPESAFE_API_KEY"), "TYPESAFE_API_KEY not set")
local cfg = {
  provider = "jev",
  endpoint = os.getenv("TYPESAFE_ENDPOINT") or "https://api.typesafe.ai/v1/systemone",
  model    = os.getenv("TYPESAFE_MODEL") or "jev-latest",
  api_key  = key, timeout_ms = 8000,
}
local usage_in, usage_out = 0, 0
local j = assert(http.new(cfg, nil, function(ev, u)
  if ev == "usage" then usage_in = usage_in + (u.input_tokens or 0); usage_out = usage_out + (u.output_tokens or 0) end
end))

local f = assert(io.open("/work/bench/datasets/jev-sec-bench-injection.json"))
local data = cjson.decode(f:read("*a")); f:close()

local out = { model = cfg.model, run_at = os.date("!%Y-%m-%dT%H:%M:%SZ"), templates = { "injection", "abuse" },
  deployment_context = os.getenv("JEV_DEPLOYMENT_CONTEXT") or "", samples = {} }
local lats, errs = {}, 0
local function now() ngx.update_time(); return ngx.now() * 1000 end
local t_start = now()

for i, s in ipairs(data.samples) do
  local p = judge.build({ "injection", "abuse" }, s.text, { deployment = os.getenv("JEV_DEPLOYMENT_CONTEXT") or "" })
  local ans, err
  for attempt = 1, 3 do
    local t0 = now()
    ans, err = j.call(p, cfg.timeout_ms)
    if ans then lats[#lats + 1] = now() - t0; break end
    ngx.sleep(0.5 * attempt)
  end
  if not ans then
    errs = errs + 1
    io.stderr:write(string.format("sample %d failed: %s\n", i, tostring(err)))
  end
  out.samples[#out.samples + 1] = {
    text = s.text, label = s.label, recorded = s.probability,
    injection = ans and ans.injection or cjson.null, abuse = ans and ans.abuse or cjson.null,
  }
  if i % 50 == 0 then io.stderr:write(string.format("%d/%d\n", i, #data.samples)) end
end

table.sort(lats)
local function pct(q) return lats[math.max(1, math.ceil(#lats * q))] end
out.stats = {
  n = #lats, errors = errs, wall_s = (now() - t_start) / 1000,
  p50_ms = pct(0.5), p95_ms = pct(0.95), p99_ms = pct(0.99), max_ms = lats[#lats],
  input_tokens = usage_in, output_tokens = usage_out,
}
local path = "/work/bench/datasets/live-" .. cfg.model .. (out.deployment_context ~= "" and "-ctx" or "") .. ".json"
local w = assert(io.open(path, "w")); w:write(cjson.encode(out)); w:close()
io.write(cjson.encode(out.stats), "\nwrote ", path, "\n")
