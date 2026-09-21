-- wrk script: POST random chat bodies from a JSON-lines file.
-- env BODIES=/path/to/file.jsonl  PATH_=/v1/chat/completions  SCORE=0.2|fail|slow

local bodies = {}
local f = assert(io.open(os.getenv("BODIES") or "/work/bench/datasets/bodies.jsonl", "r"))
for line in f:lines() do if #line > 0 then bodies[#bodies + 1] = line end end
f:close()

local path = os.getenv("PATH_") or "/v1/chat/completions"
local score = os.getenv("SCORE") or "0.2"

wrk.method = "POST"
wrk.path = path
wrk.headers["Content-Type"] = "application/json"
wrk.headers["X-Jev-Mock-Score"] = score

local i = 0
request = function()
  i = i + 1
  return wrk.format(nil, path, nil, bodies[(i % #bodies) + 1])
end

done = function(summary, latency, requests)
  io.write(string.format("RESULT requests=%d errors=%d p50_us=%d p99_us=%d max_us=%d rps=%.0f\n",
    summary.requests, summary.errors.status, latency:percentile(50), latency:percentile(99), latency.max,
    summary.requests / (summary.duration / 1e6)))
end
