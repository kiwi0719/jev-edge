#!/bin/sh
# Soak / limits check. Runs inside the jev-edge-test image:
#   docker run --rm --init -v "$PWD":/work jev-edge-test sh /work/bench/soak.sh
#
# 4 workers, tiny shared dicts, low caps, 60 s of mixed traffic with a slow mock.
# Verifies: no worker crash, every request answered, max_inflight and max_async
# drops are counted rather than queued, a full shared dict only logs,
# breaker and adaptive state are shared across workers, memory is flat.

set -e
cd /work
apk add --no-cache -q wrk jq procps >/dev/null 2>&1 || true
DUR=${DUR:-60s}
mkdir -p /tmp/nx/logs /tmp/nx/conf bench/out
jq -c '.samples[] | {messages:[{role:"user",content:.text}]}' bench/datasets/jev-sec-bench-injection.json > bench/datasets/bodies.jsonl

cat > /tmp/nx/conf/jev-edge.conf.lua <<'EOF'
return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.6,   -- suspicious band => L3 for everything
          mock_delay_ms = 80, mock_fail_ratio = 0.05, timeout_ms = 100, timeout_max_ms = 300, max_inflight = 8 },
  rules = { "llm-endpoints" },
  policy = { mode = "enforce", block_threshold = 0.85, suspect_threshold = 0.5 },
  cache = { fp_ttl = 30 },
  async = { enabled = true, max_async = 4, rep_block_after = 0 },
  breaker = { window_s = 10, min_samples = 50, fail_ratio = 0.5, open_s = 3 },
}
EOF
cat > /tmp/nx/conf/nginx.conf <<'EOF'
worker_processes 4; error_log /tmp/nx/logs/error.log warn; pid /tmp/nx/nginx.pid;
events { worker_connections 4096; }
http {
  lua_package_path "/work/adapters/openresty/lib/?.lua;/work/?.lua;;";
  lua_shared_dict jev_cache 256k; lua_shared_dict jev_config 64k; lua_shared_dict jev_metrics 256k;
  init_by_lua_block { require("resty.jev.edge").init("/tmp/nx/conf/jev-edge.conf.lua") }
  init_worker_by_lua_block { require("resty.jev.edge").init_worker() }
  access_log off;
  server {
    listen 18080;
    location /v1/ { access_by_lua_block { require("resty.jev.edge").access() } content_by_lua_block { ngx.say("ok") } }
    location = /_jev/metrics { content_by_lua_block { require("resty.jev.edge").metrics() } }
    location = /_jev/health  { content_by_lua_block { require("resty.jev.edge").health() } }
  }
}
EOF
openresty -p /tmp/nx -c /tmp/nx/conf/nginx.conf; sleep 0.5
rss() { ps -o rss= -p $(pgrep -f 'nginx: worker' | tr '\n' ',' | sed 's/,$//') | awk '{s+=$1} END {print s}'; }
echo "rss_kb_start=$(rss)"
BODIES=/work/bench/datasets/bodies.jsonl PATH_=/v1/chat/completions SCORE=0.6 \
  wrk -t4 -c64 -d$DUR -s bench/wrk-post.lua http://127.0.0.1:18080/v1/chat/completions 2>/dev/null | grep RESULT
echo "rss_kb_end=$(rss)"
echo "--- metrics"
curl -s localhost:18080/_jev/metrics | grep -E 'jev_requests_total|actions|async_dropped|breaker_state|l2_timeout'
echo "--- health (breaker/adaptive shared: samples should be > 0 from any worker)"
for i in 1 2 3 4; do curl -s localhost:18080/_jev/health | jq -c '{samples:.timeout.samples, effective:.timeout.effective_ms, breaker:.breaker_state}'; done
echo "--- error.log summary"
grep -oE 'jev-edge: [a-zA-Z0-9 _:]+' /tmp/nx/logs/error.log | sed 's/[0-9]\+/N/g' | sort | uniq -c | sort -rn | head
echo "workers alive: $(pgrep -fc 'nginx: worker') ; crashes: $(grep -c 'exited on signal' /tmp/nx/logs/error.log || true)"
openresty -p /tmp/nx -c /tmp/nx/conf/nginx.conf -s quit
