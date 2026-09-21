#!/bin/sh
# End-to-end latency bench. Runs inside the jev-edge-test image (see
# adapters/openresty/Dockerfile.test). Invoke from the repo root with:
#
#   make bench
#
# Scenarios (mock provider):
#   baseline   jev-edge not loaded at all
#   unwatched  access() runs, path not watched (L1 pass)
#   healthy    watched path, mock Jev answers in 100 ms
#   slow       watched path, mock Jev answers in 500 ms (over the 300 ms cut)
#   dead       watched path, mock Jev fails every call
#
# Bodies come from the benign half of the deepset dataset (natural language,
# so L1 sends them to L2 - this measures the expensive path, not the cheap one).

set -e
cd /work
apk add --no-cache -q wrk jq >/dev/null 2>&1 || true

DUR=${DUR:-10s}
CONN=${CONN:-32}
OUT=${OUT:-bench/out}
mkdir -p $OUT /tmp/nx/logs /tmp/nx/conf

jq -c '.samples[] | select(.label==0) | {messages:[{role:"user",content:.text}]}' \
  bench/datasets/jev-sec-bench-injection.json > bench/datasets/bodies.jsonl

write_conf() { # $1 = mock_delay_ms, $2 = mock_fail_ratio
cat > /tmp/nx/conf/jev-edge.conf.lua <<EOF
return {
  jev = { provider = "mock", mock_header = "x-jev-mock-score", mock_score = 0.2,
          mock_delay_ms = $1, mock_fail_ratio = $2, timeout_ms = 300 },
  rules = { "llm-endpoints" },
  policy = { mode = "enforce", block_threshold = 0.85, suspect_threshold = 0.5 },
  cache = { fp_ttl = 0.001 },
  breaker = { window_s = 60, min_samples = 20, fail_ratio = 0.5, open_s = 5 },
}
EOF
}

cat > /tmp/nx/conf/nginx.conf <<'EOF'
worker_processes 2; error_log /tmp/nx/logs/error.log warn; pid /tmp/nx/nginx.pid;
events { worker_connections 4096; }
http {
  lua_package_path "/work/adapters/openresty/lib/?.lua;/work/?.lua;;";
  lua_shared_dict jev_cache 32m; lua_shared_dict jev_config 1m; lua_shared_dict jev_metrics 1m;
  init_by_lua_block { require("resty.jev.edge").init("/tmp/nx/conf/jev-edge.conf.lua") }
  init_worker_by_lua_block { require("resty.jev.edge").init_worker() }
  access_log off;
  server {
    listen 18080;
    location /baseline/ { content_by_lua_block { ngx.say("ok") } }
    location /static/   { access_by_lua_block { require("resty.jev.edge").access() } content_by_lua_block { ngx.say("ok") } }
    location /v1/       { access_by_lua_block { require("resty.jev.edge").access() } content_by_lua_block { ngx.say("ok") } }
    location = /_jev/metrics { content_by_lua_block { require("resty.jev.edge").metrics() } }
  }
}
EOF

run() { # name path score
  name=$1; path=$2; score=$3
  BODIES=/work/bench/datasets/bodies.jsonl PATH_=$path SCORE=$score \
    wrk -t2 -c$CONN -d$DUR -s bench/wrk-post.lua http://127.0.0.1:18080$path 2>/dev/null | grep RESULT | sed "s/^RESULT/$name/" | tee -a $OUT/results.txt
}

: > $OUT/results.txt

start() { openresty -p /tmp/nx -c /tmp/nx/conf/nginx.conf; sleep 0.5; }
stop()  { openresty -p /tmp/nx -c /tmp/nx/conf/nginx.conf -s quit; while [ -f /tmp/nx/nginx.pid ]; do sleep 0.05; done; }

write_conf 100 0
start
run baseline  /baseline/x 0.2
run unwatched /static/x   0.2
run healthy   /v1/chat/completions 0.2
curl -s localhost:18080/_jev/metrics > $OUT/metrics-healthy.txt
stop

write_conf 500 0
start
run slow /v1/chat/completions 0.2
curl -s localhost:18080/_jev/metrics > $OUT/metrics-slow.txt
stop

write_conf 0 1
start
run dead /v1/chat/completions 0.2
curl -s localhost:18080/_jev/metrics > $OUT/metrics-dead.txt
stop

echo
echo "== results ($DUR, $CONN connections, 2 workers, mock provider) =="
cat $OUT/results.txt
echo
echo "== dead-Jev verdict split (must be 100% pass) =="
grep -E 'jev_actions_total|jev_breaker_state|source="breaker"' $OUT/metrics-dead.txt
