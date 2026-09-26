#!/bin/sh
# Kong hybrid mode: a data plane that lacks a rule file the control plane
# has. Run by run.sh (make e2e-kong); needs Docker and the jev-edge-test image.
set -e
cd "$(dirname "$0")/hybrid"
project="${COMPOSE_PROJECT_NAME:-jev-e2e-kong}-hybrid"
dc() { docker compose -p "$project" "$@"; }
tmp=$(mktemp -d)
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/certs" && chmod 777 "$tmp/certs"
docker run --rm -u 0 -v "$tmp/certs":/c kong:3.9 \
  sh -c 'kong hybrid gen_cert /c/cluster.crt /c/cluster.key >/dev/null && chmod 644 /c/cluster.crt /c/cluster.key'
export JEV_E2E_CERTS="$tmp/certs"
dc up -d --quiet-pull 2>&1 | grep -v ' Created\| Started\| Built\| Waiting\| Healthy\| Exited\| Creating\| Starting\| Running' || true

fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$2] got [$3]"; fail=1; fi
}
admin() { dc exec -T app curl -s -o /dev/null -w '%{http_code}' "$@" </dev/null; }
LONG='{"messages":[{"role":"user","content":"Please write a detailed summary of the attached quarterly report."}]}'
dp() { # path -> the app's answer through the data plane
  dc exec -T app curl -s -H 'Content-Type: application/json' -H 'X-E2e-Reason: 1' -d "$LONG" "http://dp:8000$1" </dev/null
}
wait_for() { # path expected: poll until the DP answers it (its config synced)
  got=""
  for i in $(seq 1 80); do
    got=$(dp "$1" 2>/dev/null || true)
    [ "$got" = "$2" ] && break
    sleep 0.5
  done
  printf '%s' "$got"
}
route() { # name path plugin-config-json -> the plugin's creation status
  admin -X POST http://cp:8001/services/app/routes -d "name=$1" -d "paths[]=$2" -d strip_path=false >/dev/null
  admin -X POST "http://cp:8001/routes/$1/plugins" -H 'Content-Type: application/json' \
    -d "{\"name\":\"jev-edge\",\"config\":$3}"
}
MOCK='"jev":{"provider":"mock","mock_score":0.2,"timeout_ms":300}'
CFG_A='{'"$MOCK"',"rules_json":"[{\"id\":\"a\",\"extends\":\"llm-endpoints\",\"watch_paths\":[\"^/a/\"]}]","policy":{"mode":"enforce"}}'
CFG_C='{'"$MOCK"',"rules_json":"[{\"id\":\"c\",\"extends\":\"llm-endpoints\",\"watch_paths\":[\"^/c/\"]}]","policy":{"mode":"enforce"}}'
CFG_B='{'"$MOCK"',"rules":["cp-only"],"policy":{"mode":"enforce"}}'
CFG_D='{'"$MOCK"',"rules":["cp-only"],"policy":{"mode":"enforce","unjudgeable":"block"}}'
SAFE="app verdict=safe score=0.20 source=l2 reason=injection+0.20"
ERR="app verdict=error score=0.00 source=adapter reason=rules+failed+to+load%3A+cp-only"

for i in $(seq 1 120); do
  [ "$(admin http://cp:8001/status 2>/dev/null)" = "200" ] && break
  sleep 0.5
done
check "control plane is up" "201" "$(admin -X POST http://cp:8001/services -d name=app -d url=http://app:8081)"
code=$(route a /a "$CFG_A")
check "route a (a rule set both nodes have) is accepted" "201" "$code"
check "route a is judged on the data plane" "$SAFE" "$(wait_for /a/chat "$SAFE")"
# the CP has cp-only: it accepts both; the DP lacks it
code=$(route b /b "$CFG_B")
check "route b (cp-only, a rule set the DP lacks) is accepted by the CP" "201" "$code"
code=$(route d /d "$CFG_D")
check "route d (cp-only, unjudgeable = block) is accepted by the CP" "201" "$code"
check "route b on the DP: verdict error, the missing rule named, passed" "$ERR" "$(wait_for /b/chat "$ERR")"
code=""
for i in $(seq 1 40); do
  code=$(dc exec -T app curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d "$LONG" http://dp:8000/d/chat </dev/null)
  [ "$code" = "403" ] && break
  sleep 0.5
done
check "route d on the DP: blocked (policy.unjudgeable = block, enforce)" "403" "$code"
# the DP kept syncing: a route added after the ones it cannot judge arrives
code=$(route c /c "$CFG_C")
check "route c is accepted" "201" "$code"
check "a route added later still reaches the DP" "$SAFE" "$(wait_for /c/chat "$SAFE")"
check "the DP logs the rule that failed to load" "yes" \
  "$(dc logs dp 2>/dev/null | grep -q 'rules\[1\] (cp-only) failed to load' && echo yes || echo no)"

if [ $fail -ne 0 ]; then echo; echo "--- dp logs"; dc logs dp | tail -30; echo "--- cp logs"; dc logs cp | tail -20; exit 1; fi
echo "kong hybrid e2e: all checks passed"
