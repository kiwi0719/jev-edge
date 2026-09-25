.PHONY: test lint check invariants luajit-check golden golden-check calibrate labels context-lint test-js test-openresty bench bench-offline bench-judge bench-judge-live bench-chart dist opm-build rock-lint rock-pack rock-upload install live-check live-full live-openai soak shim e2e-envoy e2e-forward-auth e2e-apisix e2e-kong e2e-haproxy test-litellm suite-fetch suite-build suite-live suite-report suite-tooldocs-build suite-untrusted suite-untrusted-report suite-heldout-build suite-heldout suite-heldout-report conformance conformance-vectors conformance-check test-laya

test:
	busted

# Homebrew's luacheck is built against Lua 5.5 and crashes there; install one
# for LuaJIT instead (see CONTRIBUTING.md) and point LUACHECK at it:
#   luarocks --lua-version 5.1 --lua-dir=$(brew --prefix luajit) --local install luacheck
#   make lint LUACHECK=~/.luarocks/bin/luacheck
LUACHECK ?= luacheck
lint:
	$(LUACHECK) core rules scripts conformance $$(ls -d adapters bench 2>/dev/null)

# Every core file must at least compile under LuaJIT (the OpenResty runtime).
LUAJIT ?= luajit
luajit-check:
	@for f in $$(find core rules -name '*.lua' -not -path '*/spec/*'); do \
	  $(LUAJIT) -e "assert(loadfile('$$f'))" || exit 1; done; echo "luajit ok"

check: lint invariants luajit-check golden-check conformance-check test

# Tripwires for bug classes a past audit found (scripts/invariants.lua).
invariants:
	lua scripts/invariants.lua

# Golden vectors: the cross-implementation contract for core (core/golden/README.md).
# `golden` regenerates them from the Lua core after a deliberate behaviour change;
# `golden-check` fails when the committed files no longer match what core produces.
golden:
	lua core/golden/gen.lua

golden-check:
	@tmp=$$(mktemp -d) && lua core/golden/gen.lua $$tmp 2>/dev/null && \
	  if diff -ru core/golden $$tmp --exclude=gen.lua --exclude=README.md >/dev/null; then \
	    echo "golden ok"; rm -rf $$tmp; \
	  else diff -ru core/golden $$tmp --exclude=gen.lua --exclude=README.md | head -40; \
	    echo "golden vectors are stale: run 'make golden' and commit core/golden/*.json"; rm -rf $$tmp; exit 1; fi

# Protocol conformance for judge servers (conformance/gen.lua): the System One
# request as the gateway builds it, checked against a live server.
#   make conformance ENDPOINT=http://127.0.0.1:8080/v1/systemone [API_KEY=...] [MODEL=laya]
#                    [STRICT=1] [MOCK=1] [BUDGET_MS=250]
# `conformance-vectors` regenerates the vectors after a template or provider
# change; `conformance-check` fails when the committed ones are stale.
conformance:
	python3 conformance/run.py --endpoint $${ENDPOINT:?set ENDPOINT=<judge url>} \
	  $${API_KEY:+--api-key $$API_KEY} $${MODEL:+--model $$MODEL} $${BUDGET_MS:+--budget-ms $$BUDGET_MS} \
	  $(if $(STRICT),--strict) $(if $(MOCK),--mock)

conformance-vectors:
	lua conformance/gen.lua

conformance-check:
	@tmp=$$(mktemp -d) && lua conformance/gen.lua $$tmp 2>/dev/null && \
	  if diff -u conformance/vectors.json $$tmp/vectors.json >/dev/null && \
	     diff -u conformance/questions.json $$tmp/questions.json >/dev/null; then \
	    echo "conformance vectors ok"; rm -rf $$tmp; \
	  else diff -u conformance $$tmp | head -40; \
	    echo "conformance vectors are stale: run 'make conformance-vectors' and commit conformance/*.json"; rm -rf $$tmp; exit 1; fi

# laya-server (adapters/laya-server): unit tests, and the whole conformance
# suite in process against its mock backend; then run.py's own transport
# checks against stub servers (conformance/test_run.py). Standard library only.
test-laya:
	cd adapters/laya-server && python3 -m unittest -v test_laya_server
	cd conformance && python3 -m unittest -v test_run

# JavaScript adapter: the TypeScript core replays the same golden vectors (needs pnpm).
test-js:
	cd adapters/js && pnpm install --frozen-lockfile --silent && pnpm typecheck && pnpm test

# Deployment-context lint: make context-lint CONF=/etc/nginx/jev-edge.conf.lua
# or make context-lint TEXT="A support assistant ..."
context-lint:
	lua bench/context_lint.lua $${CONF:-} $${TEXT:+--text "$$TEXT"}

# Threshold calibration from monitor-mode logs plus labels:
#   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv [MAX_FP=0.001]
# One judge per run: a log with scores from several providers / models is
# refused until PROVIDER= (and MODEL=) picks one, e.g. PROVIDER=jev MODEL=laya.
# Operator feedback (POST /_jev/feedback) is written to the jev access log, not
# to a file; this derives the labels file calibrate reads from those log lines:
#   make labels LOG=/var/log/nginx/jev.log OUT=bench/datasets/labels.csv
labels:
	lua bench/labels-from-log.lua $${LOG:?set LOG=<jev access log>} $${OUT:+-o $$OUT}

calibrate:
	lua bench/calibrate.lua $${LOG:?set LOG=<jev access log>} $${LABELS:-} $${MAX_FP:+--max-fp $$MAX_FP} \
	  $${PROVIDER:+--provider $$PROVIDER} $${MODEL:+--model $$MODEL}

# Integration tests run in the official OpenResty image (needs Docker).
# --init matters: without a reaper Test::Nginx waits on zombie masters.
test-openresty:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$(CURDIR)":/work jev-edge-test

bench-offline:
	lua bench/offline.lua

# Judge-directed attacks (bench/datasets/judge-directed.jsonl) through L1:
# which reach L2, which a pattern names, which benign look-alikes it flags.
bench-judge:
	lua bench/judge_robustness.lua

# The same cases through the real judge, per-category detection. Costs
# provider calls: TYPESAFE_API_KEY (jev) and/or OPENAI_BASE_URL [OPENAI_API_KEY,
# OPENAI_MODEL] (openai-compat) in .env; JEV_DEPLOYMENT_CONTEXT optional.
bench-judge-live:
	docker run --rm --env-file .env -e JEV_DEPLOYMENT_CONTEXT -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/judge_robustness.lua --live'

bench:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$(CURDIR)":/work jev-edge-test sh /work/bench/run.sh

# Redraw docs/bench-latency-*.svg from a results.txt (default: the 4-connection run)
# and docs/bench-accuracy-*.svg from the live results committed under bench/datasets.
bench-chart:
	lua bench/chart.lua $${RESULTS:-bench/out-c4/results.txt} docs
	lua bench/chart_accuracy.lua docs

# One real round trip + 60-sample latency/agreement check against the provider.
# Needs TYPESAFE_API_KEY in .env (gitignored). Costs ~40k input tokens.
live-check:
	docker run --rm --env-file .env -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/live.lua $${N:-60}'

# Every dataset sample through the live provider with both templates; writes
# bench/datasets/live-<model>[-ctx].json. ~340k input tokens bare, ~400k with
# JEV_DEPLOYMENT_CONTEXT set in the environment.
live-full:
	docker run --rm --env-file .env -e JEV_DEPLOYMENT_CONTEXT -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/live_full.lua'

# Suite v1 (bench/suite/README.md): Chinese, multi-turn, indirect injection and
# over-defense look-alikes as whole chat bodies. suite-build needs Python +
# pyarrow and the sources suite-fetch downloads; the built suite is committed.
suite-fetch:
	sh bench/suite/fetch.sh

suite-build:
	python3 bench/suite/build.py --raw bench/suite/raw

# Costs provider calls: every record, both templates, ~2.7k calls per run.
# CTX=1 sends each record's deployment context. Resumes an interrupted run.
suite-live:
	docker run --rm --env-file .env -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/suite/live.lua $(if $(CTX),--ctx)'

suite-report:
	lua bench/suite/report.lua > bench/suite/report.md

# Experiment (bench/suite/README.md#experiment-judging-retrieved-content-on-its-own):
# the retrieved part of each indirect record judged on its own. Costs ~900 calls
# for suite v1 and ~1.6k for the non-email tool results (whole text + segment).
suite-tooldocs-build:
	python3 bench/suite/build_tooldocs.py --raw bench/suite/raw

suite-untrusted:
	docker run --rm --env-file .env -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'for s in "SUITE=suite-v1 untrusted" "SUITE=suite-v1-tooldocs live" "SUITE=suite-v1-tooldocs untrusted"; do \
	     set -- $$s; env $$1 resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	       -I /work/adapters/openresty/lib -I /work /work/bench/suite/$$2.lua || exit 1; done'

suite-untrusted-report:
	lua bench/suite/untrusted_report.lua > bench/suite/untrusted-report.md

# Held-out test for untrusted judging in the shipped core (bench/suite/README.md):
# heldout-v1 through core.evaluate with the real judge, untrusted off and on.
# ~3.6k calls. suite-heldout-build needs InjecAgent, Hermes and LLMail phase 1
# in bench/suite/raw (see build_heldout.py).
suite-heldout-build:
	python3 bench/suite/build_heldout.py --raw bench/suite/raw

suite-heldout:
	docker run --rm --env-file .env -v "$(CURDIR)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/suite/heldout.lua'

suite-heldout-report:
	lua bench/suite/heldout_report.lua > bench/suite/heldout-report.md

# openai-compat provider against an Ollama container on the jev-net network:
#   docker network create jev-net; docker run -d --rm --name ollama --network jev-net ollama/ollama
#   docker exec ollama ollama pull qwen2.5:0.5b
live-openai:
	docker run --rm --network jev-net -v "$(CURDIR)":/work jev-edge-test \
	  resty -I /work/adapters/openresty/lib -I /work /work/bench/live_openai.lua $${N:-20}

# 4 workers, tiny dicts, low caps, slow flaky mock: limits, drops, memory, crashes.
soak:
	docker run --rm --init -e DUR=$${DUR:-60s} -v "$(CURDIR)":/work jev-edge-test sh /work/bench/soak.sh

# Envoy: gRPC shim build and the two-transport end-to-end (Docker Compose).
shim:
	cd adapters/envoy/grpc-shim && go vet ./... && go test ./... && go build -o jev-shim .

e2e-envoy:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/envoy/e2e/run.sh

e2e-apisix:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/apisix/e2e/run.sh

e2e-kong:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/kong/e2e/run.sh

e2e-haproxy:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/haproxy/e2e/run.sh

# LiteLLM guardrail unit tests (needs python3 with httpx and pytest; LiteLLM itself is optional).
test-litellm:
	cd adapters/litellm && python3 -m pytest -q

# Traefik / Caddy / nginx forward-auth end-to-end (Docker Compose).
e2e-forward-auth:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/forward-auth/e2e/run.sh

# ---------------------------------------------------------------------------
# Packaging. The opm tarball and `make install` both flatten the tree into a
# single lib/ so `require "jev.core"` resolves without the loader shim:
#   lib/resty/jev/*   adapter        lib/jev/core/*  core        lib/jev/rules/*  rules
# ---------------------------------------------------------------------------
VERSION   := $(shell sed -n 's/^version = //p' dist.ini)
DIST      := dist/lua-resty-jev-edge-$(VERSION)
LUA_LIB_DIR ?= /usr/local/openresty/lualib
PREFIX_CONF ?= /etc/nginx

dist:
	rm -rf $(DIST) && mkdir -p $(DIST)/lib/jev/core $(DIST)/lib/jev/rules $(DIST)/lib/resty
	cp -R adapters/openresty/lib/resty/jev $(DIST)/lib/resty/
	cp core/*.lua $(DIST)/lib/jev/core/ && cp -R core/templates $(DIST)/lib/jev/core/
	cp rules/*.lua $(DIST)/lib/jev/rules/
	mkdir -p $(DIST)/doc && cp dist.ini LICENSE README.md $(DIST)/ && cp README.md CHANGELOG.md $(DIST)/doc/
	cp -R adapters/openresty/conf $(DIST)/conf
	@echo "assembled $(DIST)"

# opm build/upload run from the assembled tree (opm needs lib/ next to dist.ini).
# `opm build` only works inside a full OpenResty install (it looks for
# <prefix>/site); a Homebrew opm alone cannot. Without one, build in the
# official image instead: same command, same output under dist/.
opm-build: dist
	@if [ -d "$$(dirname $$(dirname $$(command -v opm 2>/dev/null || echo /x/x)))/site" ]; then \
	  cd $(DIST) && opm build; \
	else \
	  echo "no local OpenResty install; running opm build in openresty/openresty:alpine-fat"; \
	  test -f "$$HOME/.opmrc" || printf 'github_account=%s\n' "$$(sed -n 's/^author = //p' dist.ini)" > "$$HOME/.opmrc"; \
	  docker run --rm -v "$(CURDIR)/$(DIST)":/pkg -v "$$HOME/.opmrc":/root/.opmrc:ro -w /pkg openresty/openresty:alpine-fat opm build; \
	fi

# ---------------------------------------------------------------------------
# LuaRocks. The rockspec maps the source tree directly (no `make dist` needed);
# uploading requires an API key from https://luarocks.org/settings/api-keys;
# pass it once via ARGS=--api-key=<key> and luarocks stores it itself.
# ---------------------------------------------------------------------------
ROCKSPEC := lua-resty-jev-edge-$(VERSION)-1.rockspec

rock-lint:
	luarocks lint $(ROCKSPEC)

rock-pack: rock-lint
	luarocks pack $(ROCKSPEC)

# First run needs the key: make rock-upload ARGS=--api-key=<key>
# luarocks then saves it to ~/.luarocks/upload_config.lua for later runs.
rock-upload: rock-lint
	luarocks upload $(ARGS) $(ROCKSPEC)

install: dist
	mkdir -p $(LUA_LIB_DIR)/jev $(LUA_LIB_DIR)/resty
	cp -R $(DIST)/lib/jev $(LUA_LIB_DIR)/
	cp -R $(DIST)/lib/resty/jev $(LUA_LIB_DIR)/resty/
	@test -f $(PREFIX_CONF)/jev-edge.conf.lua || cp $(DIST)/conf/jev-edge.conf.lua $(PREFIX_CONF)/jev-edge.conf.lua
	@echo "installed to $(LUA_LIB_DIR); config at $(PREFIX_CONF)/jev-edge.conf.lua"
