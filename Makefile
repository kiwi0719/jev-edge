.PHONY: test lint check luajit-check golden golden-check calibrate labels context-lint test-js test-openresty bench bench-offline bench-chart dist opm-build rock-lint rock-pack rock-upload install live-check live-full live-openai soak shim e2e-envoy e2e-forward-auth e2e-apisix e2e-haproxy test-litellm

test:
	busted

# Homebrew's luacheck is built against Lua 5.5 and crashes there; install one
# for LuaJIT instead (see CONTRIBUTING.md) and point LUACHECK at it:
#   luarocks --lua-version 5.1 --lua-dir=$(brew --prefix luajit) --local install luacheck
#   make lint LUACHECK=~/.luarocks/bin/luacheck
LUACHECK ?= luacheck
lint:
	$(LUACHECK) core rules $$(ls -d adapters bench 2>/dev/null)

# Every core file must at least compile under LuaJIT (the OpenResty runtime).
luajit-check:
	@for f in $$(find core rules -name '*.lua' -not -path '*/spec/*'); do \
	  luajit -bl $$f >/dev/null || exit 1; done; echo "luajit ok"

check: lint luajit-check golden-check test

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

# JavaScript adapter: the TypeScript core replays the same golden vectors (needs pnpm).
test-js:
	cd adapters/js && pnpm install --frozen-lockfile --silent && pnpm typecheck && pnpm test

# Deployment-context lint: make context-lint CONF=/etc/nginx/jev-edge.conf.lua
# or make context-lint TEXT="A support assistant ..."
context-lint:
	lua bench/context_lint.lua $${CONF:-} $${TEXT:+--text "$$TEXT"}

# Threshold calibration from monitor-mode logs plus labels:
#   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv [MAX_FP=0.001]
# Operator feedback (POST /_jev/feedback) is written to the jev access log, not
# to a file; this derives the labels file calibrate reads from those log lines:
#   make labels LOG=/var/log/nginx/jev.log OUT=bench/datasets/labels.csv
labels:
	lua bench/labels-from-log.lua $${LOG:?set LOG=<jev access log>} $${OUT:+-o $$OUT}

calibrate:
	lua bench/calibrate.lua $${LOG:?set LOG=<jev access log>} $${LABELS:-} $${MAX_FP:+--max-fp $$MAX_FP}

# Integration tests run in the official OpenResty image (needs Docker).
# --init matters: without a reaper Test::Nginx waits on zombie masters.
test-openresty:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$(CURDIR)":/work jev-edge-test

bench-offline:
	lua bench/offline.lua

bench:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$(CURDIR)":/work jev-edge-test sh /work/bench/run.sh

# Redraw docs/bench-latency-*.svg from a results.txt (default: the 4-connection run).
bench-chart:
	lua bench/chart.lua $${RESULTS:-bench/out-c4/results.txt} docs

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
