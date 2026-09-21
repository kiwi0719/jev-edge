.PHONY: test lint check luajit-check test-openresty bench bench-offline bench-chart dist opm-build install live-check live-full live-openai soak shim e2e-envoy e2e-forward-auth

test:
	busted

lint:
	luacheck core rules $$(ls -d adapters bench 2>/dev/null)

# Every core file must at least compile under LuaJIT (the OpenResty runtime).
luajit-check:
	@for f in $$(find core rules -name '*.lua' -not -path '*/spec/*'); do \
	  luajit -bl $$f >/dev/null || exit 1; done; echo "luajit ok"

check: lint luajit-check test

# Integration tests run in the official OpenResty image (needs Docker).
# --init matters: without a reaper Test::Nginx waits on zombie masters.
test-openresty:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$$(PWD)":/work jev-edge-test

bench-offline:
	lua bench/offline.lua

bench:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	docker run --rm --init -v "$$(PWD)":/work jev-edge-test sh /work/bench/run.sh

# Redraw docs/bench-latency-*.svg from a results.txt (default: the 4-connection run).
bench-chart:
	lua bench/chart.lua $${RESULTS:-bench/out-c4/results.txt} docs

# One real round trip + 60-sample latency/agreement check against the provider.
# Needs TYPESAFE_API_KEY in .env (gitignored). Costs ~40k input tokens.
live-check:
	docker run --rm --env-file .env -v "$$(PWD)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/live.lua $${N:-60}'

# Every dataset sample through the live provider with both templates; writes
# bench/datasets/live-<model>[-ctx].json. ~340k input tokens bare, ~400k with
# JEV_DEPLOYMENT_CONTEXT set in the environment.
live-full:
	docker run --rm --env-file .env -e JEV_DEPLOYMENT_CONTEXT -v "$$(PWD)":/work jev-edge-test sh -c \
	  'resty --http-conf "lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; lua_ssl_verify_depth 5;" \
	   -I /work/adapters/openresty/lib -I /work /work/bench/live_full.lua'

# openai-compat provider against an Ollama container on the jev-net network:
#   docker network create jev-net; docker run -d --rm --name ollama --network jev-net ollama/ollama
#   docker exec ollama ollama pull qwen2.5:0.5b
live-openai:
	docker run --rm --network jev-net -v "$$(PWD)":/work jev-edge-test \
	  resty -I /work/adapters/openresty/lib -I /work /work/bench/live_openai.lua $${N:-20}

# 4 workers, tiny dicts, low caps, slow flaky mock: limits, drops, memory, crashes.
soak:
	docker run --rm --init -e DUR=$${DUR:-60s} -v "$$(PWD)":/work jev-edge-test sh /work/bench/soak.sh

# Envoy: gRPC shim build and the two-transport end-to-end (Docker Compose).
shim:
	cd adapters/envoy/grpc-shim && go vet ./... && go build -o jev-shim .

e2e-envoy:
	docker build -q -t jev-edge-test -f adapters/openresty/Dockerfile.test adapters/openresty
	sh adapters/envoy/e2e/run.sh

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
opm-build: dist
	cd $(DIST) && opm build

install: dist
	mkdir -p $(LUA_LIB_DIR)/jev $(LUA_LIB_DIR)/resty
	cp -R $(DIST)/lib/jev $(LUA_LIB_DIR)/
	cp -R $(DIST)/lib/resty/jev $(LUA_LIB_DIR)/resty/
	@test -f $(PREFIX_CONF)/jev-edge.conf.lua || cp $(DIST)/conf/jev-edge.conf.lua $(PREFIX_CONF)/jev-edge.conf.lua
	@echo "installed to $(LUA_LIB_DIR); config at $(PREFIX_CONF)/jev-edge.conf.lua"
