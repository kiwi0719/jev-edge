.PHONY: test lint check luajit-check test-openresty bench bench-offline

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
