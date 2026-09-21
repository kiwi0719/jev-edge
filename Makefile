.PHONY: test lint check luajit-check

test:
	busted

lint:
	luacheck core rules $$(ls -d adapters bench 2>/dev/null)

# Every core file must at least compile under LuaJIT (the OpenResty runtime).
luajit-check:
	@for f in $$(find core rules -name '*.lua' -not -path '*/spec/*'); do \
	  luajit -bl $$f >/dev/null || exit 1; done; echo "luajit ok"

check: lint luajit-check test
