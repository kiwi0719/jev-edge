# Contributing

## Ground rules

- `core/` never requires `ngx`. All IO goes through the `ctx` table. luacheck enforces an empty globals list there.
- Any change to L1 rules, normalization, thresholds or timeouts must come with bench numbers (see [Bench data](#bench-data)), or at least a note on why they cannot. The [design decisions](docs/design.md#decisions) are settled unless a PR argues otherwise with those numbers.
- `core/golden/*.json` is the definition of core behaviour. A change that alters it regenerates the vectors (`make golden`) in the same PR and updates the TypeScript core in `adapters/js` so `make test-js` is green too; `make check` fails on drift. See [core/golden/README.md](core/golden/README.md).
- Fail-open is not negotiable. A PR that can make legitimate traffic wait on or be blocked by a Jev outage will not be merged.
- Never log or commit request bodies from real traffic. Bench datasets under `bench/datasets/private/` are gitignored for this reason.

## Workflow

1. Open an issue or pick one labelled `good first issue` / `help wanted`.
2. Branch from `main`. Keep PRs to one milestone item.
3. Run the core specs and lint locally (needs `luarocks install busted dkjson lrexlib-pcre2 luacheck`, plus `luajit` on PATH):

   ```bash
   make check
   ```

   On macOS, Homebrew's `luacheck` is built against Lua 5.5 and crashes on
   start (`attempt to assign to const variable`). Install one for LuaJIT
   instead, which is the runtime the code targets anyway, and point the
   Makefile at it:

   ```bash
   luarocks --lua-version 5.1 --lua-dir="$(brew --prefix luajit)" --local install luacheck
   make lint LUACHECK=~/.luarocks/bin/luacheck
   ```

4. Run the OpenResty integration suite. It runs in the official OpenResty image, so it needs Docker and nothing else:

   ```bash
   make test-openresty
   ```

   Without Docker, `cd adapters/openresty && prove -r t/` works on a box with OpenResty, Test::Nginx and lua-resty-http installed.

   For a change that touches core, also run the TypeScript side (needs pnpm):

   ```bash
   make test-js
   ```

5. Add a line to `CHANGELOG.md` under Unreleased.

## Bench data

Neither bench needs an API key. Run both before and after your change and paste the lines that moved into the PR.

```bash
make bench-offline
```

Replays recorded Jev probabilities for the deepset dataset through L1 and the policy thresholds and prints AUC, false-positive and miss rates per threshold. This is the one to run for rule, normalization and threshold changes.

```bash
make bench
```

Drives OpenResty in Docker with the `mock` provider through five scenarios (baseline, unwatched path, healthy / slow / dead Jev) and writes p50 / p99 per scenario to `bench/out/results.txt`. This is the one to run for anything on the request path: cache, breaker, adaptive timeout, header handling. `make soak` is the same image with four workers, tiny dicts and a flaky mock (`DUR=` sets the length, default 60 s); use it for changes to shared-dict usage or the L3 timer.

For a change to the provider call itself, put `TYPESAFE_API_KEY=...` in a gitignored `.env` and run `make live-check`: one real round trip plus a 60-sample latency and agreement check, about 40k input tokens. `make live-full` re-runs the whole dataset (about 400k input tokens) and is only needed when a template changes.

`make calibrate LOG=<jev log> LABELS=<labels>` is the same threshold tool operators use; for a rules or threshold PR against real traffic, its before / after recommendation is the most convincing number you can paste.

What the numbers mean and where the current ones stand is in [bench/report.md](bench/report.md) and [docs/design.md](docs/design.md#bench-and-acceptance).

## Labels

| Label | Meaning |
|---|---|
| `bug` | behaviour differs from [docs/design.md](docs/design.md) |
| `false-positive` | legitimate traffic judged suspicious / blocked |
| `miss` | attack traffic judged safe |
| `fail-open` | anything touching outage behaviour; reviewed with extra care |
| `core` / `adapter:openresty` / `adapter:apisix` / `adapter:envoy` / `adapter:haproxy` / `adapter:forward-auth` / `adapter:litellm` / `adapter:js` | area |
| `bench` | datasets, methodology, numbers |
| `provider` | judgment backend integrations |
| `milestone:M1` … `milestone:M6` | roadmap tracking |
