# Contributing

## Ground rules

- `core/` never requires `ngx`. All IO goes through the `ctx` table. luacheck enforces an empty globals list there.
- Any change to L1 rules, normalization or thresholds must come with bench numbers (`bench/`), or at least a note on why they cannot.
- Fail-open is not negotiable. A PR that can make legitimate traffic wait on or be blocked by a Jev outage will not be merged.
- Never log or commit request bodies from real traffic. Bench datasets under `bench/datasets/private/` are gitignored for this reason.

## Workflow

1. Open an issue or pick one labelled `good first issue` / `help wanted`.
2. Branch from `main`. Keep PRs to one milestone item.
3. Run locally (needs `luarocks install busted dkjson lrexlib-pcre2 luacheck`, plus `luajit` on PATH):

   ```bash
   make check
   cd adapters/openresty && prove -r t/
   ```

4. Add a line to `CHANGELOG.md` under Unreleased.

## Labels

| Label | Meaning |
|---|---|
| `bug` | behaviour differs from the README design section |
| `false-positive` | legitimate traffic judged suspicious / blocked |
| `miss` | attack traffic judged safe |
| `fail-open` | anything touching outage behaviour; reviewed with extra care |
| `core` / `adapter:openresty` / `adapter:envoy` / `adapter:cloudflare` | area |
| `bench` | datasets, methodology, numbers |
| `provider` | judgment backend integrations |
| `milestone:M1` … `milestone:M6` | roadmap tracking |
