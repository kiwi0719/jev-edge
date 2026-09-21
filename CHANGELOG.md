# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-22

First release. OpenResty adapter only.

Known gaps: the `jev` and `openai-compat` providers follow the published API
contracts but have not been run against the live services; the config-file
mtime reload has no integration test; the replay-cache bench target (80%)
is not met (74%) on synthetic variants.

### Changed
- `mock` provider emulates the HTTP hard timeout so slow-Jev scenarios trip
  the breaker like the real client would.
- `edge.access` no longer JSON-encodes config on every request to detect
  changes; it compares table identity (p50 on the unwatched path 153 → 111 µs
  under saturation).
- L1 `always_suspect` patterns are PCRE, matched through an injected
  `ctx.re_find`, so one rule file serves every adapter. Missing matcher
  disables the prefilter with a single warning (fail-open).

### Added
- Packaging: `dist.ini` for opm (`lua-resty-jev-edge`), `make dist`,
  `make install` (flattens core/ and rules/ under `lib/jev/`).
- Install section in the README.
- Bench (`bench/`): offline accuracy evaluation replaying jev-sec-bench's
  recorded Jev probabilities (deepset/prompt-injections) through L1 and the
  policy, replay-cache measurement, core latency microbench; Docker
  end-to-end latency bench with wrk over baseline / unwatched / healthy /
  slow / dead scenarios. `bench/report.md` holds the numbers.
- OpenResty adapter (`adapters/openresty`): `resty.jev.edge` with init /
  init_worker / access / log / config_api / metrics; providers `jev`
  (TypeSafe System One), `openai-compat` and `mock`; shared-dict cache,
  breaker wiring, L3 async timer with IP reputation, `/_jev/config`
  runtime override with validation, `/_jev/metrics` Prometheus text,
  config-file reload timer. 14 Test::Nginx blocks (61 assertions) run in
  the official OpenResty image via `make test-openresty`. File-mtime reload
  is not yet covered by a test.
- M1 core skeleton: `core/` (normalize, rules, judge, policy, breaker, verdict,
  defaults, init) with 68 busted specs; bundled `injection` and `abuse`
  templates; `rules/llm-endpoints.lua` and `rules/default.lua`.
- Design section in `README.md` covering the three-layer filter, provider
  abstraction, cache, breaker, header protocol, hot reload and bench plan.
- Repository scaffolding: license, lint config, changelog.
