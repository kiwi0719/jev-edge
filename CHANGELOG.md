# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Generic forward-auth endpoint `resty.jev.edge.forward_auth()` for Traefik
  ForwardAuth, Caddy `forward_auth` and nginx `auth_request`. Original
  method/URI from `X-Forwarded-*` or `X-Original-*`, client IP from
  `X-Forwarded-For`; body judged when forwarded (Traefik ≥ 3.3
  `forwardBody`), otherwise `skipped` with reason `no body`. Reference
  configs in `adapters/forward-auth/`, Docker Compose e2e against real
  Traefik, Caddy and nginx (`make e2e-forward-auth`, CI job), Test::Nginx
  `05-forward-auth.t` including real `auth_request` wiring.
- Envoy support. `resty.jev.edge.authz()` serves HTTP `ext_authz` at
  `/_jev/authz/`: same evaluation as `access()`, 200 + `X-Jev-*` headers or
  403 + block body, client IP from `x-envoy-external-address` /
  `x-forwarded-for`, adapter errors answer 200 + `X-Jev-Verdict: error`.
- `adapters/envoy/grpc-shim`: Go implementation of
  `envoy.service.auth.v3.Authorization/Check` that forwards to `/_jev/authz`
  and fails open on adapter errors.
- `adapters/envoy/envoy-http.yaml`, `envoy-grpc.yaml` reference configs;
  `adapters/envoy/e2e` Docker Compose end-to-end against real Envoy
  (`make e2e-envoy`, also a CI job): 12 checks across both transports.
- Test::Nginx `04-authz.t`.

### Changed
- L1 checks IP reputation right after the path match, before method,
  content-type and body gates, so headers-only forward-auth requests from a
  blocked IP are denied. A watched request without a body now passes with
  reason `no body`.

## [0.1.1] - 2026-09-22

### Added
- `/_jev/health`: one real provider round trip reporting latency, effective
  timeout, breaker state and mode. `bench/live.lua` + `make live-check` run
  connectivity, a 60-sample latency distribution and agreement with the
  recorded jev-sec-bench probabilities.
- Adaptive L2 timeout (`resty.jev.adaptive`): `timeout_headroom × (mean + 2 sd)`
  of observed latency clamped to `[timeout_ms, timeout_max_ms]`, shared across
  workers, censored samples on timeout. `jev_l2_timeout_ms` gauge.

### Changed
- Default `policy.block_threshold` 0.85 → 0.70. With a deployment context
  on deepset/prompt-injections: 0% FP and 13% miss, against 0% / 28% at 0.85.
- `async.rep_block_after` defaults to 0 (reputation is recorded and alerted,
  never blocked, until enabled). A NAT address can hide thousands of users.
- `max_inflight` now applies to every provider, mock included.
- Example `log_format` uses `escape=none`; `escape=json` double-escaped the
  JSON in `$jev_log`.
- Default L2 timeout: fixed 300 ms → adaptive 400–1000 ms. Live measurement
  against `jev-latest` showed p95 314 ms; 300 ms would have dropped 15% of calls.
- HTTP timeout budget split 30/10/60 (connect/send/read) instead of a fixed
  50 ms connect, which could not complete a TLS handshake to the API.
- Example nginx.conf sets `lua_ssl_trusted_certificate`; without it every
  provider call fails certificate verification.

### Fixed
- Chunked request bodies (no Content-Length) bypassed `max_body_bytes` and
  were read whole; reads are now bounded to `max_body_bytes + 1`.
- `jev` provider verified against the live TypeSafe API (auth, request shape,
  response parsing).

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
