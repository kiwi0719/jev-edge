# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- L1 `always_suspect` patterns are PCRE, matched through an injected
  `ctx.re_find`, so one rule file serves every adapter. Missing matcher
  disables the prefilter with a single warning (fail-open).

### Added
- M1 core skeleton: `core/` (normalize, rules, judge, policy, breaker, verdict,
  defaults, init) with 63 busted specs; bundled `injection` and `abuse`
  templates; `rules/llm-endpoints.lua` and `rules/default.lua`.
- Design document (`DESIGN.md`) covering the three-layer filter, provider
  abstraction, cache, breaker, header protocol, hot reload and bench plan.
- Repository scaffolding: license, lint config, changelog.
