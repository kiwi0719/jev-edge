<!-- One milestone item per PR. See CONTRIBUTING.md. -->

## What and why



Closes #

## Checklist

- [ ] `make check` is green (specs, lint, invariants, golden drift)
- [ ] `make test-openresty` is green, if the request path changed
- [ ] `make test-js` is green, if `core/` or `core/golden/*.json` changed
- [ ] Bench lines that moved are pasted below, if rules, normalization,
      thresholds, timeouts, cache or breaker changed (`make bench-offline` /
      `make bench`)
- [ ] Fail-open still holds: nothing here can make legitimate traffic wait on
      or be blocked by a Jev outage
- [ ] No real request bodies or API keys in code, fixtures or logs
- [ ] `CHANGELOG.md` has a line under Unreleased

## Bench

<!-- before / after, or why there are no numbers -->
