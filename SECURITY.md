# Security policy

## Supported versions

Only the latest minor release gets security fixes. Fixes land on `main` and
ship in the next patch release; there are no backports to older lines.

## Reporting a vulnerability

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/kiwi0719/jev-edge/security/advisories/new).
Do not open a public issue, pull request or discussion for it.

Include the version or commit, the adapter, a minimal config and the requests
that reproduce it. Never include real API keys or request bodies from real
traffic.

You should get a first reply within 7 days. Once a fix is ready it is released,
the advisory is published, and you are credited unless you ask not to be.

## What counts

A vulnerability is anything that lets a client get around the filter itself,
or turns the filter against the deployment:

- a request on a watched path that skips judgment entirely (header, body-size,
  encoding or path tricks), or reuses another request's cached verdict
- forged identity or `X-Jev-*` headers that the gateway configs pass upstream
  as trusted
- `X-Forwarded-For` or subject handling that lets one client act as, or
  exhaust the budget of, another
- a request that crashes a worker, wedges the L3 timer or exhausts a shared
  dict
- API keys, request bodies or other secrets written to logs or headers
- anything that breaks fail-open: a Jev outage or slow response that blocks or
  stalls legitimate traffic

What does not count: a single prompt that is judged safe (label `miss`) or a
legitimate one that is judged suspicious (label `false-positive`). Those are
tuning problems; open a public issue with the text and the `$jev_log` line. A
general technique that defeats L1 normalization for a whole class of inputs is
in scope; report that privately.
