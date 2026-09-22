# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `scripts/invariants.lua` (`make invariants`, part of `make check` and CI):
  tripwires for the bug classes the 0.4.0 audit found (one version
  everywhere, every module in the rockspec, headers read without the 100
  limit, cache keys only through `core.cache_key`, SHA-256 fingerprints,
  X-Forwarded-For read from the right, upstream URLs that keep their host,
  gateway configs that drop forged identity headers, `$(CURDIR)` in the
  Makefile, the same rule set in Lua and TypeScript). Run against v0.3.1 it
  reports 25 problems.
- `security` workflow: CodeQL (TypeScript, Go, Python, workflows),
  govulncheck on both Go binaries (blocks when a released fix exists) and
  `pnpm audit`. Dependabot for actions, npm, Go modules and Dockerfiles.
- `SECURITY.md` (private reports through GitHub advisories, and what counts
  as a vulnerability for a filter), `CODE_OF_CONDUCT.md` (Contributor
  Covenant 2.1) and a pull request template with the CONTRIBUTING checklist.

### Changed
- CI: core specs on Lua 5.1, 5.4, 5.5 and OpenResty's LuaJIT (plus the LuaJIT
  bytecode check); the Test::Nginx suite and the four e2e jobs share one
  image built from `Dockerfile.test` with a layer cache; e2e is one matrix
  job; the HAProxy agent's Go tests run (with `-race`, as the shim's do),
  `gofmt` is enforced, Go is the latest 1.26 patch; `pnpm build` runs;
  LiteLLM gets `ruff` (pyflakes, bugbear); docs-only changes skip CI; a
  newer push cancels a PR's running CI; the token is read-only; a weekly
  run catches upstream gateway images that moved.

### Fixed
- The feedback endpoint and the mock provider read request headers without
  the 100-header limit, like the rest of the adapter.
- HAProxy SPOA image built with Go 1.26 (was 1.23, out of support, with
  standard-library advisories open) on Alpine 3.22.
- JS dev dependencies: vitest 4 and vite 7 (vitest 2 and its vite had a
  critical and a high advisory; dev only, nothing shipped in the package).

## [0.4.0] - 2026-09-23

L1 now reads a watched request the way the backend will, and reports the
requests it still cannot read instead of passing them as "no text". Plus the
fixes from a full audit of 0.3.1. Four changes alter what an existing
deployment sees; read **Changed** before upgrading.

### Changed
- **`max_body_bytes` is 1 MiB (was 64 KB)**, nginx's default
  `client_max_body_size`. Bodies up to it are parsed whole. Past it the body is
  no longer passed as "body too large": its first `max_body_bytes` and last
  64 KiB are scanned for the text fields' string values (truncated JSON
  included) and judged, with ` (window)` at the end of the reason. Where to
  raise it (rule, nginx, Envoy, HAProxy, Traefik, APISIX, JS) is in README
  "Body size and what L1 reads"; every limit on the path has to agree.
- **Content-Type is a hint, not a gate.** `llm-endpoints` lists
  `skip_content_types` (media: `image/`, `audio/`, `video/`, `font/`, PDF,
  zip, gzip) instead of an allow list, and the body decides the format: JSON
  when it parses as JSON whatever the header (Ollama and FastAPI read it that
  way; `text/json`, none, `application/octet-stream` were "not watched"),
  forms and `multipart/form-data` fields (text file parts too), other text
  whole. A rule that lists `content_types` keeps the allow list.
- **Text over `max_judge_bytes` (new, 32 KiB) is judged on a window**: the
  `always_suspect` hit (all of the text is scanned for it) with 1 KiB either
  side, then values newest first. The fingerprint and L2 see the window; so
  does L3 (`rules.judged_text`). `ctx.re_find` should return the match's byte
  span (`from, to`, as `ngx.re.find` does) so the hit lands in the window.
- **Verdict-cache keys** are `fp:<scope>:<fingerprint>` (see Security); the
  cache refills after the upgrade. Subject history in the JS runtime moves to
  ring keys, so earlier KV history is not read again.

### Added
- **`Content-Encoding` gzip, deflate and br are decoded** before L1
  (`resty.jev.decode` through FFI to zlib and libbrotlidec; `DecompressionStream`
  and `node:zlib` in JS), capped at `max_body_bytes` so a small compressed body
  cannot expand into memory. Express's body-parser inflates request bodies by
  default, so a compressed prompt used to reach the app unjudged. `br` needs
  `brotli-libs` (Alpine) or `libbrotli1` (Debian) on OpenResty images.
- **`policy.unjudgeable = "pass" | "block"`** (default `pass`) for a watched
  request L1 cannot read: an encoding it cannot decode, a binary body, or an
  oversized body with no text in its head or tail. It is passed as
  `X-Jev-Verdict: skipped` with `X-Jev-Reason: unjudgeable: <why>`, or
  rejected in enforce mode with `block`. Metrics: `jev_unjudged_total{reason}`,
  `jev_window_total`.
- Gateways that hand over part of a body say so, and jev-edge scans it as a
  head: Envoy's `x-envoy-auth-partial-body` (example configs now allow 1 MiB
  and forward `content-encoding`), and the HAProxy SPOA agent's
  `X-Jev-Body-Partial` from HAProxy's declared body size (new `size` arg in
  `spoe.conf`).
- `nextMiddleware(request, event)` forwards Next's event, so `waitUntil` keeps
  the subject write alive.

### Security
- **A repeated `Content-Type` header no longer skips judging.** OpenResty and
  APISIX hand a repeated header to Lua as a list; L1 called `:lower()` on it,
  raised, and the adapter failed open with `X-Jev-Verdict: error`. The values
  are now joined (`rules.content_type`) and the content type is watched when
  any of them is.
- **The verdict cache is scoped to the prompt that produced the score.** The
  key was `fp:<fingerprint>`, so a SAFE judged under a lenient tenant rule,
  deployment context, provider or model (an APISIX route with
  `provider = "mock"`) was replayed on a strict one. The key is now
  `fp:<scope>:<fingerprint>` (`core.cache_key`), scope = rule id, templates,
  deployment context, provider and model. L3 writes the same key. Trust stays
  keyed by fingerprint alone. Cached verdicts from earlier versions are not
  read again; the cache refills.
- **A judge answer with no score is an error, not SAFE.** `{"answers":{}}` or
  only non-numeric values reduced to score 0, counted as a breaker success
  and was cached as SAFE for `fp_ttl`. It now takes the `on_error` path and
  writes nothing (L2 and L3). `judge.reduce` returns the count of numeric
  answers as a third value.
- **A UTF-8 BOM before a JSON body no longer hides the text.** cjson rejects
  it, extraction returned "no text" and L1 passed, while Python and Express
  backends skip the BOM and read the prompt.
- **The JS runtime fingerprints with SHA-256.** 0.3.1 said it did; it still
  passed `djb2`, so a few appended letters could land an attack on a cached
  SAFE fingerprint. `core.sha256Hex` (synchronous, same hex as
  `resty.sha256`) is now the runtime's hash.
- **Watch paths match the path the origin routes on.** `forward_auth` (from
  `X-Forwarded-Uri` / `X-Original-URI`) and the JS runtime now percent-decode
  the path and collapse duplicate slashes before the watch list, as nginx
  does for `$uri`; `/v1/%63hat/completions` and `//v1/chat/completions` were
  "path not watched" while the backend served `/v1/chat/completions`.
- **Cloudflare Workers forward to the configured upstream only.** The
  forwarding URL was `new URL(path, upstream)`, and a request path starting
  with `//` made that a different host (an open proxy, unjudged).
- **The LiteLLM guardrail keeps every text form core judges.** It kept only
  `type == "text"` parts and string `input` items, so Responses API input,
  `input_text` parts and Anthropic `tool_result` arrived empty or were
  skipped without a call; a `prompt` next to `messages` was ignored.

- **The client cannot pick the IP or path it is judged under.**
  `forward_auth` no longer reads `X-Envoy-External-Address` (only Envoy sets
  it; `authz` still does). The HAProxy SPOA agent, the Caddyfile and the
  nginx `auth_request` conf drop client copies of `X-Envoy-External-Address`
  and `X-Real-IP`, and the nginx sub-request sets `X-Forwarded-Uri` /
  `X-Forwarded-Method` itself: a client's `X-Forwarded-Uri: /healthz` made the
  request "path not watched" and skipped the reputation block. The JS runtime
  reads `X-Forwarded-For` from the right (`client_ip.trusted_hops`), trusts
  `cf-connecting-ip` only on Cloudflare (or a configured `clientIpHeader`),
  and the Node middleware appends the socket address like any proxy. The
  LiteLLM guardrail forwards the whole `X-Forwarded-For` chain, not its
  client-written first entry.
- **More than 100 request headers no longer hide `Content-Type`.** OpenResty
  and APISIX read all headers (`ngx.req.get_headers(0)`); past the default
  100 the rest were dropped and L1 passed "content-type not watched".
- **A JSON `null` in `messages` or in content parts no longer ends the list.**
  The JS port stopped there (it followed the test decoder, which leaves a
  hole, not cjson, which keeps `null` as a value); the Lua specs now decode
  bodies the way cjson does.
- **The Node middleware judges the body the app will read.** A form parsed by
  `express.urlencoded()` was re-encoded as JSON and yielded no text; Express
  4's `json()` placeholder `{}` for a body it did not parse was judged instead
  of the stream; and a stream that had fully arrived but was not yet read
  (`req.complete`) was taken for consumed, so the request was not judged.

- **LiteLLM guardrail: the whole `X-Forwarded-For` chain wins over
  `requester_ip_address`**, which LiteLLM may itself take from the
  client-written first entry (`use_x_forwarded_for`).

### Fixed
- JS subject history is a ring (one atomic counter, one key per entry), as
  on OpenResty: concurrent requests no longer lose entries. Atomic on the
  memory store and the Durable Object; best effort on KV. Stores without
  `incr` keep the list layout.
- APISIX picks the rule for L3 and sampling by path, method and content type
  (`rules.rule_for`), like the OpenResty adapter; it used path alone.
- APISIX keeps breaker, adaptive timeout and in-flight counters per provider,
  endpoint and model instead of one set for every route, and skips L3 while
  the breaker is not closed.
- `jev_tokens_total` is recorded: the usage callback was called with an
  extra argument and dropped every sample.
- Subject trajectories: the ring counter's ttl is extended on every append
  (it expired `history_ttl` after the subject's first request, however
  active), and each slot carries its sequence number so a read between
  another worker's `incr` and `set`, or after `max_entries` changed, skips
  the slot instead of returning a stale entry.
- The breaker's half-open probe is claimed with an atomic `add` where the
  store has one, so exactly one worker probes.
- `watch_paths` validation rejects capture errors (unbalanced parentheses,
  back-references to a missing or open capture), which lstrlib only raises
  once a request reaches them, silently failing that rule open.
- Whitespace-only text has a fingerprint, so it is cached like any other
  text instead of costing a judge call per request.
- nginx `auth_request`: a deny answers with a JSON body; the README says
  `block_status` must be 401 or 403 there (anything else becomes a 500).
- Traefik: `maxBodySize` removed from the example; past it Traefik denied
  with 401 instead of letting jev-edge pass the request as "body too large".
- Envoy gRPC shim: default timeout 1.5 s, below Envoy's 2 s, so a slow
  jev-edge still yields `X-Jev-Verdict: error` instead of a silent pass.
- Makefile: Docker targets mount `$(CURDIR)`; `$$(PWD)` only worked on
  case-insensitive filesystems.

## [0.3.1] - 2026-09-22

Patch release from a full audit of 0.3.0. Everything below is a fix; there is
no new feature and no config key was removed. Two entries change observable
values: fingerprints and subject ids are different strings than in 0.3.0
(caches simply refill), and `X-Forwarded-For` is read from the other end.

### Security
- **Content-parts bodies are judged.** `messages[*].content` in the array
  form every current chat API accepts (`[{type="text", text=...}, ...]`,
  Responses API `input_text`, Anthropic `tool_result` with nested `content`)
  used to extract no text, so the request passed L1 as "no text" in every
  mode. `normalize.extract` now collects strings, each part's `text` and
  nested `content`, on every adapter (golden vectors added).
- **Fingerprint is SHA-256 over the whole normalized text.** 0.3.0 hashed a
  2048-byte prefix with `crc32_long` (djb2 in the JS runtime). Either let a
  chosen text reuse another text's cached or operator-trusted verdict: any
  suffix behind a shared prefix, or a few appended bytes to hit a chosen
  32-bit value. `fp_prefix_bytes` now only bounds sampled and logged text.
- **Client IP behind a proxy is the appended hop, not the first element.**
  `authz` and `forward_auth` took the leftmost `X-Forwarded-For` value, which
  the client writes, so reputation blocks could be aimed at any address and
  evaded by rotating the header. They now take element `client_ip.trusted_hops`
  from the right (default 1, the value the proxy in front appended);
  `x-envoy-external-address` is used when Envoy sends it.
- **`GET /_jev/config` redacts `jev.api_key`, `feedback.token` and
  `subject.salt`**, in both the effective config and the override.
- **Admin endpoints on their own listener** in the example config, the demo
  (`127.0.0.1:8090`) and the recipes: a gateway that reaches `/_jev/authz` on
  the traffic port could reach `/_jev/config` through `..` path tricks.
  The Envoy configs turn on `normalize_path` / `merge_slashes`, HAProxy and
  the gRPC shim / SPOE agent refuse `..`, `%2e` and `//` (fail-open).
- **Inbound `X-Jev-*` headers are stripped** by the Envoy, Caddy, Traefik and
  nginx auth_request reference configs too, so a forged `X-Jev-Verdict: safe`
  cannot reach the upstream on the fail-open path. `X-Jev-Subject` is
  stripped as well unless it is the configured subject header.
- **Subject values with `hashed = true` must look like an id we computed**
  (`<from>:<hex>`), and raw subject values over 512 bytes are dropped.
- Subject ids use SHA-256 on every adapter (OpenResty and APISIX used SHA-1).

### Fixed
- Core: the breaker re-tripped on the first success after a probe closed it,
  because the window that tripped it was still counted; the window is reset
  on close. A suspicious cache hit no longer sets `async`, so a repeated
  suspicious prompt is one L3 call, not one per hit. `body_size` is the
  larger of the declared size and the body handed over. `rules.resolve` on a
  string spec returns a copy with defaults applied instead of the shared
  module table, and rejects malformed `watch_paths` patterns (a bad pattern
  used to raise on every request and fail everything open). `encode_reason`
  truncates after encoding, never inside a `%XX` escape, so the header is
  really <= 200 bytes. `defaults.validate` rejects thresholds outside
  [0,1], non-HTTP `block_status`, zero breaker windows, zero
  `sampling.max_samples` and other values that made a gate degenerate.
  Text that normalizes to nothing (digit runs, UUIDs) is fingerprinted as
  typed instead of being judged on every request.
- OpenResty: L3 builds the same prompt L2 did (deployment context, the rule
  that actually matched on path, method and content type), gets the ceiling
  timeout instead of the adaptive estimate that just failed, is not started
  while the breaker is open, and its timeouts no longer feed the adaptive
  estimate. In-flight counters (`inflight:l2`, `inflight:l3`) are released on
  every exit including premature timers at reload and Lua errors, and never
  go negative after an eviction. `openai-compat` no longer stores its
  question set on the shared config table (concurrent requests with
  different templates got each other's filter). `PUT /_jev/config` and
  `POST /_jev/feedback` read bodies nginx spooled to disk. A broken rule in an
  override is a 422, not a log line. `/_jev/health` with a misconfigured
  provider is a 503 JSON body, not a traceback. `X-Forwarded-Uri` is
  normalised (`//`, `.`, `..`) before matching `watch_paths`. `resty.jev.cache`
  warns once when a dict starts evicting. The `+json` content types the
  extractor already decoded are now watched by `llm-endpoints`.
- Subject trajectories on OpenResty and APISIX are stored as a ring (one
  atomic counter plus one key per entry) instead of one list per subject:
  the old append was a read-modify-write in a per-request timer, so two
  workers recording the same subject lost entries and a burst could exhaust
  `lua_max_pending_timers`. Existing `subj:` list keys are simply ignored.
- New optional `lua_shared_dict jev_state`: trust grants, breaker state,
  in-flight counters and the adaptive estimate move there when it is
  declared, so a flood of new prompts filling `jev_cache` cannot evict them.
  Without it everything stays in `jev_cache` as before.
- JavaScript: fail-open now covers the whole request path (body read,
  subject store, `onVerdict`, block response), not only the core call; the
  provider timeout covers the response body, not just the headers; Lua
  pattern conversion no longer corrupts `-` inside `[...]`; byte truncation
  stops at a UTF-8 boundary; bodies without `Content-Length` are bounded;
  `nodeMiddleware` no longer hands the app a placeholder body; `cf-ray` is
  only trusted on Cloudflare; Hono and Lambda@Edge presets strip inbound
  `X-Jev-*` and honour `block_status`; `engines` is `node >= 20` and `@types/node` follows the Node 20 line.
- Envoy gRPC shim: a response without `X-Jev-Verdict` (404, 5xx, a sidecar
  error) is fail-open, as documented, instead of a deny; fail-open overwrites
  forged headers. HAProxy SPOE agent and LiteLLM guardrail: block is
  `status >= 400` with `X-Jev-Verdict`, so a non-403 `block_status` blocks
  instead of failing open; the agent timeout is below HAProxy's `timeout
  processing` so the fail-open answer can arrive; `Expect` and hop-by-hop
  headers are not forwarded. LiteLLM percent-decodes the reason. APISIX
  reports chunked bodies over the cap as "body too large", not "no body".
- Docs: thin-adapter contract written down once in `docs/recipes.md`; stale
  test counts, the misplaced version note in `docs/design.md`, and the
  Makefile comment; `.gitignore` covers default `go build` outputs.

## [0.3.0] - 2026-09-22

### Added
- Subject extraction and storage behind the trajectory contract: `subject =
  { enabled, from = ip|header|cookie, name, salt, hashed, history_ttl,
  max_entries }` on OpenResty, APISIX and the JavaScript hosts. The raw value
  is hashed with the per-deployment `salt` (SHA-1 / SHA-256) before storage
  or logging; the config is rejected without one. Trajectories live in their
  own bounded store (`lua_shared_dict jev_subject`, `subjectStore`) so a
  flood of subjects evicts trajectories, never verdicts or trust. The thin
  Worker forwards its hashed id as `X-Jev-Subject` (`hashed = true` at the
  origin). `$jev_log` carries `subject`. Test::Nginx `08-subject.t`.

### Added
- False-positive feedback loop (`core/trust.lua`,
  `adapters/js/src/core/trust.ts`, `POST /_jev/feedback`, `make labels`): an
  operator marks a blocked request "not an attack" and every later request
  with that exact text passes at L1.5 — before the verdict cache, so it beats
  a stale malicious score — without an L2 call. `feedback = { enabled = true,
  token = ... }` turns it on; the token is required, because the endpoint
  writes bypasses. `label = "attack"` revokes, so undoing a mislabel costs
  what making one did.

  Three decisions are part of the design, not configuration defaults to be
  shrugged at:

  **Trust expires.** `trust_ttl` is seven days, and traffic on the same
  fingerprint extends it at most `max_renewals` (4) times — about five weeks,
  after which the false positive deliberately comes back. A fingerprint is
  derived from attacker-visible text, so a permanent entry would be a standing
  bypass nobody reviews again; a template still tripping the judge after five
  weeks is a rule or `deployment_context` bug, and the alert is the point.
  Renewals are bounded, so a fingerprint costs at most `max_renewals` writes
  ever, and only past half its life.

  **Trust is local to the gateway.** It lives in the existing shared dict: no
  new component to run or make highly available, and no partition that fails
  the loop open across a fleet. Other gateways converge as they see the same
  text. Core reads and writes it through `ctx.trust`, which defaults to
  `ctx.cache`, so moving trust to a shared store is an adapter change rather
  than a core one — deliberately not the default path.

  **The labels file is derived, never written.** The worker appends to no
  file: no hot-path write, no multi-worker race, nothing lost with the
  container. Each report is one line in the jev access log (`src="feedback"`,
  with `fp`, `label`, `by`, `rid`), which is already collected, rotated and
  auditable, and correctable by reporting again. `make labels LOG=... OUT=...`
  (`bench/labels-from-log.lua`) replays those lines, last report per
  fingerprint winning, into the labels file `make calibrate` reads.

  Six golden vectors pin the behaviour across both cores (trusted pass, trust
  over a cached malicious score, expiry, disabled, renewal, renewal cap);
  `core/spec/trust_spec.lua` and `adapters/openresty/t/07-feedback.t` cover
  the module and the endpoint end to end.
- Subject trajectory contract (`core/subject.lua`, `adapters/js/src/core/subject.ts`):
  `evaluate` accepts an optional `ctx.subject = { id, history, record }` and
  hands one flat trajectory entry to `record` on every exit that made a
  decision (not the L1 pass path). The entry carries the raw score, not only
  the label, so it can be replayed later as calibration input.

  **This version records; it does not decide.** `history` is accepted and
  ignored, and both golden vectors and `core/spec/subject_spec.lua` assert
  that a request with a subject and a non-empty history gets the same verdict,
  field for field, as one without. Scoring a subject over time needs a window
  length, a decay factor and a threshold, and there is no traffic yet to
  calibrate any of them; a guess shipped as a default would be worse than the
  absent feature. The shape is frozen now so that turning recording into
  deciding is an implementation change in two files rather than a contract
  change in every adapter and vector.

  The read/write split is part of the contract: `history` is one store lookup
  on the request path and may always be absent (cold subject, evicted entry,
  a store that lost it — never an error), while `record` is a sink the core
  hands a value to and never waits for. On nginx a shared dict satisfies that
  as is; on Workers it keeps a Durable Object hop a deployment choice rather
  than something the request path pays for.
- Golden vectors in `core/golden/`: 131 cases across six suites (normalize,
  extract, rules, policy, verdict, evaluate) generated from the Lua core by
  `core/golden/gen.lua`, replayed by `core/spec/golden_spec.lua`, and checked
  for drift by `make golden-check` in CI (`make check` includes it). They are
  the cross-implementation contract the Cloudflare TypeScript core will be
  held to; `core/golden/README.md` states what parity covers and what is left
  to each platform.
- `make calibrate LOG=<jev log> LABELS=<labels> [MAX_FP=]`
  (`bench/calibrate.lua`): score distribution, would-have-blocked table, AUC,
  false-positive and miss rates per threshold, and a recommended
  `block_threshold` / `suspect_threshold` under a false-positive budget, from a
  monitor-mode `$jev_log` file plus labels keyed by request id or fingerprint.
  `--json` for scripts. Install step 7 and a "Choosing thresholds" README
  section point to it.

- JavaScript adapter (`adapters/js`, npm package `@jev-edge/js`, first as Cloudflare only):
  a TypeScript port of core that replays the same golden vectors under vitest
  (116/116), plus `thinWorker` (L1 and cache at the edge, judgment by an
  existing jev-edge via `/_jev/authz`), `fullWorker` (KV cache, Durable Object
  `JevState` for breaker and adaptive timeout, `jev` / `openai-compat` /
  `mock` providers) and `pagesMiddleware`. `handle()` and `evaluate()` for
  other frameworks. Wrangler examples, README with the parity boundary, CI job.
- `make context-lint CONF=<conf.lua> | TEXT=<context>` (`bench/context_lint.lua`):
  checks a deployment context for length, generic phrasing, a refusal list, an
  audience, "be safe" instructions and proper nouns; FAIL on missing or
  generic, WARN otherwise, `--json` for scripts.
- `make test-js`.
- Apache APISIX plugin (`adapters/apisix`): same engine, per-route config with
  the config-file keys, `$jev_log` as an APISIX variable; e2e against real
  APISIX 3.13 (`make e2e-apisix`, CI job).
- HAProxy SPOE agent (`adapters/haproxy/spoa`, Go) with `spoe.conf` and a
  reference `haproxy.cfg`; forwards the original headers and body to
  `/_jev/authz`, sets `txn.jev.*`, fails open; e2e against real HAProxy 3.1
  (`make e2e-haproxy`, CI job).
- LiteLLM proxy guardrail (`adapters/litellm/jev_edge_guardrail.py`):
  `async_pre_call_hook` that asks `/_jev/authz`, annotates
  `metadata.jev_verdict`, blocks with 403 in enforce mode, fails open;
  `make test-litellm`, CI job.
- `docs/recipes.md` (en, zh-CN): the `/_jev/authz` contract and configuration
  for Istio, Envoy Gateway, Azure API Management and Apigee.
- `@jev-edge/js` (renamed from `@jev-edge/cloudflare`, directory
  `adapters/js`): `nextMiddleware`, `nodeMiddleware`, `honoMiddleware` and
  `lambdaEdgeHandler` on the shared runtime, with tests; Cloudflare presets
  unchanged under `./cloudflare`.

- Multi-tenant rules: `rules` entries may be inline tables with `extends`
  (`core/rules.lua` `resolve()`), each with its own `watch_paths` and
  `deployment_context`; first match wins. Supported in the config file and
  `PUT /_jev/config`, the APISIX plugin conf, and the JavaScript `rules`
  option. Test::Nginx `06-samples-tenants.t`.
- Decision sampling: `sampling` config section (`core/sampling.lua`,
  `adapters/js/src/sampling.ts`), `GET|DELETE /_jev/samples` on OpenResty,
  shared-dict ring on APISIX, `onSample` callback on the JavaScript hosts.
  Normalized text only, off by default.

### Changed
- README (en, zh-CN) restructured for first-time readers: Status table,
  "Try it in 30 seconds" on `demo/`, latency figures quoted with their
  measurement conditions, Contributing spells out the test and bench
  commands. Design moved to `docs/design.md`, the cost table to
  `docs/cost.md`. Architecture diagram no longer claims a fixed 300 ms cut.

## [0.2.0] - 2026-09-22

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
- License changed from MIT to Apache 2.0.
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
