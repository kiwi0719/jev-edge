# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The fixes from a full audit of 0.6.1 (correctness, security and latent bugs in
core, the rule set, every adapter, CI, release and ops), each checked against
a reproduction before and after. L1 now reads what the backends read in many
more request shapes and on many more routes, judges tool-call arguments and
tool definitions, and reads a body it used to pass as "no text" or skip as
"not watched". A client can no longer open the breaker with text the judge
refuses, read the score off a block, or make a relay fail open with a path,
header or body it cannot forward. Several defaults and cache keys change, and
some configs that used to load are refused: read **Upgrade notes** first.

### Upgrade notes
- **Tool definitions are judged by default.** `llm-endpoints` gains
  `tool_fields` (`tools`, `functions`, `response_format.json_schema`,
  `text.format`): a request that carries tools makes one more judge call the
  first time a tool set is seen, and is a cache hit on the next turn. A rule
  that extends `llm-endpoints` turns it off with `tool_fields = {}`.
- **Cache and fingerprint keys change once.** The fingerprint keeps digit
  runs and UUIDs; the verdict-cache scope adds `jev.endpoint` and the question
  wording when either is set; chunks overlap by 1 KiB. Expect a cold verdict
  cache after the upgrade. A fingerprint an operator trusted through
  `/_jev/feedback` for a text with a digit run or a UUID must be reported
  again.
- **Subject ids from `Authorization` and `Proxy-Authorization` change once**
  (the auth scheme is canonicalised). Upgrade a thin Worker and its origin
  together.
- **The breaker counts 401, 404 and 405** (a bad key, endpoint or model), and
  no longer counts 400, 403, 413, 422 or a reply it cannot use: those are the
  client's text, not the provider's health. A misconfigured judge now opens
  the breaker and pages, where every call used to fail with it closed.
- **IP reputation blocks at L1 only under a config with
  `async.rep_block_after > 0`.** Kong and APISIX routes share `rep:<ip>`; a
  route that keeps the default 0 no longer blocks the IPs a stricter route
  flagged.
- **A block response tells the client `X-Jev-Verdict` and
  `X-Jev-Request-Id` only**: Kong, APISIX, every JS host, the forward-auth
  denial, the gRPC shim's deny and the LiteLLM guardrail's exception. A
  client or test that read `X-Jev-Score`, `X-Jev-Reason` or `X-Jev-Source`
  off a 403 must read the log, the upstream headers or `onVerdict`.
- **Configs that were silently wrong are refused**: `policy.block_status`
  outside 400-499, a non-string `policy.block_body` or judge setting, JSON
  `null` in an override, a rule field of the wrong type (a string where a list
  goes, a map for `watch_paths`, a limit that is not a number), an unknown
  template in a rule or in `untrusted.templates`, a malformed
  `untrusted.fields` path, and a rule `extends` that is not a rule set id.
  `methods` may now be a list (`["POST"]`). A refused file keeps the previous
  config, as before, and is now reported (`config_error`, 503 from
  `/_jev/health`).
- **New shared dict `jev_subject_rep`** for subject reputation, apart from
  the trajectories in `jev_subject`: declare it where you declare
  `jev_subject` (`example.nginx.conf`, Kong's `nginx_http_lua_shared_dict`,
  APISIX's `custom_lua_shared_dict`). Without it reputation shares
  `jev_subject`, with one warning per worker.
- **APISIX**: declare jev-edge's dicts under
  `nginx_config.http.custom_lua_shared_dict`; APISIX 3.13 drops them from
  `lua_shared_dict`, which left the plugin without a cache, breaker or
  reputation. The plugin's priority is 1000 (was 2450), it declares
  `run_policy = "prefer_route"`, and `check_schema` refuses a missing or
  broken rule set, so such a route is not loaded.
- **Kong hybrid mode**: this release adds plugin schema fields
  (`questions_json`, `ssl_verify`, `subject.reputation`, `max_tokens`,
  `token_param`, `temperature`, `extra_body_json`, provider `laya`). Upgrade
  the control plane first and every data plane right after; a data plane on
  an older version refuses every config push that uses a new field.
- **HAProxy**: `jev-spoa` listens on `127.0.0.1:9000` by default (pass
  `-listen :9000` in a container). Ship the new `spoe.conf` (it sends `uri`
  and at most 88 KiB of body) and `haproxy.cfg` (a `deny_status 400` line)
  with the new agent.
- **Envoy**: copy three changes from the reference configs:
  `path_with_escaped_slashes_action: REJECT_REQUEST`, `x-jev-body-partial`
  removed with the other `X-Jev-*` before ext_authz, and `envoy-http.yaml` no
  longer forwards `x-envoy-external-address` (`trusted_hops = 1` reads the
  hop `use_remote_address` appends).
- **LiteLLM guardrail**: it appends the peer LiteLLM saw to
  `X-Forwarded-For`, so behind N appending proxies set jev-edge's
  `trusted_hops` to N + 1 (one more than before). The `HTTPException` detail
  is `{error, request_id}`; the verdict is on `exc.jev_verdict` and in the
  proxy's metadata. Settings come from `JEV_EDGE_*` when no keyword is
  given, and it warns at startup without `default_on: true`.
- **JavaScript**: `/_jev/health` answers `{ ok, adapter, core }` unless
  `health: "details"`; `honoMiddleware` puts only `X-Jev-Request-Id` on the
  response; pass the Durable Object namespace (`env.JEV_STATE`) as `state`,
  not a stub kept across requests.
- **Laya**: the profile's L2 timeouts are 500 / 800 ms (were 100 / 300) and
  `max_inflight = 1`. laya-server's `LAYA_GATEWAY_TIMEOUT_MS` (default 500)
  replaces `LAYA_QUEUE_MS` and must equal the gateway's `timeout_ms`; run
  `make conformance` with `BUDGET_MS=500` and `CONCURRENCY=<max_inflight
  summed over gateways>`.

### Security

What L1 reads:
- **Watch paths match the path the backend routes on.** `;` segment
  parameters are dropped, empty and `.` segments removed, `..` resolved and
  ASCII case folded, in the path and the pattern alike, on every call site
  and both cores (`paths_case_sensitive = true` keeps the case). Express,
  Spring and Tomcat routed `/V1/Chat/Completions` or `/v1;a=b/chat/completions`
  to the chat handler while L1 said "path not watched". Kong matches the
  decoded `ngx.var.uri` (`/v1%2Fchat/completions` was skipped), and the TS
  core matches bytes, `.` across line terminators, as Lua does.
- **The generation routes and prompt fields LLM servers accept are
  watched.** Ollama `/api/generate`; LiteLLM and llama.cpp without `/v1`
  (`/chat/completions`, `/completions`, `/responses`, `/completion`,
  `/infill`); `/engines/<m>/`, Azure `/openai/deployments/<name>/` and
  `/openai/v1/`; `/v1/responses` and `/v1/messages`; the AI SDK's
  `/api/completion`; Gemini `generateContent` and `streamGenerateContent`
  (the Gemini API, Vertex AI, LiteLLM's `/models/<m>:...`) and
  `/v1beta/openai/chat/completions`; SGLang, TGI and vLLM native routes
  (`/generate`, `/generate_stream`, `/vertex`, `/invocations`, and TGI's `/`
  for a JSON body only, through the new `json_only_paths`); Open WebUI's
  `/api/v1/...`, `/ollama/...` and `/openai/...`; LM Studio's `/api/v0/...`
  and `/api/v1/chat`; Cohere `/v2/chat` and `/v1/generate`. New text fields:
  `system`, `instructions`, `preamble`, `system_prompt`, Gemini
  `systemInstruction`, `contents[*].parts` and function responses, Cohere
  `chat_history` and `documents`, AI SDK 5 `messages[*].parts` (tool parts'
  input and output), llama.cpp's `prompt_string`, `input_prefix`,
  `input_suffix` and `input_extra` (filename and text), Responses
  `prompt.variables`, TGI `inputs` and `instances`, and `suffix`.
- **A media Content-Type is a hint.** A body under `image/png` (or another
  `skip_content_types` type) is read like any other: JSON or text under it is
  judged, and only a binary body passes as "content-type not watched".
  Ollama, llama.cpp and FastAPI parse the JSON whatever the header says.
- **JSON the decoder refuses is scanned, never passed as "no text".** cjson
  refuses a lone surrogate escape, nesting past 1000 and bytes after the
  value; Python, Node and Go read all three. Such a body, declared JSON or
  one that starts with `{` or `[` under any type, has its text fields, tool
  definitions and object arguments read by the scanner; under `text/plain`
  or no type the whole body is judged too. With nothing to scan, declared
  JSON is `unjudgeable: invalid json`.
- **JSON keys match without regard to case**, plus U+017F and U+212A, as Go's
  `encoding/json` (Ollama) matches them: `{"MESSAGES":[...]}` passed as "no
  text".
- **Tool-call arguments are judged with the text** (OpenAI, Ollama,
  Anthropic `tool_use`, Responses `function_call` and `mcp_call`, custom tool
  input, AI SDK tool parts): a `**` field path reads every key and string
  below it, a string of JSON decoded, in document order with its turn.
- **Tool definitions are judged as a part of their own**, with the rule's
  question and their own cache entry keyed by their text: every key and
  string of `tools`, `functions` and output schemas except JSON Schema type
  names, scanned whole by `always_suspect`, one window judged. A
  pre-registered false-positive bench over 30 real tool sets
  ([bench/tools](bench/tools/README.md)) found none at 0.5 with the
  `injection` question (highest 0.12); the `untrusted` question flagged 14 of
  30, so it is not used for them. Detection of poisoned tools was not
  measured: this is not a tool-poisoning defence.
- **More model-visible shapes are read**: Anthropic `document` blocks,
  Responses `file_search_call` results and every `*_call_output`, Cohere
  documents, Gemini function responses, a Bedrock Converse `toolResult`
  (its text and json blocks), a tool or function message whose content is
  an object, a Gemini `parts` object by its keys, and, as retrieved content
  with `untrusted` on, the same results. Converse `toolUse.input` and Gemini
  `functionCall.args` are read as tool-call arguments.
- **Multipart bodies are read as RFC 2046, Go and Starlette read them**: the
  delimiter only at a line start, every part read, the `boundary` parameter
  by name, a file only with a `filename` parameter. A file part typed
  `application/octet-stream` or with an empty type is read when it is text.
  More than 8 distinct boundaries is `unjudgeable: multipart boundaries`.
- **A prompt sent as token ids is unjudgeable** (`unjudgeable: token prompt`)
  instead of "no text"; beside text long enough to judge, the text is
  judged and the ids still count. A rule's new `token_prompts = "block"`
  refuses them in enforce mode without making every unjudgeable request
  block. SGLang's `input_ids` is a text field.
- **Past `max_body_bytes`, nothing hides behind the cut.** Keys written with
  JSON escapes are read, a value the head or tail cuts is read whole, a body
  that fits in `max_body_bytes` + 64 KiB is scanned as one string, and an
  array under a `**` key is read whole with base64 data URLs left out (only
  under `image_url`, `url` or `file_data`, and only when base64 to the end).
- **A compressed body that inflates past `max_body_bytes` has its tail
  scanned**, reading on to 4 x the limit; past that it is `unjudgeable: body
  too large`.
- **A body the gateway cut is reported, not taken as whole.** `/_jev/authz`
  takes a body that reaches `max_body_bytes` as cut whatever the gateway
  says (`jev_authz_events_total{event="cut_at_cap"}`), and the new
  `policy.partial = "unjudgeable"` reports a cut body as `unjudgeable:
  partial body`. A client's own `X-Jev-Body-Partial` or
  `x-envoy-auth-partial-body` never reaches `/_jev/authz` from the SPOA, the
  gRPC shim or the reference Envoys.
- **The walk's bounds no longer starve what follows.** An object or array
  over the node budget (now 20,000) keeps its newest part and at most half
  of what is left; a request left with too little to judge is `unjudgeable:
  json over the walk bounds`, and a cut part says `(window)`.
- **Every `always_suspect` hit places the judging window**, not the first
  pattern's first match, so a harmless decoy no longer pushes the attack out;
  a hit that starts inside a character takes the whole character, in both
  cores alike.
  A matcher that fails (PCRE's JIT stack limit, a pattern that does not
  compile) counts as a hit, logged once. The shipped base64 pattern is one
  class run the JIT matches at any size. The TS core runs patterns as PCRE
  without UTF over bytes (`\s` ASCII, `.` one byte, non-ASCII literals as
  their bytes, `i` folding ASCII only), as `ngx.re` with `ijo` does, and
  translates the inline options `(?i)`, `(?s)`, `(?m)` and `(?x)` (and
  `(?-i)` where the engine has RegExp modifiers) instead of counting such a
  pattern as a hit on every text.
- **Chunks overlap by 1 KiB**, text within `max_judge_chunks` capacity is
  judged in full by bytes, and a hit no chunk holds whole is judged as a part
  of its own.
- **The fingerprint keeps digit runs and UUIDs**: "transfer 12345" reused
  the verdict of "transfer 99999".
- **The judge is sent well-formed text only**: ill-formed UTF-8 becomes
  U+FFFD in both cores, so a 0xFF byte cannot make a strict judge answer 400.
- **Linear time where a client chose the input**: form bodies (a 1 MiB body
  held a worker for an hour), a chunk cut over continuation bytes, and
  trimming Content-Type and subject values. The scanner reads strings in
  byte loops LuaJIT compiles: a crafted 1 MiB body costs about 65 ms of
  worker CPU in L1, an ordinary one about 15 ms.

Judging, breaker and cache:
- **Only a failing provider counts against the breaker.** A judge error
  carries its kind (transport, timeout, unavailable, rejected, unusable);
  transport, timeout and unavailable (5xx, 429, 401, 404, 405) count. About
  20 requests the judge refused (a content filter's 400, laya-server's 400
  for a 0xFF byte, a reply with no scores) opened the breaker for every
  tenant. A request that says nothing about the provider hands a half-open
  probe on (`breaker.release()`).
- **L3 judges the parts L2 judged** (chunks, retrieved content, tool
  definitions) and writes the whole request's cache entry only when every
  part answered: a text-only score could be served for text with tool
  definitions. L3 takes no L2 in-flight slot, and its outcomes are counted.
- **The verdict-cache scope names the judge endpoint and the question
  wording**, so routes or Workers sharing a store with different judges no
  longer replay each other's scores.
- **Text over `max_judge_chunks` is blocked under `unjudgeable = "block"`
  while the breaker is open**, instead of passing as "breaker open".
- **openai-compat**: echo detection compares the fallback answer keys the
  parser accepts (a planted `{"score": 0}` was read as the judge's answer),
  and the Lua and TS providers read the same JSON and compare answers to 6
  digits.
- **A typo in `untrusted.templates` is refused at load**, and a part whose
  prompt cannot be built is left out instead of failing every agent request
  open; the verdict's reason then ends in "(a part not judged)".
- **An in-flight slot a killed thread held comes back** after a lease;
  before, `max_inflight` such calls refused every L2 call for good.

Reputation and subjects:
- **Only the subject's own text charges reputation.** Tool definitions,
  retrieved content, and with `untrusted` on a text that holds retrieved
  content or a body that was scanned still decide the request but add no
  points: text planted in a page or a mailbox could get the users whose
  agents fetched it blocked. The same applies to L3's IP reputation.
- **Subject values cannot be respelled**: a cookie subject is every value
  the backend may read (duplicates, case variants, quoting) and any blocked
  one blocks; an `Authorization` subject is keyed on the credential, not its
  scheme's spelling; an IPv6 client is counted by its /64
  (`client_ip.ipv6_prefix`), for IP reputation and `subject.from = "ip"`.
- **Reputation blocks survive a flood of new subject values**: the
  trajectory store no longer evicts, and reputation lives in
  `jev_subject_rep`.
- **A salted subject value up to 64 KiB is hashed** (an RS256 bearer token
  left a request with no subject), and a dropped one is logged.
- **An IP reputation block lasts its whole `rep_block_ttl`**, not
  `cache.rep_ttl`.
- **A thin Worker's authz call and its forwarded request add a subject's
  points once**, not twice.
- **`/_jev/authz` never takes the relay's address for the client's** (no
  `X-Forwarded-For` in a mesh, or fewer hops than `trusted_hops`), and a
  client's `x-envoy-external-address` never reaches it through Envoy.

Verdict headers, relays and admin endpoints:
- **Block responses carry `X-Jev-Verdict` and `X-Jev-Request-Id` only**
  (`verdict.client_headers`): the score, reason and source were an oracle to
  walk a prompt under the threshold.
- **No client `X-Jev-*` header reaches the upstream, under any name**, on a
  pass or a fail-open, on every adapter; the configured subject header stays.
  `/_jev/authz` names the ones Envoy must remove.
- **Admin endpoints refuse `..`, `//` and encoded slashes** in the raw path,
  and the reference Envoys reject `%2F`: `..%2F` reached a co-located
  `/_jev/config` through `/_jev/authz/`.
- **`example.nginx.conf` has a gateway-only listener** for `/_jev/authz` and
  `/_jev/forward-auth`, and a thin Worker can send an origin token
  (`originToken`, `JEV_ORIGIN_TOKEN`).
- **Traefik's `forwardAuth` keeps `trustForwardHeader: false`**, and an
  invariant fails on any other value.

Gateways:
- **HAProxy**: every Content-Type value is forwarded (a second `image/png`
  skipped the request); the size contract keeps every accepted message in
  one SPOE frame; an answer nginx refused, an SPOE error or a missing answer
  is unjudgeable (`-unjudged=pass|block`), never an unmarked pass; the path
  comes from the request target, dot segments and doubled slashes are
  resolved as nginx resolves them, and a path, header value or method Go
  cannot relay gets 400; the agent listens on loopback, caps connections and
  frame sizes and recovers from a malformed frame; it keeps its connections
  to jev-edge.
- **Envoy gRPC shim**: an answer without a verdict below 500 is unjudgeable
  (`-unjudged`), a path it cannot relay gets 400, dot segments are resolved
  as nginx does, a deny carries no score, reason or source, and a client's
  `X-Jev-*` is dropped. The reference configs size the authz hop (60 KiB
  of headers).
- **APISIX**: judges after the access-phase gatekeepers and rate limiters
  (priority 1000), once per request when a global rule and a route both
  carry the plugin, and not at all for a request that matched no route; keeps
  `jev.api_key` and `subject.salt` encrypted in etcd and resolves `$env://`
  and `$secret://` references, and never uses one that does not resolve as
  the salt (subject tracking is off for that conf until it does); builds the
  runtime inside the fail-open path.
- **Kong**: picks up a rotated vault secret for the judge key and the salt;
  shares a breaker only between routes with the same key and tuning; keys a
  header subject an auth plugin hid on the authenticated credential; a data
  plane missing a rule file keeps syncing and answers that route
  `verdict=error` naming the rule, instead of refusing every push.
- **Istio recipe** sends every body-carrying request to ext_authz and lets
  `watch_paths` decide, strips forged `X-Jev-*`, and knows the client.

JavaScript runtime:
- **Durable Objects work across requests**: a real stub is recognised, the
  presets and `createRuntime` take the namespace and make a stub per
  operation, and a stub kept past its request falls back to isolate memory
  instead of failing every later request open.
- **A store that fails no longer fails the request open**: writes after the
  verdict are best effort, a failed breaker read is a closed breaker and a
  failed timeout read the floor.
- **The judged path is the routed one**: `nodeMiddleware` uses
  `originalUrl` on a fixed origin (a mount path hid the route, a bad Host
  threw), Next.js judges `nextUrl.pathname` without `basePath` and locale,
  and a path nginx would refuse (`%u0063`, `%00`) gets 400 on every host.
- **Bodies are read as the Lua adapters read them**: every gzip member,
  the size in bytes (0xFF padding tripled it), `NaN` and `Infinity` as cjson
  and Python take them, and "decoder not available" instead of "corrupt"
  where the runtime has none (Next's edge runtime).
- **The thin Worker** blocks whatever its origin blocked (any 4xx with
  `X-Jev-Verdict`, at any threshold), caches only what the origin judged,
  asks it about the whole request once, answers 404 to the origin's
  `/_jev/*` paths, and sends the origin token.
- **`/_jev/health` says `ok`, `adapter` and `core` only**, and Hono tells the
  client the request id only; Hono judges a body read before it.
- **Subject reputation on Cloudflare lives in one Durable Object per
  subject**, and KV reputation warns that it is best effort.

LiteLLM guardrail:
- **It sends the request's structure, bounded**: roles, content parts, tool
  calls and results, system prompts as the first message, tool definitions
  and `text.format` unchanged, tool-call arguments and Gemini function
  responses unfiltered, head and tail past `JEV_EDGE_MAX_BODY_BYTES`, up to
  the 1000 levels jev-edge decodes, without recursion.
- **Nothing a request, its key or its team sets switches it off**
  (`disable_global_guardrail` on LiteLLM 1.80, team metadata, opted-out
  lists), and `/guardrails/apply_guardrail` can be refused
  (`JEV_EDGE_TEST_ENDPOINT=refuse`).
- **It trusts only the proxy's own metadata** for the client address and
  its verdict, and appends the peer it saw to `X-Forwarded-For`.
- **Call types as LiteLLM passes them**: realtime text through
  `apply_guardrail`, batch files per line, Bedrock, Gemini, Gigachat and
  generic pass-through bodies, Bedrock text documents; a pass-through with no
  visible body, or a document it cannot read, is unjudgeable
  (`JEV_EDGE_UNJUDGED`), and a token-id prompt is sent to jev-edge. A body
  whose only text is under a structural key (`id`, `name`, `toolUseId`) on a
  path jev-edge reads whole is sent, not skipped as "no text".

laya-server:
- **It takes a burst instead of dropping it** (listen backlog, connection
  cap), answers within the gateway's read budget or refuses at once
  (`LAYA_GATEWAY_TIMEOUT_MS`, a cost model seeded before it listens), and
  sizes its pool from the CPUs it may use.
- **The client cannot make it slow or wrong**: `Content-Length` of ASCII
  digits only, at most `LAYA_MAX_QUESTIONS` questions tokenized once,
  special-token text encoded as text, windows cut between characters (an
  NFKC tokenizer overflowed the model), a stalled client not logged as a
  backend fault, and `TCP_NODELAY` (40 ms per answer).
- **The Laya profile sends one L2 call at a time**, which laya-server's
  default pool answers in time, and sizes its timeout floor from the
  worst-case text.

CI and release:
- **release-npm publishes only a tag on a commit `main` has**, builds without
  the OIDC token, and publishes the packed tarball from a job that runs no
  repository or dependency code; a manual real publish must run on a tag.
- **pnpm is pinned** (11.9.0) in `package.json`, every workflow reads it, and
  no dependency build script runs.
- **The govulncheck gate fails when the scan fails**, and non-PR runs no
  longer cancel each other.

### Added
- Config: `client_ip.ipv6_prefix`, `policy.partial`, rule `json_only_paths`,
  `tool_fields`, `token_prompts` and `paths_case_sensitive`, openai-compat
  `jev.max_tokens`, `jev.token_param`, `jev.temperature` (false omits it) and
  `jev.extra_body`. The openai-compat judge is asked with the deployment
  context, and a failed call quotes the provider's error.
- Kong schema: provider `laya`, `jev.ssl_verify`, `jev.questions_json`,
  `subject.reputation`, `jev.extra_body_json`; APISIX schema likewise, with
  `encrypt_fields`.
- Metrics and alerts: `jev_adapter_errors_total{entry}` with
  JevAdapterErrors, `jev_async_total{result}` with JevAsyncFailing,
  `jev_l2_errors_total{kind}` with JevL2NoVerdicts (every L2 call failing,
  whatever the breaker says) and JevL2Saturated (`max_inflight` refusals),
  `jev_authz_events_total{event}`; a verdict's `error_kind`; Grafana panels
  for each.
- `GET /_jev/config` reports `config_error`, and `/_jev/health` answers 503
  while a config is refused.
- JavaScript: `state: { namespace, name }`, `health: "details"`,
  `originToken`, `denoKvStore({ consistency })` and `getMany`.
- Golden format 2 (breaker calls and state), `utf8.json`, `client_headers`,
  and 717 vectors in all; `make package-check` loads the installed rock and
  opm tree; Kong hybrid-mode e2e; the tool-definition bench.

### Changed
- **Config reload** watches the file's content (CRC-32 and length), not its
  whole-second mtime; a file edit with a broken rule is refused whole; a
  config refused at startup runs the defaults with their rules; a refused
  file never becomes the one overrides are checked against, and a `DELETE`
  the file in force cannot take answers 422.
- **Metrics**: every family in one block, the L2 latency histogram complete
  and up to 30 s, busy refusals and cache-only verdicts out of it; only
  core's L2 calls feed the adaptive timeout.
- **Sampling**: the ring keeps the size its first writer gave it, and each
  sample names its rule (and route on Kong and APISIX) and carries the tool
  definitions.
- **JavaScript**: default memory stores are bounded; writes after the verdict
  go through `waitUntil`; a JevState judged request makes two hops; Deno KV
  reads the cache eventually consistent and the ring with `getMany`;
  `@jev-edge/js` loads with `require()` on Node >= 20.19 and 22.12.
- `resty.jev.loader` steps aside when `jev.core` / `jev.rules` are installed.

### Fixed
- `make opm-build`, the opm package and `make install` on a clean machine;
  the laya-server healthcheck on another port; the conformance keepalive
  check; the starter config's openai-compat `max_judge_bytes`; the env hint
  of a refused reload; the Grafana breaker panel (open showed as closed) and
  the subject-blocks legend; Kong picks the L3 and sampling rule with the
  decoder; the JS runtime picks the sampled rule as `rule_for` does; the
  repository invariants parse the rockspec and ci.yml properly and run their
  own mutation tests.

### Documentation
- The operating guide and design reference follow all of the above:
  what the default rule watches and reads, stateful APIs L1 cannot see, the
  breaker as it is, tool definitions, reputation charges, an origin that
  trusts a Worker's subject id, and the Kong, APISIX, HAProxy, JS and ops
  documents. Admin examples use the example config's `127.0.0.1:9180`.

## [0.6.1] - 2026-09-23

Two security fixes, a gap in what L1 reads, and documentation that is quicker
to read. The Responses fix is the one behaviour change without opting in:
Responses API tool output now reaches L2 as part of the whole text.

### Security
- **In-flight overflow no longer trips the breaker.** A call refused by the
  gateway's own `max_inflight` cap (`judge.BUSY`, "max_inflight exceeded")
  was recorded as a breaker failure, so a burst of about 85 concurrent
  requests with distinct text could open the breaker and switch L2 (and L3)
  off for every path and tenant for `open_s`, repeatable every 30 s. Such a
  call never reached the provider and is now not recorded at all; when a
  request is judged in parts (chunks, retrieved content), a busy part no
  longer turns answered parts into a failure. The request still passes as
  `verdict=error`. Lua and JS cores.

### Fixed
- **Responses API tool results are judged.** The default text fields never
  read a Responses `function_call_output` (its text is under `output`), so
  with `untrusted` off every tool result in that shape went unjudged (0.6.0
  held-out: AUC 0.497, every attack passing). `input[*].output` is a default
  text field now (`llm-endpoints`, `default`, and the fallback for inline
  rules), as OpenAI `role: tool` and Anthropic `tool_result` content already
  were. Judged only as whole text, most attacks in it still pass (0.6.1
  held-out: AUC 0.966, 72% missed at 0.5); turn `untrusted` on for tool
  traffic.

### Removed
- **IP trust at L1.** `core/rules.lua` and `rules.ts` passed any IP whose
  reputation entry had `trusted_until`, but nothing ever wrote it; the L3
  `safe` counter that would have fed it is gone too. Reputation now only
  blocks: a run of safe verdicts must not let an attacker warm up an IP and
  skip L2. Golden vector `ip trusted` is now `ip trust is not a bypass`.

### Changed
- **README cut to a five-minute read**: what jev-edge is, a quick look, how it
  works, install, the benchmark table. The operating guide (body size,
  deployment context, thresholds, false positives, subject reputation,
  retrieved content, Laya, cost, repository layout, roadmap) moved to
  `docs/design.md` as its Part 1; links elsewhere point there.
- **The Chinese documents are rewritten** in Chinese rather than translated
  sentence by sentence: README, design, cost, recipes and ops.
- **The held-out set was re-run on 0.6.1** and the numbers in the docs are that
  run (`untrusted` off 77.8% missed at 0.5, on 19.0%, 1 false positive in 700);
  the 0.6.0 run stays in git history.

## [0.6.0] - 2026-09-23

Retrieved content judged on its own, accuracy measured beyond deepset, and
Laya as an L2 judge with a System One conformance suite. Nothing changes for
an existing deployment unless it opts in (`untrusted.enabled`,
`provider = "laya"`); every existing golden vector is unchanged.

### Added
- **Laya as an L2 judge.** `provider = "laya"` (Lua and JS) sends the jev
  System One request to a server you run; its scores stay apart from jev's in
  the cache, the log and calibration. `adapters/laya-server/` serves a
  fine-tuned Laya model over that protocol (Python, Dockerfile; ONNX, your
  own Python scorer, or a mock backend): long text is judged in overlapping
  windows in one batch and refused with 413 past `LAYA_MAX_WINDOWS`, never
  silently cut; `fit_temperature.py` fits the temperature that makes `noul` a
  calibrated probability; `jev-laya.conf.lua` is the gateway profile (L2
  timeout 100 / 300 ms instead of 400 / 1000, `max_judge_bytes = 4096`,
  monitor mode). The base Laya model is not usable for this task without
  fine-tuning, so no Laya benchmark and no default thresholds ship.
- **Protocol conformance suite.** `conformance/`: System One vectors built
  by the real provider from the real templates (`make conformance-vectors`,
  `conformance-check` in `make check`) and `run.py`, which checks any judge
  server for the answer set, `noul` range, determinism, error codes, long
  input, keepalive, aborted and stalled clients and p99 latency
  (`make conformance ENDPOINT=... [STRICT=1] [MOCK=1]`). `make test-laya`
  runs it against laya-server, including a server that truncates, which must
  fail.
- **Per-provider question wording.** `jev.questions.<template>` replaces
  `instructions`, `criteria`, `instructions_ctx` or `criteria_ctx` for the
  `jev` / `laya` request only, for wording validated on another judge.
- **Calibration per judge.** The access log records `provider` and `model`;
  `make calibrate` refuses a log that mixes judges until `PROVIDER=` /
  `MODEL=` (`--provider` / `--model`) picks one, since their scores are not
  comparable.
- **Retrieved content judged on its own** (`untrusted`, off by default, hot
  reloadable, overridable per rule). L1 cuts retrieved content out of a body
  parsed whole: OpenAI `role: "tool"` / `"function"` messages, Anthropic
  `tool_result` blocks, Responses `function_call_output` items, and any
  `untrusted.fields` JSON path. It gets its own judging window and is judged
  in a parallel call with the new `untrusted` question, without the deployment
  context; the whole-text judgment is unchanged and the request gets the
  higher score. Its own cache entry (tool results repeated in a conversation's
  history are not paid for again), a request fingerprint that covers it (trust
  and the verdict cache cannot pass new retrieved content under old text), and
  retrieved content judged alone next to a message too short to judge
  (reason `retrieved content`). Lua and TypeScript cores, 12 new golden vectors
  (`judge.by_question` in the vector format answers only the questions a
  prompt asked), APISIX and Kong schemas, the starter config, and Test::Nginx
  cases through the OpenResty adapter (hot toggle through `/_jev/config`, the
  Responses shape, a malformed section refused; the `mock` provider takes
  `mock_scores` per question for them). On a held-out
  set of 1,200 tool results the question was not written against, the shipped
  core with it on cut misses at 0.5 from 86.8% to 19.2% with 1 false positive
  in 700; one more call per request carrying tool content, L2 p50 277 → 293 ms.
- **Held-out set** (`bench/datasets/heldout-v1.jsonl`, `make suite-heldout`):
  InjecAgent and LLMail-Inject phase 1 attacks against benign InjecAgent
  templates and Hermes function-calling results, rendered as OpenAI, Anthropic
  or Responses bodies, run end to end through `core.evaluate`. Committed
  before the run.
- **The untrusted-segment experiment** (`make suite-untrusted`): the question
  measured on suite v1's indirect records and on non-email tool results
  (`suite-v1-tooldocs`), committed before its first run. It showed that the
  question, not separating the text, does the work.
- **Accuracy chart** (`docs/bench-accuracy-*.svg`, `make bench-chart`), drawn
  from the committed live results.
- **Template wording pinned across cores**: a vitest case compares every
  TypeScript template to its `core/templates/*.lua` file.
- **Suite v1: accuracy beyond deepset.** `bench/datasets/suite-v1.jsonl`, 2,735
  whole chat request bodies from seven MIT / Apache-2.0 sources: Chinese
  instruction attacks (Safety-Prompts) against Chinese benign instructions,
  over-defense look-alikes (NotInject), indirect injection in retrieved emails
  and tool results (LLMail-Inject, BIPIA), and attacks spliced into real
  multi-turn threads (OpenAssistant, Gandalf). `make suite-fetch` /
  `suite-build` / `suite-live [CTX=1]` / `suite-report`. First live run
  committed with its results: strong on Chinese override and multi-turn, weak
  on indirect injection (BIPIA 81.5% miss at 0.5), and the general-assistant
  deployment context raised false positives instead of helping. See
  `bench/suite/README.md`, including two source categories whose labels did
  not hold up.

### Changed
- **The latency chart is redrawn from a new run**, and its "hard cut at
  300 ms" label is gone: `timeout_ms` is the adaptive timeout's floor, so the
  slow-provider scenario waits up to `timeout_max_ms` (p99 478 ms against a
  500 ms mock). The 0.5.0 code gives the same 475 ms; the old chart no longer
  matched the code it described.

### Fixed
- **CodeQL `js/incomplete-url-substring-sanitization`** in
  `adapters/js/test/worker.test.ts`: the fetch stub matched the judge by URL
  prefix, which `api.typesafe.ai.example` also passes; it compares the parsed
  host now. Test-only, no runtime change.

### Known gap
- Without `untrusted`, Responses API `function_call_output` items are not
  judged at all (their text is under `output`, which no default text field
  reads). The held-out run shows every attack in that shape passing with it
  off. Turn `untrusted` on when fronting the Responses API with tools.

## [0.5.0] - 2026-09-23

Subject reputation, a Kong plugin, a Deno preset and the npm package, an
operations kit, judge robustness (including long text judged in chunks),
and CI that runs the previous audit's bug classes as tripwires. Nothing
changes for an existing deployment unless it opts in (`subject.reputation`,
`max_judge_chunks`); the openai-compat judge now treats an echoed planted
answer as an injection and an incomplete reply as an error.

### Added
- **Subject reputation** (`subject.reputation`): judged verdicts add points
  per subject (a header such as an API key, a cookie, or the IP) over a
  sliding window (suspicious 1, malicious 3 by default); past `block_at` the
  subject is blocked at L1 for `block_ttl`, from any address and for any
  text. Off by default. Counters are two keys per subject in the subject
  store (atomic `incr`); L1 blocks never count. `make calibrate` replays the
  window per subject from monitor-mode logs (log lines now carry `ts`) and
  recommends `block_at`. `jev_subject_blocks_total`. Golden vectors carry
  the subject store and its writes; both cores replay them.
- **Kong Gateway plugin** (`adapters/kong`, Kong 3.x, same engine as the
  APISIX plugin): priority 905 (after auth, acl and rate limiting), body via
  `resty.jev.body` including spooled bodies, fail-open on every error; schema
  mirrors the APISIX keys and runs core's validation; `make e2e-kong` (real
  Kong 3.9, DB-less, 18 checks) runs in CI. The rockspec ships the plugin.
- **Deno Deploy preset** (`@jev-edge/js/deno`: `denoHandler`, and
  `denoKvStore` with atomic `incr` on Deno KV).
- **npm release workflow** (`release-npm.yml`): on a `v*` tag, checks that
  the tag matches the package version, tests, builds, checks every export
  resolves and publishes with provenance when `NPM_TOKEN` is set (skips
  otherwise). Package metadata, `LICENSE` and `prepublishOnly` added.
- **Operations** (`ops/`): a Grafana dashboard, Prometheus alert rules
  (breaker open, L2 error ratio, unjudgeable ratio, L2 timeout at its
  ceiling, async drops, L2 starved) with `promtool test rules` unit tests run
  in CI; new metrics `jev_feedback_total{label,result}` and
  `jev_l2_timeout_max_ms`.
- **Judge robustness**: `bench/datasets/judge-directed.jsonl` (45 cases:
  verdict requests, text addressing the classifier, fake answer JSON, fake
  end-of-input markers, retractions, other languages, buried instructions,
  and benign look-alikes) and `make bench-judge` (offline L1 pass; the live
  part needs a provider key); six `always_suspect` patterns for
  judge-directed text, each with a golden positive, and negatives such as
  "Is this email safe to open?".
- **Judging long text in chunks** (`max_judge_chunks` in a rule, default 1):
  text over `max_judge_bytes` is split into up to that many chunks (cut at
  a newline where possible, never inside a character), judged in parallel
  (`judge.call_many`: `ngx.thread` on OpenResty, APISIX and Kong,
  `Promise.all` in JS), the highest chunk score wins, each chunk has its own
  cache entry. Past the cap, the newest chunks plus a window over the rest,
  or `unjudgeable: text over max_judge_chunks` with `policy.unjudgeable =
  "block"`. An instruction in the middle of a long message that no pattern
  matches is no longer cut out when chunks are on. Golden vectors accept
  inline rule specs (7 chunk cases in both cores).
- Partial bodies are covered end to end: Envoy (HTTP and gRPC, cut at
  `max_request_bytes`) and HAProxy (past `tune.bufsize`, Content-Length and
  chunked) flag them, and the e2e suites check that an attack in the part
  that arrived is blocked and a benign one is judged. `docs/design.md` has
  a "Traffic L1 does not see" section (WebSocket frames, Realtime API,
  responses, multimodal content, headers-only and partial-body gateways).
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
- **`@jev-edge/js` could not be loaded by Node or Deno**: `dist/` used
  extensionless relative imports (fine for bundlers, `ERR_UNSUPPORTED_DIR_IMPORT`
  for Node's ESM loader, so `nodeMiddleware` and Lambda@Edge only worked
  bundled). Every import has its `.js`, and the build uses `NodeNext` so an
  extensionless import no longer compiles.
- **openai-compat judge prompt hardened**, the same in Lua and TS: the text
  sits between per-request random markers it cannot contain; every
  top-level JSON object in the reply is read and each question takes its
  highest value, so a low answer echoed from the input cannot lower the real
  one; a reply missing an asked question is an error, not a lower score;
  `null`, `false`, `""` and `[]` are no longer read as 0 in TS. The
  injection template tells the judge that text addressing it is itself a
  signal.
- **openai-compat: a reply that only repeats an answer planted in the judged
  text scores 1**, the same in Lua and TS (compared on parsed values). It
  was read as the model's own answer, so a planted `{"injection": 0}` that a
  small model echoed passed the request.
- A byte cut through a multi-byte UTF-8 character no longer reaches the L2
  prompt: the head and tail of an oversized body, and a gateway's partial
  body, end on character boundaries.
- `.gitignore`'s `jev-edge/` matched any directory of that name; it is
  anchored to the repository root.
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
