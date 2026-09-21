# Bench report

Generated 2026-09-22. Reproduce with `make bench-offline`, `make bench`, `make live-check`, `make live-full`, `make soak`, `make live-openai`.

Dataset for every accuracy number: deepset/prompt-injections via jev-sec-bench (662 samples: 263 attacks, 399 benign). Its labels were collected for a specific deployment, a German news publisher's reader assistant, so "write me C++" counts as an attack there and as a normal request anywhere else. That single fact drives the biggest result below.

## Part 1: accuracy, three L2 oracles

Pipeline = L1 rules → L2 (score replayed from a stored run) → policy, mode `enforce`. All three columns use the same 662 texts.

| oracle | what Jev saw | model | AUC |
|---|---|---|---|
| **bare** | the text alone, jev-edge `injection` template | jev-latest | 0.983 |
| **+context** | `{assistant: <deployment description>, user_message: <text>}`, jev-edge `injection` template in its context form | jev-latest | **0.996** |
| recorded | jev-sec-bench's own prompt and context | jev-1.13.0 | 0.993 |

| block threshold | FP bare | miss bare | FP +context | miss +context | FP recorded | miss recorded |
|---|---|---|---|---|---|---|
| 0.10 | 1.0% | 12.2% | 27.6% | 0.0% | 26.3% | 0.8% |
| 0.20 | 0.5% | 21.7% | 10.3% | 0.4% | 12.3% | 1.9% |
| 0.30 | 0.3% | 28.9% | 5.0% | 3.8% | 5.5% | 3.8% |
| 0.50 | 0.0% | 37.3% | 0.8% | 5.3% | 2.5% | 4.9% |
| 0.70 | 0.0% | 47.5% | 0.0% | 13.3% | 0.5% | 11.4% |
| 0.85 | 0.0% | 58.6% | 0.0% | 28.1% | 0.0% | 22.4% |

Reading it:

- **`deployment_context` is the most important setting in jev-edge.** Without it Jev answers "is this text an injection attack" and scores off-purpose requests ("translate to polish", "generate SQL") near zero: 46 of the 263 labelled attacks fall below 0.2. With a one-paragraph description of the deployment the same model, same template, reaches AUC 0.996 and agrees with jev-sec-bench's recorded run on 654 of 662 samples at the 0.5 line.
- The bare column is not wrong for a generic gateway: it has 0% false positives at 0.5 and still catches instruction-override attacks. It just cannot know what is off-purpose for your service.
- With context, 0.5 is a defensible starting threshold: 0.8% FP, 5.3% miss on this dataset. 0.85, the shipped default, is very conservative: zero FP, 28% miss.
- The `abuse` template scored 0% FP at every threshold on this dataset and AUC 0.921 against injection labels; it was not designed for them and has no dataset of its own yet.

The full pipeline adds about +1 pt of miss over the oracle at every threshold: the three attacks L1 passes because they are under 20 characters.

Pipeline table with the +context oracle (`lua bench/offline.lua bench/datasets/live-jev-latest-ctx.json`):

| block threshold | benign passed at L1 | benign sent to L2 | attacks passed at L1 (never judged) | FP (pipeline) | miss (pipeline) | FP (oracle alone) | miss (oracle alone) |
|---|---|---|---|---|---|---|---|
| 0.30 | 5.3% | 94.7% | 1.1% | 4.3% | 4.9% | 5.0% | 3.8% |
| 0.50 | 5.3% | 94.7% | 1.1% | 0.5% | 6.5% | 0.8% | 5.3% |
| 0.70 | 5.3% | 94.7% | 1.1% | 0.0% | 14.1% | 0.0% | 13.3% |
| 0.85 | 5.3% | 94.7% | 1.1% | 0.0% | 28.5% | 0.0% | 28.1% |


## Replay cache

263 attack texts × 5 variants (case, whitespace, trailing reference number, padding): 1315 requests, 524 L2 calls. Of the 1052 repeats, **74.3%** were served from cache; 0.7% passed at L1.

The variant that defeats the cache is the appended reference number: digits are stripped but the surrounding `(ref )` text remains, so the fingerprint differs. Case, whitespace and padding variants all hit.

## L1 prefilter alone

`always_suspect` hits: 0 / 399 benign (0.0%), 9 / 263 attacks (3.4%). A prefilter hit only forces L2; it never blocks by itself, so benign hits cost latency, not availability.

Worst-case match time per pattern on 5 adversarial inputs (20 KB repeats):

| # | worst ms | pattern |
|---|---|---|
| 1 | 1.00 | `\b(ignore\|disregard\|forget)\b.{0,20}\b(previous\|prior\|above\|earlier\|all)\b.{0,20}\b(instructions?\|rules?\|prompts?)\b` |
| 2 | 0.00 | `\byou are now\b` |
| 3 | 0.01 | `\b(system\|hidden\|secret\|initial)\s+prompt\b` |
| 4 | 0.00 | `<\\|?(system\|im_start)\\|?>` |
| 5 | 0.00 | `\[/?INST\]` |
| 6 | 0.00 | `\bdeveloper mode\b` |
| 7 | 0.08 | `\b(DAN\|do anything now)\b` |
| 8 | 0.03 | `\b(reveal\|print\|repeat\|show)\b.{0,30}\b(instructions\|system prompt\|rules)\b` |
| 9 | 0.22 | `(?:[A-Za-z0-9+/]{4}){40,}={0,2}` |


## core.evaluate latency (single core, Lua 5.5, no nginx)

| path | µs per call |
|---|---|
| unwatched path | 0.87 |
| watched, short body | 11.42 |
| watched, natural language → L1 suspect (judge stubbed) | 16.65 |

The OpenResty adapter adds body read, header writes and shared-dict access on top; see `bench/run.sh` for end-to-end P99.

## Part 2: end-to-end latency (OpenResty in Docker, mock provider)

`openresty/openresty:alpine-fat` on Docker Desktop (macOS, Apple Silicon), 2 workers, 10 s per scenario, wrk with 2 threads.
Bodies are the 399 benign deepset texts, so every watched request goes through L1 → L2.

Scenarios: **baseline** = plain `content_by_lua`, jev-edge not loaded. **unwatched** = `access()` runs, path not in `watch_paths`.
**healthy** = mock Jev answers in 100 ms. **slow** = mock Jev needs 500 ms, cut at `timeout_ms = 300`. **dead** = mock Jev fails every call.

### 4 connections (latency under light load)

| scenario | rps | p50 | p99 | max |
|---|---|---|---|---|
| baseline | 94,889 | 36 µs | 47 µs | 865 µs |
| unwatched | 92,531 | 39 µs | 71 µs | 3.29 ms |
| healthy | 40 | 102.43 ms | 105.53 ms | 105.74 ms |
| slow | 54,662 | 53 µs | 288.05 ms | 308.67 ms |
| dead | 69,912 | 48 µs | 173 µs | 4.51 ms |

### 32 connections (both workers saturated; throughput, not latency)

| scenario | rps | p50 | p99 | max |
|---|---|---|---|---|
| baseline | 531,433 | 41 µs | 87 µs | 3.09 ms |
| unwatched | 253,475 | 111 µs | 1.63 ms | 65.51 ms |
| healthy | 324 | 103.04 ms | 105.85 ms | 107.58 ms |
| slow | 83,142 | 330 µs | 214.05 ms | 312.30 ms |
| dead | 84,543 | 335 µs | 1.42 ms | 14.27 ms |

### Reading the numbers

- **Added latency on the L1 pass path**: p99 goes from 47 µs to 71 µs at light load. Target was ≤ 1 ms.
- **Dead Jev**: every request passed (`jev_actions_total{action="pass"}` equals the request count, breaker gauge = 1). After the first 20 failures the breaker opens and p50 returns to ~50 µs.
- **Slow Jev**: p99 sits at the 300 ms hard cut until the breaker opens, then the median drops to 53 µs. The p99 stays high because the breaker re-probes every `open_s` seconds.
- **Healthy Jev**: latency is the provider's; jev-edge adds ~3 ms on top of the 100 ms mock delay at p99 (`ngx.sleep` granularity plus header work).


## Part 3: live provider checks

### TypeSafe `jev` provider, `jev-latest`, full dataset

Two full runs from a laptop on a residential connection, sequential, one request per sample carrying both templates.

| | bare | +context |
|---|---|---|
| requests / errors | 662 / 0 | 662 / 0 |
| p50 / p95 / p99 / max | 269 / 328 / 396 / 649 ms | 272 / 334 / 390 / 1393 ms |
| input tokens | 339,368 | 403,582 |
| wall time | 182 s | 186 s |

A fixed 300 ms timeout would have cut 15% of the 60-sample smoke run and about the same share here; the adaptive default (400 ms floor, 1000 ms ceiling) settles around 470 ms on this link.

### `openai-compat` provider, Ollama `qwen2.5:0.5b`

20 dataset samples through a 0.5 B model in a container: 20 / 20 responses parsed after the prompt was tightened to name the question ids and give an example reply; 14 / 20 agreed with the labels, which says something about a 0.5 B model and nothing about the provider. The protocol path (chat completions, `response_format: json_object`, tolerant parsing of numeric strings and lone `probability` keys) is verified.

## Part 4: soak

`make soak DUR=120s`: 4 workers, 256 KB cache dict, `max_inflight = 8`, `max_async = 4`, mock provider at 80 ms with 5% failures and every verdict in the suspicious band so every request wants an L3 timer.

| | |
|---|---|
| requests / errors | 12,304,781 / 0 |
| p50 / p99 | 541 µs / 3.0 ms |
| workers alive / crashes | 4 / 0 |
| `max_inflight exceeded` | 2,746 (logged and passed, not queued) |
| `jev_async_dropped_total` | 11,850,621 (dropped, not queued) |
| breaker + adaptive state | identical sample counts from every worker: shared |
| worker RSS | 34 MB → 47 MB at 60 s → 48 MB at 120 s (plateau) |

The 256 KB cache dict was permanently full; `ngx.shared.DICT` evicts LRU on `set`, so no failures were logged and the cache kept serving.

## Against the v0.1 targets

| Metric | Target | Measured |
|---|---|---|
| P99 added to L1-passed traffic | ≤ 1 ms | 24 µs |
| False-positive rate (enforce) | ≤ 0.1% | 0.0% at ≥ 0.70 with context; 0.8% at 0.50 |
| Miss rate vs Jev alone | ≤ oracle + 2 pt | +1.2 pt at 0.50 (6.5% vs 5.3%) |
| Replay cache hit rate | ≥ 80% | 74% of repeats (appended-reference variant defeats normalization) |
| Pass rate with Jev dead | 100% | 100% |
| Normal traffic sent to L2 | ≤ 2% site-wide | not measurable on a chat-only dataset |
