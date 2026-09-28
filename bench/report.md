# Bench report

Generated 2026-09-22; latency, soak, replay cache and L1 sections re-run 2026-09-28 (accuracy tables reproduce unchanged). Reproduce with `make bench-offline`, `make bench`, `make live-check`, `make live-full`, `make soak`, `make live-openai`.

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

263 attack texts × 5 variants (case, whitespace, trailing reference number, padding): 1315 requests, 525 L2 calls. Of the 1052 repeats, **74.2%** were served from cache; 0.7% passed at L1.

The variant that defeats the cache is the appended reference number: digits are stripped but the surrounding `(ref )` text remains, so the fingerprint differs. Case, whitespace and padding variants all hit.

## L1 prefilter alone

`always_suspect` hits: 0 / 399 benign (0.0%), 9 / 263 attacks (3.4%). A prefilter hit only forces L2; it never blocks by itself, so benign hits cost latency, not availability.

Worst-case match time per pattern on 5 adversarial inputs (20 KB repeats):

| # | worst ms | pattern |
|---|---|---|
| 1 | 1.20 | `\b(ignore\|disregard\|forget)\b.{0,20}\b(previous\|prior\|above\|earlier\|all)\b.{0,20}\b(instructions?\|rules?\|prompts?)\b` |
| 2 | 0.00 | `\byou are now\b` |
| 3 | 0.01 | `\b(system\|hidden\|secret\|initial)\s+prompt\b` |
| 4 | 0.00 | `<\\|?(system\|im_start)\\|?>` |
| 5 | 0.00 | `\[/?INST\]` |
| 6 | 0.00 | `\bdeveloper mode\b` |
| 7 | 0.09 | `\b(DAN\|do anything now)\b` |
| 8 | 0.03 | `\b(reveal\|print\|repeat\|show)\b.{0,30}\b(instructions\|system prompt\|rules)\b` |
| 9 | 0.22 | `[A-Za-z0-9+/]{160,}={0,2}` |
| 10 | 0.01 | `\b(rate\|classify\|mark\|label\|score\|flag\|treat\|judge)\b.{0,30}\b(this\|it\|me\|the (above\|following\|message\|request\|input\|prompt\|text))\b.{0,30}\bas\s+(a\s+)?(safe\|benign\|harmless\|clean\|legitimate\|non-?malicious\|0(\.0+)?)\b(?!\s+(to\|for)\b)` |
| 11 | 0.08 | `\b(classifier\|moderator\|guardrail\|safety (filter\|model\|system\|check)\|content filter\|judge model)\b.{0,40}\b(output\|return\|respond\|answer\|reply\|say\|print)\b.{0,20}\b(0(\.0+)?\|safe\|benign\|harmless\|false)\b` |
| 12 | 0.01 | `\b(to\|for)\s+(the\|any)\s+(ai\|model\|llm\|classifier\|moderator\|reviewer\|filter)\s+(reviewing\|checking\|scanning\|screening\|evaluating\|analy[sz]ing\|reading\|judging)\s+(this\|these\|the)\b` |
| 13 | 0.01 | `[\x7b,]\s*"(injection\|abuse\|noul\|jailbreak\|prompt_injection)"\s*:\s*(\x7b\|\[\|"?(0(\.\d+)?\|false\|safe\|benign)\b)` |
| 14 | 0.01 | `(={3,}\|-{3,}\|#{2,}\|\*{3,}\|\[\|</?)\s*end[ _-]+(of[ _-]+)?(the[ _-]+)?(user[ _-]+)?(input\|message\|prompt\|text\|data\|query)\b` |
| 15 | 0.34 | `\b(real\|actual\|true\|correct\|final)\s+(verdict\|rating\|classification)(\s+(is\|should be)\|\s*[=:])\s*"?(safe\|benign\|harmless\|clean\|0(\.0+)?\|not (malicious\|an? (injection\|attack)))\b` |

## core.evaluate latency (single core, Lua 5.5, no nginx)

| path | µs per call |
|---|---|
| unwatched path | 4.38 |
| watched, short body | 30.61 |
| watched, natural language → L1 suspect (judge stubbed) | 41.82 |

The OpenResty adapter adds body read, header writes and shared-dict access on top; see `bench/run.sh` for end-to-end P99.


## Part 2: end-to-end latency (OpenResty in Docker, mock provider)

`openresty/openresty:alpine-fat` on Docker Desktop (macOS, Apple Silicon), 2 workers, 10 s per scenario, wrk with 2 threads.
Bodies are the 399 benign deepset texts, so every watched request goes through L1 → L2.

Scenarios: **baseline** = plain `content_by_lua`, jev-edge not loaded. **unwatched** = `access()` runs, path not in `watch_paths`.
**healthy** = mock Jev answers in 100 ms. **slow** = mock Jev needs 500 ms, cut at `timeout_ms = 300`. **dead** = mock Jev fails every call.

### 4 connections (latency under light load)

| scenario | rps | p50 | p99 | max |
|---|---|---|---|---|
| baseline | 101,391 | 33 µs | 76 µs | 1.23 ms |
| unwatched | 72,197 | 40 µs | 1.14 ms | 3.25 ms |
| healthy | 40 | 103.03 ms | 106.99 ms | 107.36 ms |
| slow | 45,543 | 66 µs | 285.39 ms | 307.60 ms |
| dead | 53,727 | 65 µs | 200 µs | 7.22 ms |

### 32 connections (both workers saturated; throughput, not latency)

| scenario | rps | p50 | p99 | max |
|---|---|---|---|---|
| baseline | 366,667 | 61 µs | 223 µs | 3.27 ms |
| unwatched | 170,675 | 162 µs | 515 µs | 6.37 ms |
| healthy | 320 | 104.13 ms | 108.30 ms | 108.97 ms |
| slow | 68,939 | 418 µs | 203.79 ms | 308.70 ms |
| dead | 66,286 | 446 µs | 1.05 ms | 13.75 ms |

### Reading the numbers

- **Added latency on the L1 pass path**: p50 goes from 33 µs to 40 µs at light load. The unwatched p99 is not stable between runs on this host: 123 µs to 1.38 ms over six 4-connection runs, on 0.6.3 and on this tree alike, against a baseline p99 of 76–97 µs. Target was ≤ 1 ms.
- **Dead Jev**: every request passed (`jev_actions_total{action="pass"}` equals the request count, breaker gauge = 1). After the first 20 failures the breaker opens and p50 returns to ~65 µs.
- **Slow Jev**: p99 sits at the 300 ms hard cut until the breaker opens, then the median drops to 66 µs. The p99 stays high because the breaker re-probes every `open_s` seconds. The bench pins `timeout_max_ms = 300`: without it the adaptive timeout (ceiling 1000 ms by default) grows past 500 ms, waits out the slow mock and the p99 reads ~480 ms, which is what the scenario measured between the adaptive default and this fix.
- **Healthy Jev**: latency is the provider's; jev-edge adds ~7 ms on top of the 100 ms mock delay at p99 (`ngx.sleep` granularity plus header work).
- These numbers come from a different, slower host state than the 2026-09-22 run (core.evaluate is ~2.5× slower here too); compare runs from the same host only. Main (0.6.3) and this tree were run interleaved, three times each: every scenario within ±5%, with overlapping ranges.


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
| requests / errors | 9,461,721 / 0 |
| p50 / p99 | 711 µs / 46.18 ms |
| workers alive / crashes | 4 / 0 |
| `max_inflight exceeded` | 234,251 (logged and passed, not queued) |
| `jev_async_dropped_total` | 235,383 (dropped, not queued) |
| breaker + adaptive state | identical sample counts from every worker: shared |
| worker RSS | 35 MB → 56 MB at 120 s (56 MB after a 60 s run too: plateau) |

Against the 2026-09-22 run, p99 went from 3.0 ms to 46 ms and `max_inflight exceeded` from 2,746 to 234,251, while async drops fell from 11.9 M to 235 k. 0.6.3 shows the same on this host (60 s: p99 43 ms, 187 k over the cap), so the change came with the 0.6.x in-flight and async accounting, not with these fixes; it was not bisected further.

The 256 KB cache dict was permanently full; `ngx.shared.DICT` evicts LRU on `set`, so no failures were logged and the cache kept serving.

## Against the v0.1 targets

| Metric | Target | Measured |
|---|---|---|
| P99 added to L1-passed traffic | ≤ 1 ms | 40–55 µs typical (unwatched p99 minus baseline p99); over 1 ms in two of six runs on this host (see Part 2) |
| False-positive rate (enforce) | ≤ 0.1% | 0.0% at ≥ 0.70 with context; 0.8% at 0.50 |
| Miss rate vs Jev alone | ≤ oracle + 2 pt | +1.2 pt at 0.50 (6.5% vs 5.3%) |
| Replay cache hit rate | ≥ 80% | 74.2% of repeats (appended-reference variant defeats normalization) |
| Pass rate with Jev dead | 100% | 100% |
| Normal traffic sent to L2 | ≤ 2% site-wide | not measurable on a chat-only dataset |
