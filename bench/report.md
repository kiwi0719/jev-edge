# Bench report

Generated 2026-09-22. Reproduce with `make bench-offline` and `make bench`.

## Part 1: offline accuracy

Dataset: `bench/datasets/jev-sec-bench-injection.json` (662 samples, 263 attacks, 399 benign), recorded model `jev-1.13.0`, run_at 2026-09-16T06:02:16.521661Z.

Rules: `llm-endpoints`; body path `/v1/chat/completions`; mode `enforce`. L2 uses the recorded Jev probability for each text instead of a live call.

## Pipeline accuracy vs Jev alone

| block threshold | benign passed at L1 | benign sent to L2 | attacks passed at L1 (never judged) | FP (pipeline) | miss (pipeline) | FP (Jev alone) | miss (Jev alone) |
|---|---|---|---|---|---|---|---|
| 0.50 | 5.3% | 94.7% | 1.1% | 2.3% | 6.1% | 2.5% | 4.9% |
| 0.70 | 5.3% | 94.7% | 1.1% | 0.3% | 12.5% | 0.5% | 11.4% |
| 0.85 | 5.3% | 94.7% | 1.1% | 0.0% | 23.2% | 0.0% | 22.4% |
| 0.95 | 5.3% | 94.7% | 1.1% | 0.0% | 54.8% | 0.0% | 54.8% |

`attacks passed at L1` is the cost of the L1 prefilter: attacks whose text was too short or did not look like natural language, so Jev never saw them. `miss (pipeline)` includes them.

## Replay cache

263 attack texts × 5 variants (case, whitespace, trailing reference number, padding): 1315 requests, 524 L2 calls. Of the 1052 repeats, **74.3%** were served from cache; 0.7% passed at L1.

The variant that defeats the cache is the appended reference number: digits are stripped but the surrounding `(ref )` text remains, so the fingerprint differs. Case, whitespace and padding variants all hit.

## core.evaluate latency (single core, Lua Lua 5.5, no nginx)

| path | µs per call |
|---|---|
| unwatched path | 0.85 |
| watched, short body | 11.19 |
| watched, natural language → L1 suspect (judge stubbed) | 16.48 |

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

### Against the v0.1 targets

| Metric | Target | Measured |
|---|---|---|
| P99 added to L1-passed traffic | ≤ 1 ms | 24 µs |
| Normal traffic sent to L2 | ≤ 2% of *all* traffic | n/a here: this dataset is 100% chat text, and 94.7% of it is sent to L2. The 2% target is about site-wide traffic, where most requests never hit a watched path. |
| False-positive rate (enforce) | ≤ 0.1% | 0.0% at block ≥ 0.85; 0.3% at 0.70 |
| Miss rate vs Jev alone | ≤ baseline + 2% | +0.8 pt at 0.85 (23.2% vs 22.4%); +1.2 pt at 0.50 |
| Replay cache hit rate | ≥ 80% | 74.3% of repeats (the appended-reference variant defeats normalization) |
| Pass rate with Jev dead | 100% | 100% |

Two targets are not met as written. The replay number is honest about a normalization gap.
The L2-share target needs a mixed-traffic dataset to be meaningful; the offline bench cannot produce it.

## Part 3: live provider check (`make live-check`, 2026-09-22)

From a laptop on a residential connection, Docker on macOS, `jev-latest`, one Noul question, short state (the dataset text only).

| | |
|---|---|
| connectivity | OK; first call 701 ms (cold TLS handshake) |
| latency, 60 sequential calls | p50 268 ms, p90 304 ms, p95 314 ms, p99 355 ms, min 230 ms, 0 errors |
| calls over a fixed 300 ms cut | 9 / 60 (15%) |
| agreement with recorded jev-1.13.0 | median \|Δp\| 0.030, mean 0.157, max 0.880; 10 / 60 flip sides at 0.5 |

Consequences: the default timeout moved from a fixed 300 ms to adaptive `400 … 1000 ms`. The agreement numbers are not a like-for-like model comparison: jev-sec-bench supplied a deployment context as state and its own question wording, this check sends the bare text with jev-edge's `injection` template. The offline accuracy table in Part 1 therefore describes jev-1.13.0 under jev-sec-bench's prompt, not `jev-latest` under jev-edge's.
