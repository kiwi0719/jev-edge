# bench

Two benches, both reproducible without a TypeSafe key.

| Command | What it measures | Needs |
|---|---|---|
| `make bench-offline` | accuracy of the whole pipeline (L1 + thresholds) against jev-sec-bench's recorded Jev probabilities on deepset/prompt-injections; replay cache hit rate; core-only latency | Lua + `dkjson` + `lrexlib-pcre2` |
| `make bench` | end-to-end latency in OpenResty for five scenarios (baseline, unwatched path, healthy / slow / dead Jev) using the `mock` provider; verifies 100% pass with Jev down | Docker |

`bench/datasets/jev-sec-bench-injection.json` is `results/injection.json` from
[Gaurav-Gosain/jev-sec-bench](https://github.com/Gaurav-Gosain/jev-sec-bench) (MIT),
itself a run of `jev-1.13.0` over [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
(Apache-2.0). Each sample carries the text, the label and the probability Jev returned, so the
offline bench replays Jev's answers instead of calling it.

Latest results: [report.md](report.md). `bench/out*/` is gitignored; commit the report, not the raw output.
