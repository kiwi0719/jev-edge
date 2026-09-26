# laya-server

A fine-tuned Laya model behind the System One protocol, so jev-edge can use it as its L2 judge through the `laya` provider. Laya ships as a Python library or an ONNX package, not as an HTTP API. This server is the thin layer between the two. The server itself uses only the standard library; the backend needs onnxruntime, tokenizers and numpy.

## No benchmark, no default thresholds

The base Laya model is not usable for this task without fine-tuning. This repository therefore publishes no Laya benchmark: no accuracy, detection or false-positive figures, and no thresholds. Numbers for the base model would say nothing about a deployment, and the result after fine-tuning depends on your data and your training. The steps below measure *your* build. Run the gateway in `monitor` mode until they are done.

## Run

```bash
docker build -t laya-server adapters/laya-server
docker run --rm -p 8080:8080 -v /path/to/finetuned:/model:ro \
  -e LAYA_TEMPERATURE=1.0 -e LAYA_API_KEY=change-me laya-server
```

`/model` holds `model.onnx` (a sequence-pair classifier: one "yes" logit, or two logits with `LAYA_POSITIVE` naming the "yes" index) and `tokenizer.json`. The gateway side starts from [`jev-laya.conf.lua`](jev-laya.conf.lua).

| variable | default | |
|---|---|---|
| `LAYA_BACKEND` | `onnx` | `onnx`, `python` (your own scorer, `LAYA_SCORER=module:function`), `mock` (no model, for tests) |
| `LAYA_MODEL_DIR` | `/model` | onnx: `model.onnx` + `tokenizer.json` |
| `LAYA_POSITIVE` | `1` | onnx: index of the "yes" logit when the model has two |
| `LAYA_MODEL_NAME` | `laya` | reported in responses |
| `LAYA_TEMPERATURE` | `1.0` | from `fit_temperature.py` |
| `LAYA_MAX_TOKENS` | `1024` | the model's context length |
| `LAYA_WINDOW_OVERLAP` | `64` | tokens shared by adjacent windows |
| `LAYA_MAX_WINDOWS` | `8` | past this, 413 instead of a cut |
| `LAYA_MAX_BODY_BYTES` | `262144` | request body limit |
| `LAYA_API_KEY` | unset | when set, `Authorization: Bearer <key>` is required |
| `LAYA_ACCESS_LOG` | `1` | `0` drops the per-request line on stderr |
| `LAYA_ORT_PROVIDERS` | `CPUExecutionProvider` | onnx: execution providers, comma-separated, in order of preference, e.g. `CUDAExecutionProvider,CPUExecutionProvider` with `onnxruntime-gpu` installed. A provider missing from the installed build stops the server at start |
| `LAYA_ORT_THREADS` | CPUs / `LAYA_WORKERS` | onnx: threads in the model's intra-op pool, shared by the requests being scored. With neither this nor `LAYA_WORKERS` set, half the CPUs, at most 4. `0` leaves the choice to onnxruntime, which counts the host's cores |
| `LAYA_WORKERS` | CPUs / `LAYA_ORT_THREADS` | requests scored at once. `mock` defaults to the CPUs, `python` to `1`, because your scorer may not be thread-safe |
| `LAYA_GATEWAY_TIMEOUT_MS` | `500` | the gateway's `jev.timeout_ms` (the lowest, when several gateways call this server; 500 in the profile). A request waits for a free worker only while it can still be answered within half of it, and otherwise gets `503 overloaded` (below) |
| `LAYA_BACKLOG` | `1024` | listen backlog: at least the sum of `jev.max_inflight` over the gateways that call this server. The kernel caps it (`net.core.somaxconn` on Linux, logged at start when lower) |
| `LAYA_MAX_CONNECTIONS` | `1024` | open connections; the next one is answered `503 overloaded` and closed |
| `LAYA_IDLE_TIMEOUT_S` | `120` | a connection silent this long is closed, `0` never. Keep it above the gateway's keepalive idle time (60 s) |

CPUs are the CPUs the server may use: the ones it may run on, capped by the container's CPU quota (cgroup `cpu.max`, or `cpu.cfs_quota_us` on cgroup v1), not the host's count. By default `LAYA_WORKERS` x `LAYA_ORT_THREADS` stays within them. Past them, the requests in flight take turns on the CPUs and all slow down together. The server logs the sizes it chose at start, and warns when the ones you set go past the CPUs.

## What the server guarantees

- **Protocol.** `POST /v1/systemone` with `{model, state, questions}`, where `state` is a string or `{assistant, user_message}` and each question is `{type: "noul", instructions, criteria?}`. The response is `{model, answers: {<name>: {noul}}, usage}`. Every asked question gets an answer and no other question does. `GET /healthz` is for probes.
- **No silent truncation.** The model sees at most `LAYA_MAX_TOKENS`. Longer text is scored in overlapping windows that cover all of it, in one batch, and the question takes the highest window score. Text that would need more than `LAYA_MAX_WINDOWS` windows is refused with `413 input_too_long`. A question plus deployment context that leaves no room for text is refused with `413 question_too_long`: this is a configuration error, and the user's text is never dropped to make room.
- **Load is answered, never dropped.** The listen backlog is `LAYA_BACKLOG`, not the 5 that Python's `socketserver` uses. The gateway opens up to `jev.max_inflight` connections at once (64 in the profile), and the kernel drops a connection past the backlog. The gateway's connect budget runs out before the SYN is retried, so each drop is an L2 timeout, and enough of them open the breaker for every tenant. At most `LAYA_WORKERS` requests are scored at once, and the others wait their turn, first come first served. A request that cannot be answered in time (below), or a connection past `LAYA_MAX_CONNECTIONS`, gets `503 overloaded`, and this server logs it even with the access log off. A 503 still lets the request through at the gateway and counts toward the breaker, so size the server for the load. `usage.wait_ms` in each answer is the time the request waited for a worker. A client that hangs up or stalls in the middle of its request gets an access-log line, never a backend-error warning.
- **A request waits only while it can be answered in time.** The gateway waits for the answer 60% of its L2 timeout (connect 30%, send 10%, read 60%): 300 ms at the profile's floor of 500 ms. A 503 sent after that reaches no one, the gateway logs a timeout instead, and a request scored after that uses a worker for an answer no one reads. So the server answers within half of `LAYA_GATEWAY_TIMEOUT_MS`, 250 ms by default: the same 2x headroom `make conformance` asks for, with the last 10% left for a scoring that runs past its estimate. On arrival it estimates how long the request takes to score, from its size in approximate tokens and the time recent requests of about that size took, and how long it would wait behind the requests being scored and queued ahead of it. When the two do not fit, the request gets a 503 at once. When they fit, it waits for a worker, and gets the 503 at the end of its time if none came. A burst of short texts, a few ms each, is served from the queue; a worst-case text behind them is refused at once. A request that finds a worker free is always scored.
- **Errors.** Every error is JSON `{error: {code, message}}` with a non-200 status: 400 for a malformed request, 401 for auth, 404, 405, 411, 413, 500 when the model fails, and 503 when overloaded. An error is never returned as a score.

An L2 error lets the request through (fail open). The profile's `max_judge_bytes = 4096` is sized so the gateway never sends a text that needs the 413. See the comment in [`jev-laya.conf.lua`](jev-laya.conf.lua).

## Latency grows with windows

On CPU, a text split into N windows costs about N model calls. The windows go to the model in one batch, and that saves the per-call overhead but not the compute. A hostile text can be built to tokenize at about one token per byte (punctuation, rare letters). At `max_judge_bytes = 4096` with the deployment-context wording, that is about 6 windows, where a short prompt is one. Measured on CPU with a synthetic BERT-shaped model, the worst case took 30 to 50 times as long as a short prompt.

Under steady traffic the gateway's adaptive timeout sits at its floor, `timeout_ms`. A request that takes longer passes unjudged and counts toward the breaker, so the floor has to cover the worst case, not the typical request. The client also chooses how many worst-case texts it sends at once, up to the gateway's `max_inflight`. On CPU, N of them at once take about N times as long as one, or wait for a worker and get a 503. The profile sets 500 / 800 ms: about 2.5 times 6 windows at the ~33 ms per window Laya is reported at on CPU, for one at a time. Measure your own build at your `max_inflight` (below). If the worst case does not fit the latency you can add, lower `max_judge_bytes` or `max_inflight`, add CPUs, or use a GPU (`LAYA_ORT_PROVIDERS`), where the windows of a batch run in parallel.

## Before you enforce

1. **Fine-tune on the gateway's input.** Each model input is a pair. The first segment is the question's `instructions`, then `Yes if:` / `No if:` criteria, then `assistant: …` when a deployment context is set. The second segment is a slice of the text. `question_segment()` in `laya_server.py` builds it. The exact wording the gateway sends is in [`conformance/questions.json`](../../conformance/questions.json), in both its plain and its `ctx` form. Fine-tune on that wording, or put the wording you trained on under `jev.questions` in the gateway config. That wording was validated against Jev, not Laya. The `ctx` form in particular needs its own evaluation on your data.
2. **Fit the temperature** on labelled data the model did not see in training:
   ```bash
   LAYA_BACKEND=onnx LAYA_MODEL_DIR=/path/to/finetuned \
     python3 adapters/laya-server/fit_temperature.py heldout.jsonl [--ctx]
   ```
   It prints the log loss and calibration error before and after, and the `LAYA_TEMPERATURE=` line to use. Rankings do not change, only how far the scores spread.
3. **Check the protocol and the latency** on the hardware you will run:
   ```bash
   make conformance ENDPOINT=http://laya-server:8080/v1/systemone API_KEY=change-me STRICT=1 BUDGET_MS=500
   ```
   `BUDGET_MS` is the `timeout_ms` you plan to run, and the server's `LAYA_GATEWAY_TIMEOUT_MS` should be the same. The suite times a short text and the worst case: `max_judge_bytes` of text at one token per byte, in the deployment-context wording, first one at a time and then 64 at once, like the gateway at `max_inflight`. It also opens 64 connections at once. A timing check passes only when its p99 is at most half of `BUDGET_MS`, because the gateway reads for 60% of it and the tail needs room. Every worst-case request must get a 200: a 503 is an L2 error too. The run ends with a `timeout_ms:` line, 2 to 3 times the worst-case p99 at `max_inflight`. When the server cannot answer that many at once in time, the line gives the `max_inflight` it can. Set the profile's `timeout_ms` and `max_inflight` from that line, never from the short-text p99. For a profile with a different `max_judge_bytes`, `max_inflight` or `deployment_context`, run `python3 conformance/run.py` with `--judge-bytes`, `--concurrency` and `--assistant`.
4. **Calibrate thresholds** from a monitor period. The access log carries `provider` and `model`:
   ```bash
   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv PROVIDER=laya MODEL=laya
   ```
   Give each fine-tuned build its own `jev.model` name so that its scores, cache entries and thresholds stay separate.

## Tests

```bash
make test-laya          # unit tests + the conformance suite against the mock backend
```

The suite includes negative tests. `conformance` must fail for a server that silently judges only the first window, for one whose listen backlog drops a burst of connections, for one that is fast on a short text but whose worst case is over the budget, for one that answers the worst case alone but not `max_inflight` of it at once, and for one whose 503 comes after the gateway stopped reading.
