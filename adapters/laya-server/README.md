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
| `LAYA_ORT_THREADS` | `0` | onnx: intra-op threads per session; `0` leaves onnxruntime's default |
| `LAYA_WORKERS` | CPU count | requests scored at once. `python` defaults to `1`, because your scorer may not be thread-safe |
| `LAYA_QUEUE_MS` | `1000` | how long a request waits for a free worker before `503 overloaded` |
| `LAYA_BACKLOG` | `1024` | listen backlog: at least the sum of `jev.max_inflight` over the gateways that call this server. The kernel caps it (`net.core.somaxconn` on Linux, logged at start when lower) |
| `LAYA_MAX_CONNECTIONS` | `1024` | open connections; the next one is answered `503 overloaded` and closed |
| `LAYA_IDLE_TIMEOUT_S` | `120` | a connection silent this long is closed, `0` never. Keep it above the gateway's keepalive idle time (60 s) |

## What the server guarantees

- **Protocol.** `POST /v1/systemone` with `{model, state, questions}`, where `state` is a string or `{assistant, user_message}` and each question is `{type: "noul", instructions, criteria?}`. The response is `{model, answers: {<name>: {noul}}, usage}`. Every asked question gets an answer and no other question does. `GET /healthz` is for probes.
- **No silent truncation.** The model sees at most `LAYA_MAX_TOKENS`. Longer text is scored in overlapping windows that cover all of it, in one batch, and the question takes the highest window score. Text that would need more than `LAYA_MAX_WINDOWS` windows is refused with `413 input_too_long`. A question plus deployment context that leaves no room for text is refused with `413 question_too_long`: this is a configuration error, and the user's text is never dropped to make room.
- **Load is answered, never dropped.** The listen backlog is `LAYA_BACKLOG`, not the 5 that Python's `socketserver` uses. The gateway opens up to `jev.max_inflight` connections at once (64 in the profile), and the kernel drops a connection past the backlog. The gateway's connect budget runs out before the SYN is retried, so each drop is an L2 timeout, and enough of them open the breaker for every tenant. At most `LAYA_WORKERS` requests are scored at once. A request that waits more than `LAYA_QUEUE_MS` for a worker, or a connection past `LAYA_MAX_CONNECTIONS`, gets `503 overloaded`, and this server logs it even with the access log off. A 503 still lets the request through at the gateway, so size the server for the load. `usage.wait_ms` in each answer is the time the request waited for a worker.
- **Errors.** Every error is JSON `{error: {code, message}}` with a non-200 status: 400 for a malformed request, 401 for auth, 404, 405, 411, 413, 500 when the model fails, and 503 when overloaded. An error is never returned as a score.

An L2 error lets the request through (fail open). The profile's `max_judge_bytes = 4096` is sized so the gateway never sends a text that needs the 413. See the comment in [`jev-laya.conf.lua`](jev-laya.conf.lua).

## Latency grows with windows

On CPU, a text split into N windows costs about N model calls. The windows go to the model in one batch, and that saves the per-call overhead but not the compute. A hostile text can be built to tokenize at about one token per byte (punctuation, rare letters). At `max_judge_bytes = 4096` with the deployment-context wording, that is about 6 windows, where a short prompt is one. Measured on CPU with a synthetic BERT-shaped model, the worst case took 30 to 50 times as long as a short prompt.

Under steady traffic the gateway's adaptive timeout sits at its floor, `timeout_ms`. A request that takes longer passes unjudged and counts toward the breaker, so the floor has to cover the worst case, not the typical request. The profile sets 500 / 800 ms: about 2.5 times 6 windows at the ~33 ms per window Laya is reported at on CPU. Measure your own build (below). If the worst case does not fit the latency you can add, lower `max_judge_bytes`, or use a GPU (`LAYA_ORT_PROVIDERS`), where the windows of a batch run in parallel.

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
   `BUDGET_MS` is the `timeout_ms` you plan to run. The suite times a short text and the worst case: `max_judge_bytes` of text at one token per byte, in the deployment-context wording. It also opens 64 connections at once, like the gateway at `max_inflight`. It ends with a `timeout_ms:` line, which is 2 to 3 times the worst-case p99. Set the profile's `timeout_ms` from that line, never from the short-text p99. For a profile with a different `max_judge_bytes`, `max_inflight` or `deployment_context`, run `python3 conformance/run.py` with `--judge-bytes`, `--concurrency` and `--assistant`.
4. **Calibrate thresholds** from a monitor period. The access log carries `provider` and `model`:
   ```bash
   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv PROVIDER=laya MODEL=laya
   ```
   Give each fine-tuned build its own `jev.model` name so that its scores, cache entries and thresholds stay separate.

## Tests

```bash
make test-laya          # unit tests + the conformance suite against the mock backend
```

The suite includes negative tests. `conformance` must fail for a server that silently judges only the first window, for one whose listen backlog drops a burst of connections, and for one that is fast on a short text but whose worst case is over the budget.
