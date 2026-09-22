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

## What the server guarantees

- **Protocol.** `POST /v1/systemone` with `{model, state, questions}`, where `state` is a string or `{assistant, user_message}` and each question is `{type: "noul", instructions, criteria?}`. The response is `{model, answers: {<name>: {noul}}, usage}`. Every asked question gets an answer and no other question does. `GET /healthz` is for probes.
- **No silent truncation.** The model sees at most `LAYA_MAX_TOKENS`. Longer text is scored in overlapping windows that cover all of it, in one batch, and the question takes the highest window score. Text that would need more than `LAYA_MAX_WINDOWS` windows is refused with `413 input_too_long`. A question plus deployment context that leaves no room for text is refused with `413 question_too_long`: this is a configuration error, and the user's text is never dropped to make room.
- **Errors.** Every error is JSON `{error: {code, message}}` with a non-200 status: 400 for a malformed request, 401 for auth, 404, 405, 411, 413, and 500 when the model fails. An error is never returned as a score.

An L2 error lets the request through (fail open). The profile's `max_judge_bytes = 4096` is sized so the gateway never sends a text that needs the 413. See the comment in [`jev-laya.conf.lua`](jev-laya.conf.lua).

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
   make conformance ENDPOINT=http://laya-server:8080/v1/systemone API_KEY=change-me STRICT=1 BUDGET_MS=300
   ```
   Then set `timeout_ms` / `timeout_max_ms` in the profile from the p50 / p99 it prints.
4. **Calibrate thresholds** from a monitor period. The access log carries `provider` and `model`:
   ```bash
   make calibrate LOG=/var/log/nginx/jev.log LABELS=labels.csv PROVIDER=laya MODEL=laya
   ```
   Give each fine-tuned build its own `jev.model` name so that its scores, cache entries and thresholds stay separate.

## Tests

```bash
make test-laya          # unit tests + the conformance suite against the mock backend
```

The suite includes a negative test: a server that silently judges only the first window must fail `conformance`.
