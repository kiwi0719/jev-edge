# Protocol conformance

The golden vectors in `core/golden/` pin down what core decides. These vectors pin down the **System One protocol as jev-edge speaks it**, so that any judge server can be checked against the requests the gateway actually sends. That covers TypeSafe's API as well as [laya-server](../adapters/laya-server/README.md) or anything else you point the `jev` or `laya` provider at. "Same format as Jev" is then something a test checks instead of something a vendor claims, and a server that drifts from the protocol later fails the test.

```
make conformance ENDPOINT=<url> [API_KEY=...] [MODEL=laya] [STRICT=1] [MOCK=1] [BUDGET_MS=250]
make conformance-vectors    regenerate vectors.json and questions.json (after a template or provider change)
make conformance-check      fail if the committed files are stale (part of `make check`)
```

`BUDGET_MS` is the L2 timeout floor the gateway runs with, `jev.timeout_ms`. `run.py` also takes `--judge-bytes` (default 4096, the profile's `max_judge_bytes`), `--concurrency` (default 64, `jev.max_inflight`) and `--assistant` (your `deployment_context`) for the load and worst-case checks below.

## Files

| file | |
|---|---|
| `gen.lua` | builds every request body with the real provider (`providers/jev.lua`) and the real templates. The expectations are written by hand |
| `vectors.json` | the cases: `input` (method, path, and a `body`, a `raw` body, or a `long` text built at run time) and `expect` |
| `questions.json` | the exact question wording the gateway sends, plain and with a deployment context. Fine-tuning data and `fit_temperature.py` use it |
| `run.py` | replays the vectors against a live server and runs the transport checks. Standard library only |

## What is checked

- **Answers**: an `answers` object with exactly the asked question names, including a name the server has never seen. Each answer is `{noul}` with a number in [0, 1], never NaN and never a boolean. `usage`, if present, is an object. The same request twice gives the same score.
- **State**: a string, or `{assistant, user_message}` with the `_ctx` wording; also unicode, control characters and empty text.
- **Errors**: malformed JSON, a wrong top-level type, missing, empty or unknown-type questions, bad state, an unknown path and the wrong method. Each must return a non-200 status and must not return `answers`. By default any 4xx passes where a 4xx is expected. `STRICT=1` requires the exact codes this suite picked (400, 404, 405, 413). laya-server is held to strict.
- **Long input**: text far beyond one model context must be either judged whole or refused, never cut. `MOCK=1` (laya-server with `LAYA_BACKEND=mock`) proves the "judged whole" part: an attack marker at the head or at the tail of the long text must score high.
- **Transport**: two requests on one keepalive connection; a missing or wrong key refused (with `API_KEY`); five clients that send half a body and hang up must not wedge the server; one client stalled mid-request must not block others.
- **Load**: 64 new connections at once, as the gateway opens them at `max_inflight` when its keepalive pool is cold. Each must connect within the gateway's connect budget (30% of `BUDGET_MS`) and get a 200 within `BUDGET_MS`. A server whose listen backlog is smaller than the burst drops connections. The client retries a dropped SYN only after about a second, so the gateway sees a timeout, passes the request, and counts a breaker failure.
- **Latency**: p99 over 50 sequential short requests must fit `BUDGET_MS`. So must the **worst case**: 50 requests with the longest text the gateway sends (`--judge-bytes`), made of punctuation and rare letters so that it costs about one token per byte, in the deployment-context wording. It must get a 200, because a 413 for a text the gateway sends is a bypass. On CPU a text split into N windows costs about N model calls, so the worst case can be tens of times the short one. Under steady traffic the gateway's adaptive timeout sits at its floor, so the floor has to cover the worst case. The run ends with a `timeout_ms:` line: 2 to 3 times the worst-case p99. Set the floor from that line, not from the short-text p99.

## What is not checked

Accuracy. A server can conform and still judge badly. The base Laya model is not usable for this task without fine-tuning, and no Laya benchmark ships. Measure your fine-tuned build on your own labelled data (`fit_temperature.py`, then `make calibrate`).
