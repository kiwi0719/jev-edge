"""laya-server: a fine-tuned Laya model behind the System One protocol.

jev-edge's `laya` provider (adapters/openresty/lib/resty/jev/providers/laya.lua,
adapters/js/src/providers/index.ts) sends

    POST /v1/systemone
    {"model": "...", "state": "<text>" | {"assistant": "...", "user_message": "..."},
     "questions": {"<name>": {"type": "noul", "instructions": "...",
                              "criteria": {"true": "...", "false": "..."}}}}

and reads {"answers": {"<name>": {"noul": p}}}. This server answers it with a
Laya model you have fine-tuned. The base model is not usable for this task
without fine-tuning, and no default thresholds or benchmark numbers ship for
it: calibrate on your own traffic (README.md).

Guarantees the gateway relies on, checked by conformance/ (make conformance):

  * every asked question is answered, with `noul` in [0, 1], and nothing else;
  * `noul` is a calibrated probability: sigmoid(logit / LAYA_TEMPERATURE),
    with the temperature fitted by fit_temperature.py on held-out labels;
  * no silent truncation: text longer than one model window is scored in
    overlapping windows and the question takes the highest score; text that
    would need more than LAYA_MAX_WINDOWS windows is refused with 413;
  * errors are JSON with a non-200 status (400, 401, 404, 405, 413, 500).

Standard library only, apart from the backend: `onnx` needs onnxruntime,
tokenizers and numpy; `python` loads your own scoring function; `mock` needs
nothing and exists for tests and conformance runs.

Configuration (environment):
  LAYA_BACKEND       onnx | python | mock                        (default onnx)
  LAYA_MODEL_DIR     onnx: directory with model.onnx and tokenizer.json (/model)
  LAYA_POSITIVE      onnx: index of the "yes" logit when the model has 2 (1)
  LAYA_SCORER        python: "module:function", see PythonBackend
  LAYA_MODEL_NAME    reported in responses                        (laya)
  LAYA_TEMPERATURE   temperature for the logit, from fit_temperature.py (1.0)
  LAYA_MAX_TOKENS    model context length in tokens               (1024)
  LAYA_WINDOW_OVERLAP tokens shared by adjacent windows           (64)
  LAYA_MAX_WINDOWS   windows per question before 413              (8)
  LAYA_MAX_BODY_BYTES request body limit                          (262144)
  LAYA_API_KEY       when set, requests need "Authorization: Bearer <key>"
  LAYA_ACCESS_LOG    0 turns off the per-request line on stderr     (1)
  LAYA_HOST, LAYA_PORT                                            (0.0.0.0, 8080)
"""

from __future__ import annotations

import hmac
import importlib
import json
import math
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PATH = "/v1/systemone"


# ---------------------------------------------------------------------------
# input format
# ---------------------------------------------------------------------------
#
# What one model input looks like. The server and fit_temperature.py build it
# the same way, and your fine-tuning data must be built the same way too: a
# model fine-tuned on a different layout scores this one badly.
#
#   first  segment (fixed):  question, criteria, and the assistant description
#   second segment (window): a slice of the text being judged


def question_segment(question: dict, assistant: str | None) -> str:
    parts = [question["instructions"]]
    crit = question.get("criteria")
    if isinstance(crit, dict):
        if crit.get("true"):
            parts.append("Yes if: " + crit["true"])
        if crit.get("false"):
            parts.append("No if: " + crit["false"])
    if assistant:
        parts.append("assistant: " + assistant)
    return "\n".join(parts)


def split_state(state) -> tuple[str | None, str]:
    """(assistant or None, text to judge) from a request's `state`."""
    if isinstance(state, str):
        return None, state
    return state["assistant"], state["user_message"]


# ---------------------------------------------------------------------------
# backends
# ---------------------------------------------------------------------------
#
# A backend knows its tokenizer and its model:
#   spans(text)            -> [(start, end), ...]  character span of each token
#   count(text)            -> int                  tokens `text` takes
#   logit(first, second)   -> float                raw "yes" logit for one input
#   pair_overhead          int                     special tokens a pair adds
# and optionally
#   logits(first, seconds) -> [float, ...]         all windows in one model call
# The server windows the judged text by token spans and hands the backend
# plain strings; it applies the temperature itself.


class OnnxBackend:
    """A sequence-pair classifier exported to ONNX with a tokenizers tokenizer."""

    def __init__(self, model_dir: str, positive: int = 1):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        self.tok = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        self.tok.no_truncation()
        self.tok.no_padding()
        self.sess = ort.InferenceSession(os.path.join(model_dir, "model.onnx"),
                                         providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.sess.get_inputs()}
        self.positive = positive
        pp = self.tok.post_processor
        self.pair_overhead = pp.num_special_tokens_to_add(True) if pp else 0
        self.pad_id = next((self.tok.token_to_id(t) for t in ("<pad>", "[PAD]", "<|pad|>")
                            if self.tok.token_to_id(t) is not None), 0)

    def spans(self, text: str):
        return self.tok.encode(text, add_special_tokens=False).offsets

    def count(self, text: str) -> int:
        return len(self.tok.encode(text, add_special_tokens=False).ids)

    def logit(self, first: str, second: str) -> float:
        return self.logits(first, [second])[0]

    def logits(self, first: str, seconds: list[str]) -> list[float]:
        # every window of a long text in one batch: a text split in N windows
        # costs about one model call, not N in a row, so the gateway's timeout
        # does not become a lever for a text built to split badly
        np = self.np
        encs = [self.tok.encode(first, s) for s in seconds]
        width = max(len(e.ids) for e in encs)
        ids = np.full((len(encs), width), self.pad_id, dtype=np.int64)
        mask = np.zeros((len(encs), width), dtype=np.int64)
        types = np.zeros((len(encs), width), dtype=np.int64)
        for i, e in enumerate(encs):
            n = len(e.ids)
            ids[i, :n], mask[i, :n], types[i, :n] = e.ids, e.attention_mask, e.type_ids
        feed = {"input_ids": ids}
        if "attention_mask" in self.inputs:
            feed["attention_mask"] = mask
        if "token_type_ids" in self.inputs:
            feed["token_type_ids"] = types
        out = np.asarray(self.sess.run(None, feed)[0]).reshape(len(encs), -1)
        if out.shape[1] == 1:
            return [float(x) for x in out[:, 0]]
        # two classes: the log-odds of "yes" over "no"
        return [float(x) for x in out[:, self.positive] - out[:, 1 - self.positive]]


class PythonBackend:
    """Your own scorer, for a Laya build that ships as a Python library.

    LAYA_SCORER="mypkg.judge:make" names a callable returning an object with
    spans / count / logit / pair_overhead as described above.
    """

    def __init__(self, spec: str):
        mod, _, fn = spec.partition(":")
        impl = getattr(importlib.import_module(mod), fn or "make")()
        self.spans, self.count, self.logit = impl.spans, impl.count, impl.logit
        if hasattr(impl, "logits"):
            self.logits = impl.logits
        self.pair_overhead = int(getattr(impl, "pair_overhead", 0))


class MockBackend:
    """No model: a token is a whitespace-separated word, and a window scores
    high exactly when it contains the word ATTACK. Deterministic, for tests
    and conformance runs; also shows whether a long text was judged whole."""

    pair_overhead = 3

    def spans(self, text: str):
        out, i, n = [], 0, len(text)
        while i < n:
            while i < n and text[i].isspace():
                i += 1
            j = i
            while j < n and not text[j].isspace():
                j += 1
            if j > i:
                out.append((i, j))
            i = j
        return out

    def count(self, text: str) -> int:
        return len(self.spans(text))

    def logit(self, first: str, second: str) -> float:
        if first.startswith("FAIL"):
            raise RuntimeError("mock backend failure")
        return 4.0 if "ATTACK" in second.split() else -4.0


def load_backend(env=os.environ):
    kind = env.get("LAYA_BACKEND", "onnx")
    if kind == "onnx":
        return OnnxBackend(env.get("LAYA_MODEL_DIR", "/model"), int(env.get("LAYA_POSITIVE", "1")))
    if kind == "python":
        return PythonBackend(env["LAYA_SCORER"])
    if kind == "mock":
        return MockBackend()
    raise SystemExit(f"LAYA_BACKEND must be onnx | python | mock, not {kind!r}")


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


class Refused(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


# Tokens kept free in every window: a slice re-tokenized next to the question
# can come out a token or two longer than its span count said.
SLACK = 8


class Scorer:
    def __init__(self, backend, temperature=1.0, max_tokens=1024, overlap=64, max_windows=8):
        if temperature <= 0:
            raise ValueError("LAYA_TEMPERATURE must be > 0")
        self.b = backend
        self.t = temperature
        self.max_tokens = max_tokens
        self.overlap = overlap
        self.max_windows = max_windows

    def windows(self, first: str, text: str) -> list[str]:
        room = self.max_tokens - self.b.pair_overhead - self.b.count(first) - SLACK
        if room <= self.overlap:
            # the question and the assistant description alone fill the model:
            # a configuration error (deployment_context too long), never a
            # reason to drop the user's text
            raise Refused(413, "question_too_long",
                          f"question and assistant description leave {max(room, 0)} of "
                          f"{self.max_tokens} tokens for the text")
        spans = self.b.spans(text)
        if len(spans) <= room:
            return [text]
        step = room - self.overlap
        need = 1 + math.ceil((len(spans) - room) / step)
        if need > self.max_windows:
            raise Refused(413, "input_too_long",
                          f"text of {len(spans)} tokens needs {need} windows of {room}; "
                          f"LAYA_MAX_WINDOWS is {self.max_windows}")
        out = []
        for k in range(need):
            a = k * step
            b = min(a + room, len(spans))
            out.append(text[spans[a][0]:spans[b - 1][1]])
        return out

    def logits(self, state, questions: dict) -> tuple[dict, dict]:
        """Raw "yes" logit per question (highest over the windows), before the
        temperature. fit_temperature.py fits on exactly these."""
        assistant, text = split_state(state)
        out, windows, tokens = {}, 0, 0
        for name, q in questions.items():
            first = question_segment(q, assistant)
            ws = self.windows(first, text)
            windows += len(ws)
            head = self.b.count(first) + self.b.pair_overhead
            tokens += sum(head + self.b.count(w) for w in ws)
            if len(ws) > 1 and hasattr(self.b, "logits"):
                out[name] = max(self.b.logits(first, ws))
            else:
                out[name] = max(self.b.logit(first, w) for w in ws)
        return out, {"input_tokens": tokens, "output_tokens": 0, "windows": windows}

    def score(self, state, questions: dict) -> tuple[dict, dict]:
        logits, usage = self.logits(state, questions)
        return {name: {"noul": round(sigmoid(x / self.t), 6)} for name, x in logits.items()}, usage


# ---------------------------------------------------------------------------
# request validation
# ---------------------------------------------------------------------------


def _nonempty_str(v) -> bool:
    return isinstance(v, str) and v != ""


def validate(req) -> None:
    if not isinstance(req, dict):
        raise Refused(400, "invalid_request", "body must be a JSON object")
    state = req.get("state")
    if isinstance(state, dict):
        if not isinstance(state.get("assistant"), str) or not isinstance(state.get("user_message"), str):
            raise Refused(400, "invalid_state", "object state needs string `assistant` and `user_message`")
    elif not isinstance(state, str):
        raise Refused(400, "invalid_state", "state must be a string or an object")
    qs = req.get("questions")
    if not isinstance(qs, dict) or not qs:
        raise Refused(400, "invalid_questions", "questions must be a non-empty object")
    for name, q in qs.items():
        if not isinstance(q, dict) or q.get("type") != "noul":
            raise Refused(400, "invalid_questions", f"question {name!r}: only type \"noul\" is supported")
        if not _nonempty_str(q.get("instructions")):
            raise Refused(400, "invalid_questions", f"question {name!r}: instructions must be a non-empty string")
        crit = q.get("criteria")
        if crit is not None and not (isinstance(crit, dict) and all(
                isinstance(crit.get(k), (str, type(None))) for k in ("true", "false"))):
            raise Refused(400, "invalid_questions", f"question {name!r}: criteria must be {{\"true\", \"false\"}} strings")
    if "model" in req and not isinstance(req["model"], str):
        raise Refused(400, "invalid_request", "model must be a string")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "laya-server"
    protocol_version = "HTTP/1.1"  # keepalive: the gateway pools connections

    # set by make_server
    scorer: Scorer
    model_name = "laya"
    api_key = None
    max_body = 262144
    lock = None  # a Lock when the backend is not thread-safe

    access_log = True

    def log_message(self, fmt, *args):  # one line per request on stderr
        if self.access_log or "error" in fmt:
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True  # the client gave up (its timeout); nothing to tell it

    def _error(self, e: Refused) -> None:
        self._send(e.status, {"error": {"code": e.code, "message": e.message}})

    def _drain(self) -> None:
        # read (and drop) a body we are refusing, so the keepalive stream stays in step
        n = int(self.headers.get("Content-Length") or 0)
        if 0 < n <= self.max_body:
            self.rfile.read(n)
        elif n > self.max_body:
            self.close_connection = True

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok", "model": self.model_name})
        if self.path == PATH:
            return self._error(Refused(405, "method_not_allowed", "use POST"))
        return self._error(Refused(404, "not_found", "no such path"))

    def do_PUT(self):
        self._drain()
        if self.path == PATH:
            return self._error(Refused(405, "method_not_allowed", "use POST"))
        return self._error(Refused(404, "not_found", "no such path"))

    do_DELETE = do_PATCH = do_PUT

    def do_POST(self):
        if self.path != PATH:
            self._drain()
            return self._error(Refused(404, "not_found", "no such path"))
        try:
            if self.api_key is not None:
                got = self.headers.get("Authorization") or ""
                if not hmac.compare_digest(got.encode(), ("Bearer " + self.api_key).encode()):
                    self._drain()
                    raise Refused(401, "unauthorized", "missing or wrong bearer token")
            try:
                n = int(self.headers.get("Content-Length") or "")
            except ValueError:
                self.close_connection = True
                raise Refused(411, "length_required", "Content-Length required") from None
            if n > self.max_body:
                self.close_connection = True
                raise Refused(413, "body_too_large", f"body over {self.max_body} bytes")
            raw = self.rfile.read(n)
            if len(raw) < n:
                # the client hung up mid-body: no one to answer
                self.close_connection = True
                return
            try:
                req = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                raise Refused(400, "invalid_json", "body is not valid JSON") from None
            validate(req)
            t0 = time.perf_counter()
            if self.lock:
                with self.lock:
                    answers, usage = self.scorer.score(req["state"], req["questions"])
            else:
                answers, usage = self.scorer.score(req["state"], req["questions"])
            usage["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            self._send(200, {"model": self.model_name, "answers": answers, "usage": usage})
        except Refused as e:
            self._error(e)
        except Exception as e:  # a backend fault: never a score
            self.log_message("backend error: %r", e)
            self._error(Refused(500, "backend_error", "the model failed to score this request"))


def make_server(env=os.environ, backend=None) -> ThreadingHTTPServer:
    backend = backend or load_backend(env)
    scorer = Scorer(
        backend,
        temperature=float(env.get("LAYA_TEMPERATURE", "1.0")),
        max_tokens=int(env.get("LAYA_MAX_TOKENS", "1024")),
        overlap=int(env.get("LAYA_WINDOW_OVERLAP", "64")),
        max_windows=int(env.get("LAYA_MAX_WINDOWS", "8")),
    )
    attrs = {
        "scorer": scorer,
        "model_name": env.get("LAYA_MODEL_NAME", "laya"),
        "api_key": env.get("LAYA_API_KEY") or None,
        "max_body": int(env.get("LAYA_MAX_BODY_BYTES", "262144")),
        "access_log": env.get("LAYA_ACCESS_LOG", "1") != "0",
        # onnxruntime sessions are thread-safe; a Python scorer may not be
        "lock": threading.Lock() if isinstance(backend, PythonBackend) else None,
    }
    handler = type("LayaHandler", (Handler,), attrs)
    srv = ThreadingHTTPServer((env.get("LAYA_HOST", "0.0.0.0"), int(env.get("LAYA_PORT", "8080"))), handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    srv = make_server()
    host, port = srv.server_address[:2]
    sys.stderr.write(f"laya-server on {host}:{port}{PATH}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
