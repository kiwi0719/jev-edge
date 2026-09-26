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
  * text that is not valid Unicode (a lone surrogate escape, invalid UTF-8)
    is judged with U+FFFD in its place, never refused;
  * load past what the server can take is answered, never dropped: the
    listen backlog is LAYA_BACKLOG, not socketserver's 5; at most
    LAYA_WORKERS requests are scored at once; a request that waits longer
    than LAYA_QUEUE_MS for a worker, and a connection past
    LAYA_MAX_CONNECTIONS, get a 503 `overloaded`;
  * a client that hangs up or stalls in the middle of its request gets an
    access-log line at most, never a backend-fault warning;
  * errors are JSON with a non-200 status (400, 401, 404, 405, 411, 413,
    500, 503).

Cost: on CPU a text split in N windows costs about N model calls. Batching
the windows saves the per-call overhead, not the per-window compute, so a
hostile text that tokenizes to one token per byte costs many times a short
one. Size the gateway's timeout floor from the worst-case line that
`make conformance` prints, not from the short-text p99 (README.md).

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
  LAYA_ORT_PROVIDERS onnx: execution providers, comma-separated, in order of
                     preference; each must be in this onnxruntime build
                                                   (CPUExecutionProvider)
  LAYA_ORT_THREADS   onnx: intra-op threads per session, 0 = onnxruntime's
                     default                                      (0)
  LAYA_WORKERS       requests scored at once       (CPU count; python: 1)
  LAYA_QUEUE_MS      wait for a free worker before 503            (1000)
  LAYA_BACKLOG       listen backlog: at least the sum of jev.max_inflight of
                     the gateways calling this server; the kernel caps it at
                     its somaxconn                                (1024)
  LAYA_MAX_CONNECTIONS open connections; one more gets 503 and is closed (1024)
  LAYA_IDLE_TIMEOUT_S a connection silent this long is closed, 0 = never;
                     keep it above the gateway's keepalive idle time (60 s)
                                                                  (120)
"""

from __future__ import annotations

import contextlib
import hmac
import importlib
import json
import math
import os
import re
import socket
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


_SURROGATE = re.compile("[\ud800-\udfff]")


def well_formed(s: str) -> str:
    """`s` with every lone UTF-16 surrogate (a JSON "\\ud800" escape, or
    invalid UTF-8 read with surrogatepass) replaced by U+FFFD. Tokenizers
    refuse a lone surrogate; a 500 for it would be an L2 error, which the
    gateway answers by passing the request unjudged."""
    return _SURROGATE.sub("\uFFFD", s)


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
    return well_formed("\n".join(parts))


def split_state(state) -> tuple[str | None, str]:
    """(assistant or None, text to judge) from a request's `state`, well formed."""
    if isinstance(state, str):
        return None, well_formed(state)
    return well_formed(state["assistant"]), well_formed(state["user_message"])


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


def ort_providers(spec: str | None, available: list[str]) -> list[str]:
    """LAYA_ORT_PROVIDERS as a list. A provider this onnxruntime build lacks
    stops the server: onnxruntime would fall back to CPU with a warning, and
    a timeout sized for a GPU would then fail open on every long text."""
    names = [p.strip() for p in (spec or "CPUExecutionProvider").split(",") if p.strip()]
    missing = [p for p in names if p not in available]
    if not names or missing:
        raise SystemExit(f"LAYA_ORT_PROVIDERS: {', '.join(missing) or 'empty'} not in this "
                         f"onnxruntime build (it has {', '.join(available)})")
    return names


class OnnxBackend:
    """A sequence-pair classifier exported to ONNX with a tokenizers tokenizer."""

    def __init__(self, model_dir: str, positive: int = 1, providers: str | None = None,
                 threads: int = 0):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        self.tok = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        self.tok.no_truncation()
        self.tok.no_padding()
        opts = ort.SessionOptions()
        if threads:
            opts.intra_op_num_threads = threads
        self.sess = ort.InferenceSession(os.path.join(model_dir, "model.onnx"), sess_options=opts,
                                         providers=ort_providers(providers, ort.get_available_providers()))
        self.providers = self.sess.get_providers()
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
        # every window of a long text in one batch. On CPU that saves the
        # per-call overhead only: N windows still cost about N times one, so
        # a text built to split into many windows costs that much more, and
        # the gateway's timeout floor must be sized from that worst case
        # (conformance/run.py measures it). A GPU provider
        # (LAYA_ORT_PROVIDERS) runs the batch in parallel.
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
        return OnnxBackend(env.get("LAYA_MODEL_DIR", "/model"), int(env.get("LAYA_POSITIVE", "1")),
                           providers=env.get("LAYA_ORT_PROVIDERS"),
                           threads=int(env.get("LAYA_ORT_THREADS") or "0"))
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



class Workers:
    """The scoring pool: at most `n` requests are scored at once.

    A request that finds every worker busy waits up to `wait_ms` for one,
    then gets 503 `overloaded`. By then the gateway has given up on it (its
    L2 timeout is under a second), and scoring it anyway would only push the
    requests queued behind it past their own timeouts.
    """

    def __init__(self, n: int, wait_ms: float):
        if n < 1:
            raise ValueError("LAYA_WORKERS must be >= 1")
        if wait_ms < 0:
            raise ValueError("LAYA_QUEUE_MS must be >= 0")
        self.n, self.wait_ms = n, wait_ms
        self.sem = threading.BoundedSemaphore(n)

    @contextlib.contextmanager
    def slot(self):
        """Holds a worker for the block; yields the ms spent waiting for it."""
        t0 = time.perf_counter()
        if not self.sem.acquire(timeout=self.wait_ms / 1000):
            raise Refused(503, "overloaded", f"all {self.n} workers busy for {self.wait_ms:g} ms "
                                             "(LAYA_WORKERS, LAYA_QUEUE_MS)")
        try:
            yield (time.perf_counter() - t0) * 1000
        finally:
            self.sem.release()


class ClientGone(ConnectionError):
    """The client hung up, or went silent past LAYA_IDLE_TIMEOUT_S, in the
    middle of its request: no one to answer, and not a backend fault."""


class Handler(BaseHTTPRequestHandler):
    server_version = "laya-server"
    protocol_version = "HTTP/1.1"  # keepalive: the gateway pools connections
    # TCP_NODELAY. An answer goes out in two writes, the headers and then the
    # body; with Nagle on, the body waits for the client to acknowledge the
    # headers, and a Linux client delays that ACK by about 40 ms: every
    # answer on a warm connection took 40 ms longer than its scoring.
    disable_nagle_algorithm = True

    # set by make_server
    scorer: Scorer
    workers: Workers
    model_name = "laya"
    api_key = None
    max_body = 262144
    timeout = 120  # LAYA_IDLE_TIMEOUT_S, applied to the socket by StreamRequestHandler

    access_log = True
    over_capacity = False  # set on a connection past LAYA_MAX_CONNECTIONS (Server)

    def log_message(self, fmt, *args):  # one line per request on stderr
        if self.access_log:
            self.warn(fmt, *args)

    def warn(self, fmt, *args):  # backend faults and overload: written even without the access log
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        try:
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            # the client hung up or stopped reading (its timeout): nothing to tell it
            self.close_connection = True

    def _error(self, e: Refused) -> None:
        if e.status == 503:
            self.warn("overloaded: %s", e.message)
        self._send(e.status, {"error": {"code": e.code, "message": e.message}})

    def _read(self, n: int) -> bytes:
        """n bytes of the request body; ClientGone when the client hangs up
        or goes silent (the socket timeout) before sending them."""
        try:
            raw = self.rfile.read(n)
        except OSError as e:  # socket.timeout, a reset
            self.close_connection = True
            raise ClientGone(f"{type(e).__name__} after the headers, reading a {n}-byte body") from None
        if len(raw) < n:
            self.close_connection = True
            raise ClientGone(f"hung up after {len(raw)} of {n} body bytes")
        return raw

    def _drain(self) -> None:
        # read (and drop) a body we are refusing, so the keepalive stream stays in step
        n = int(self.headers.get("Content-Length") or 0)
        if 0 < n <= self.max_body:
            self._read(n)
        elif n > self.max_body:
            self.close_connection = True

    def _shed(self) -> bool:
        """On a connection past LAYA_MAX_CONNECTIONS: answer 503 and close.
        Refusing it in the kernel instead would reach the gateway only when
        its connect budget runs out, as a timeout."""
        if not self.over_capacity:
            return False
        self._drain()
        self.close_connection = True
        self._error(Refused(503, "overloaded", f"over {self.server.max_connections} open "
                                               "connections (LAYA_MAX_CONNECTIONS)"))
        return True

    def do_GET(self):
        if self.path == "/healthz":  # busy is not unhealthy: probes are answered even past the cap
            self.close_connection = self.close_connection or self.over_capacity
            return self._send(200, {"status": "ok", "model": self.model_name})
        if self._shed():
            return
        if self.path == PATH:
            return self._error(Refused(405, "method_not_allowed", "use POST"))
        return self._error(Refused(404, "not_found", "no such path"))

    def do_PUT(self):
        if self._shed():
            return
        self._drain()
        if self.path == PATH:
            return self._error(Refused(405, "method_not_allowed", "use POST"))
        return self._error(Refused(404, "not_found", "no such path"))

    do_DELETE = do_PATCH = do_PUT

    def do_POST(self):
        if self._shed():
            return
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
            raw = self._read(n)
            try:
                try:
                    req = json.loads(raw)
                except UnicodeDecodeError:
                    # invalid UTF-8 from the client, passed on by a gateway:
                    # read as U+FFFD, as Go and Node do (a 400 would pass it)
                    req = json.loads(raw.decode("utf-8-sig", "replace"))
            except ValueError:
                raise Refused(400, "invalid_json", "body is not valid JSON") from None
            validate(req)
            with self.workers.slot() as waited:
                t0 = time.perf_counter()
                answers, usage = self.scorer.score(req["state"], req["questions"])
                usage["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            usage["wait_ms"] = round(waited, 2)
            self._send(200, {"model": self.model_name, "answers": answers, "usage": usage})
        except Refused as e:
            self._error(e)
        except ClientGone as e:
            # the client's side, not the model's: an access-log line at most
            self.log_message("client gone mid-request: %s", e)
        except Exception as e:  # a backend fault: never a score
            self.warn("backend error: %r", e)
            self._error(Refused(500, "backend_error", "the model failed to score this request"))


class Server(ThreadingHTTPServer):
    """ThreadingHTTPServer with a real listen backlog and a connection cap.

    socketserver listens with a backlog of 5. The gateway opens up to
    jev.max_inflight connections at once (64 in the Laya profile); the kernel
    drops a connection past the backlog, the gateway's connect budget (30% of
    its L2 timeout) runs out before the client retries the SYN, and the call
    is an L2 error that passes the request unjudged. About 20 of those open
    the breaker, which skips L2 for every tenant. So the backlog is
    LAYA_BACKLOG, and a connection past LAYA_MAX_CONNECTIONS is still
    accepted and answered 503: the gateway sees that at once, and this
    server's log says why.
    """

    daemon_threads = True

    def __init__(self, address, handler, backlog: int = 1024, max_connections: int = 1024):
        if backlog < 1:
            raise ValueError("LAYA_BACKLOG must be >= 1")
        if max_connections < 1:
            raise ValueError("LAYA_MAX_CONNECTIONS must be >= 1")
        self.request_queue_size = backlog  # server_activate listens with it
        self.max_connections = max_connections
        self.connections = 0
        self._count = threading.Lock()
        self.shed_handler = type(handler.__name__ + "Shed", (handler,), {"over_capacity": True})
        super().__init__(address, handler)

    def process_request_thread(self, request, client_address):
        with self._count:
            self.connections += 1
            over = self.connections > self.max_connections
        try:
            (self.shed_handler if over else self.RequestHandlerClass)(request, client_address, self)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            with self._count:
                self.connections -= 1
            self.shutdown_request(request)

    def handle_error(self, request, client_address):
        # a client that hung up or went silent (the gateway's timeout, or
        # LAYA_IDLE_TIMEOUT_S) is not a server fault: no traceback for it
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError, socket.timeout)):
            return
        super().handle_error(request, client_address)


def somaxconn() -> int | None:
    """The kernel's cap on a listen backlog, where it can be read (Linux)."""
    try:
        with open("/proc/sys/net/core/somaxconn") as f:
            return int(f.read())
    except (OSError, ValueError):
        return None


def make_server(env=os.environ, backend=None) -> Server:
    backend = backend or load_backend(env)
    scorer = Scorer(
        backend,
        temperature=float(env.get("LAYA_TEMPERATURE", "1.0")),
        max_tokens=int(env.get("LAYA_MAX_TOKENS", "1024")),
        overlap=int(env.get("LAYA_WINDOW_OVERLAP", "64")),
        max_windows=int(env.get("LAYA_MAX_WINDOWS", "8")),
    )
    # onnxruntime sessions are thread-safe; a Python scorer may not be, so it
    # gets one worker unless LAYA_WORKERS says it can take more
    default_workers = 1 if isinstance(backend, PythonBackend) else (os.cpu_count() or 1)
    attrs = {
        "scorer": scorer,
        "workers": Workers(int(env.get("LAYA_WORKERS") or default_workers),
                           float(env.get("LAYA_QUEUE_MS", "1000"))),
        "model_name": env.get("LAYA_MODEL_NAME", "laya"),
        "api_key": env.get("LAYA_API_KEY") or None,
        "max_body": int(env.get("LAYA_MAX_BODY_BYTES", "262144")),
        "access_log": env.get("LAYA_ACCESS_LOG", "1") != "0",
        "timeout": float(env.get("LAYA_IDLE_TIMEOUT_S", "120")) or None,
    }
    handler = type("LayaHandler", (Handler,), attrs)
    return Server((env.get("LAYA_HOST", "0.0.0.0"), int(env.get("LAYA_PORT", "8080"))), handler,
                  backlog=int(env.get("LAYA_BACKLOG", "1024")),
                  max_connections=int(env.get("LAYA_MAX_CONNECTIONS", "1024")))


def main() -> None:
    srv = make_server()
    host, port = srv.server_address[:2]
    h = srv.RequestHandlerClass
    providers = getattr(h.scorer.b, "providers", None)
    sys.stderr.write(f"laya-server on {host}:{port}{PATH}: {h.workers.n} workers, "
                     f"backlog {srv.request_queue_size}, at most {srv.max_connections} connections"
                     + (f", providers {','.join(providers)}" if providers else "") + "\n")
    cap = somaxconn()
    if cap is not None and cap < srv.request_queue_size:
        sys.stderr.write(f"laya-server: the kernel caps the listen backlog at {cap} "
                         f"(net.core.somaxconn), under LAYA_BACKLOG={srv.request_queue_size}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
