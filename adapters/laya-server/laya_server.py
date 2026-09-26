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
    LAYA_WORKERS requests are scored at once, the others wait their turn
    for as long as they can still be answered in time (Workers); a request
    that cannot, and a connection past LAYA_MAX_CONNECTIONS, get a 503
    `overloaded` while the gateway still reads;
  * a client that hangs up or stalls in the middle of its request gets an
    access-log line at most, never a backend-fault warning;
  * errors are JSON with a non-200 status (400, 401, 404, 405, 411, 413,
    500, 503).

Cost: on CPU a text split in N windows costs about N model calls. Batching
the windows saves the per-call overhead, not the per-window compute, so a
hostile text that tokenizes to one token per byte costs many times a short
one, and max_inflight of them at once cost more again. Size the gateway's
timeout floor and max_inflight from the worst-case line that
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
  LAYA_ORT_THREADS   onnx: threads in the model's intra-op pool, which the
                     requests being scored share; 0 = onnxruntime's own
                     choice, one per core of the host
                     (CPUs / LAYA_WORKERS; neither set: CPUs / 2, at most 4)
  LAYA_WORKERS       requests scored at once
                     (onnx: CPUs / LAYA_ORT_THREADS; mock: CPUs; python: 1)
  LAYA_GATEWAY_TIMEOUT_MS the jev.timeout_ms of the gateways calling this
                     server (the lowest, if they differ). A request waits
                     for a worker only while it can still be answered
                     within half of it; otherwise it gets 503 (Workers)
                                                   (500, the Laya profile's)
  LAYA_BACKLOG       listen backlog: at least the sum of jev.max_inflight of
                     the gateways calling this server; the kernel caps it at
                     its somaxconn                                (1024)
  LAYA_MAX_CONNECTIONS open connections; one more gets 503 and is closed (1024)
  LAYA_IDLE_TIMEOUT_S a connection silent this long is closed, 0 = never;
                     keep it above the gateway's keepalive idle time (60 s)
                                                                  (120)

CPUs means the CPUs this process may use: the ones it may run on
(sched_getaffinity), capped by the container's CPU quota (cgroup cpu.max),
not the host's count. By default LAYA_WORKERS x LAYA_ORT_THREADS stays
within them (pool_sizes), and the server says at start what it chose.
"""

from __future__ import annotations

import collections
import contextlib
import heapq
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
        # threads: the session's intra-op pool. Requests scored at once
        # share it, each adding its own calling thread. 0 = onnxruntime's
        # own choice, which counts the host's cores, not a container's quota
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


def load_backend(env=os.environ, threads: int | None = None):
    """The backend LAYA_BACKEND names. threads: onnxruntime's intra-op
    threads, by default pool_sizes' for the CPUs this process may use."""
    kind = env.get("LAYA_BACKEND", "onnx")
    if kind == "onnx":
        if threads is None:
            threads = pool_sizes("onnx", env, cpu_budget()[0])[1]
        return OnnxBackend(env.get("LAYA_MODEL_DIR", "/model"), int(env.get("LAYA_POSITIVE", "1")),
                           providers=env.get("LAYA_ORT_PROVIDERS"), threads=threads)
    if kind == "python":
        return PythonBackend(env["LAYA_SCORER"])
    if kind == "mock":
        return MockBackend()
    raise SystemExit(f"LAYA_BACKEND must be onnx | python | mock, not {kind!r}")


# ---------------------------------------------------------------------------
# CPUs
# ---------------------------------------------------------------------------
#
# os.cpu_count() is the host's count. In a container limited to 2 CPUs on a
# 64-core host it said 64: 64 workers, each running onnxruntime with its
# default pool of one thread per host core, all taking turns on 2 CPUs, so
# every request in flight slowed down together, past the gateway's timeout.


def _cpu_max(d: str) -> float | None:
    # cgroup v2: "max 100000" (no quota) or "<quota> <period>"
    try:
        with open(os.path.join(d, "cpu.max")) as f:
            quota, period = f.read().split()[:2]
        return None if quota == "max" else int(quota) / int(period)
    except (OSError, ValueError):
        return None


def _cfs_quota(d: str) -> float | None:
    # cgroup v1: cpu.cfs_quota_us is -1 without a quota
    try:
        with open(os.path.join(d, "cpu.cfs_quota_us")) as f:
            quota = int(f.read())
        with open(os.path.join(d, "cpu.cfs_period_us")) as f:
            period = int(f.read())
        return None if quota <= 0 or period <= 0 else quota / period
    except (OSError, ValueError):
        return None


def cgroup_cpus(root: str = "/sys/fs/cgroup", proc: str = "/proc/self/cgroup") -> float | None:
    """The CPUs the cgroup CPU quota allows this process: the lowest quota
    over its cgroup and each parent (v2 cpu.max; v1 cpu.cfs_quota_us over
    cpu.cfs_period_us). None without a quota or without cgroups (not Linux)."""
    try:
        with open(proc) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    best = None
    for line in lines:
        hid, ctrls, path = (line.split(":", 2) + ["", ""])[:3]
        if hid == "0" and not ctrls:
            mounts, read = [root], _cpu_max
        elif "cpu" in ctrls.split(","):
            mounts, read = [os.path.join(root, ctrls), os.path.join(root, "cpu")], _cfs_quota
        else:
            continue
        # a container sees its own cgroup at the mount point, whatever the
        # path says; a process on the host is at mount/path under parents
        parts = [p for p in path.split("/") if p and p != ".."]
        for m in mounts:
            for i in range(len(parts), -1, -1):
                q = read(os.path.join(m, *parts[:i]))
                if q is not None and (best is None or q < best):
                    best = q
    return best


def cpu_budget(root: str = "/sys/fs/cgroup", proc: str = "/proc/self/cgroup") -> tuple[int, str]:
    """(CPUs this process may use, where that number comes from): the CPUs
    it may run on, capped by the cgroup quota rounded down, at least 1.
    Rounded down because threads past a fractional quota are throttled for
    the rest of each period, which is latency the gateway waits for."""
    try:
        n, src = len(os.sched_getaffinity(0)), "CPUs this process may run on"
    except (AttributeError, OSError):  # not Linux
        n, src = os.cpu_count() or 1, "CPUs of the host"
    q = cgroup_cpus(root, proc)
    if q is not None and max(1, int(q)) < n:
        return max(1, int(q)), f"cgroup CPU quota {q:g}, of {n} {src}"
    return n, src


# onnxruntime's intra-op threads when neither LAYA_WORKERS nor
# LAYA_ORT_THREADS is set: half the CPUs, up to this. A transformer gains
# little per thread past a few (the worst-case text on a MiniLM-sized model,
# 10 CPUs: 4 threads took about two thirds of the time 1 did, 10 about as
# long as 1), and the rest of the CPUs score more requests at once.
ORT_THREADS_DEFAULT_MAX = 4


def _count_env(env, name: str) -> int | None:
    v = env.get(name)
    if v is None or v == "":
        return None
    n = int(v)
    if n < 0:
        raise ValueError(f"{name} must be >= 0")
    return n


def pool_sizes(kind: str, env, cpus: int) -> tuple[int, int]:
    """(workers, onnxruntime intra-op threads; 0 when unused).

    onnx keeps workers x threads within `cpus`. The requests being scored
    share the session's pool of `threads`, each adding its own worker
    thread, so at most workers + threads - 1 threads compute at once; the
    product bound keeps that within the CPUs with room to spare for the
    Python side (tokenizing, HTTP). Past the CPUs, the requests in flight
    take turns and all of them slow down together, and a timeout at the
    gateway passes the request unjudged.

    With neither LAYA_WORKERS nor LAYA_ORT_THREADS set, threads is half the
    CPUs up to ORT_THREADS_DEFAULT_MAX, so the worst-case text alone stays
    fast and, from two CPUs on, at least two requests are scored at once: a
    short text is not stuck behind a long one. Set one and the other
    divides the CPUs by it. LAYA_ORT_THREADS=0 hands the choice to
    onnxruntime, which counts the host's cores, and gets one worker.

    mock gets one worker per CPU. python gets one, because your scorer may
    not be thread-safe."""
    workers, threads = _count_env(env, "LAYA_WORKERS"), _count_env(env, "LAYA_ORT_THREADS")
    if kind != "onnx":
        return (workers if workers is not None else 1 if kind == "python" else cpus), 0
    if threads is None:
        threads = (min(ORT_THREADS_DEFAULT_MAX, max(1, cpus // 2)) if workers is None
                   else max(1, cpus // max(1, workers)))
    if workers is None:
        workers = max(1, cpus // (threads or cpus))
    return workers, threads


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


_SYMBOL = re.compile(r"[^\w\s]")


def _approx_tokens(s: str) -> int:
    return len(s.encode("utf-8", "replace")) // 4 + len(_SYMBOL.findall(s))


def cost_units(state, questions: dict) -> int:
    """About the tokens a request makes the model read, without the
    tokenizer: one per 4 bytes, plus one per punctuation mark or symbol, of
    the text and of each question's wording. A short prompt comes to a few
    hundred, the worst case (conformance/run.py) to several thousand, and a
    prose text of the same size to about a third of that, like their real
    token counts. The tokenizer would give the exact count, and with it the
    windows, but it holds the GIL: tokenized before queueing, 64 worst-case
    texts at once took over 100 ms one after the other, and their 503s came
    after the gateway had stopped reading. This takes microseconds.
    CostModel learns the ms per unit from the scorings themselves."""
    assistant, text = split_state(state)
    t = _approx_tokens(text)
    return sum(t + _approx_tokens(question_segment(q, assistant)) for q in questions.values())


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



# The gateway waits for the answer 60% of its L2 timeout (resty/jev/http.lua:
# connect 30%, send 10%, read 60%): 300 ms at the Laya profile's floor,
# timeout_ms = 500 (jev-laya.conf.lua). Past it the gateway has given up: a
# 503 sent later reaches no one, the gateway logs a timeout instead, and a
# request scored later spends a worker on an answer no one reads.
READ_SHARE = 0.6
# LAYA_GATEWAY_TIMEOUT_MS by default: the profile's timeout_ms.
GATEWAY_TIMEOUT_MS_DEFAULT = 500
# Workers answers within this share of it: the 2x headroom conformance
# passes a server at (conformance/run.py). The last 10% before the gateway
# stops reading is room for a scoring that takes longer than its estimate,
# and for the network.
ANSWER_SHARE = 0.5


class CostModel:
    """What a request costs to score, in ms, from its size in cost_units:
    ms per unit, learned for each size class (requests within a factor of 2
    of each other) from the scorings this server ran, under its own load.

    Per class, because the time per unit is not the same at every size: a
    short prompt is one window with room to spare, the worst case several
    full ones, and within a window the model's time grows faster than the
    tokens. A class not seen yet takes the rate of the nearest one seen, so
    a size larger than any seen is priced low until it has been scored
    once. 0 until the first scoring.

    A scoring slower than its class's rate moves the rate half way to it,
    a faster one a tenth of the way: when the server slows down (a full
    pool, a noisy neighbour) an estimate that lags sends answers after the
    gateway stops reading, while one that lags on the way back only
    refuses a little early."""

    SLOWER, FASTER = 0.5, 0.1  # weight of the newest scoring against the class's rate

    def __init__(self):
        self.rate = {}  # size class -> ms per unit

    @staticmethod
    def size_class(units: float) -> int:
        return int(units).bit_length()  # class k: [2^(k-1), 2^k)

    def observe(self, units: float, ms: float) -> None:
        if units <= 0:
            return
        k, r = self.size_class(units), ms / units
        old = self.rate.get(k)
        w = self.SLOWER if old is None or r > old else self.FASTER
        self.rate[k] = r if old is None else old + (r - old) * w

    def estimate(self, units: float) -> float:
        if not self.rate or units <= 0:
            return 0.0
        k = self.size_class(units)
        near = min(self.rate, key=lambda j: (abs(j - k), -j))  # a tie goes to the larger, dearer class
        return self.rate[near] * units


class _Turn:
    """One request's turn at the pool."""

    __slots__ = ("est", "end", "ready")

    def __init__(self, est: float):
        self.est = est                  # its expected scoring time, ms
        self.end = 0.0                  # when that ends, once it has a worker (perf_counter)
        self.ready = threading.Event()  # set when it has a worker


class Workers:
    """The scoring pool: at most `n` requests are scored at once, and the
    others wait their turn, first come first served, for as long as they
    can still be answered in time.

    In time is within `answer_ms` of the request's arrival (ANSWER_SHARE of
    LAYA_GATEWAY_TIMEOUT_MS: 250 ms at the profile's floor). On arrival a
    request's own scoring time is estimated from its size (cost_units,
    CostModel), and so is its wait: the requests being scored and queued
    ahead of it, each taking its estimate. When the wait and its own time
    do not fit, it gets 503 `overloaded` at once. When they fit, it waits
    for a worker up to answer_ms minus its own time, and gets the 503 then
    if none came. A short text needs a few ms of scoring, so a burst of
    them is served from the queue; the longest text needs most of the
    budget, so behind others it is refused at once. Every 503 comes before
    the gateway stops reading and, as far as the estimates hold, no worker
    is spent on an answer that would come after it. A request that finds a
    worker free is scored at once, whatever its estimate: no one is waiting
    for that worker.
    """

    def __init__(self, n: int, answer_ms: float, cost: CostModel | None = None):
        if n < 1:
            raise ValueError("LAYA_WORKERS must be >= 1")
        if answer_ms <= 0:
            raise ValueError("LAYA_GATEWAY_TIMEOUT_MS must be > 0")
        self.n, self.answer_ms = n, answer_ms
        self.cost = cost or CostModel()
        self._lock = threading.Lock()
        self._free = n
        self._running: set = set()
        self._queue: collections.deque = collections.deque()  # waiting turns, oldest first

    def _start(self, turn: _Turn, now: float) -> None:
        # under the lock: `turn` takes a worker
        turn.end = now + turn.est / 1000
        self._running.add(turn)
        turn.ready.set()

    def _wait_ms(self, now: float) -> float:
        # under the lock, every worker busy: how long a request queued now
        # waits, when the ones scoring and queued take their estimates
        free_at = [max(0.0, (t.end - now) * 1000) for t in self._running]
        heapq.heapify(free_at)
        for t in self._queue:
            heapq.heapreplace(free_at, free_at[0] + t.est)
        return free_at[0]

    @contextlib.contextmanager
    def slot(self, units: float = 0, since: float | None = None):
        """Holds a worker for the block; yields the ms spent waiting for it.
        units: the request's size (cost_units); since: when it arrived, by
        perf_counter (default now)."""
        now = time.perf_counter()
        left = self.answer_ms - (now - (now if since is None else since)) * 1000
        with self._lock:
            turn = _Turn(self.cost.estimate(units))
            if self._free:
                self._free -= 1
                self._start(turn, now)
            else:
                wait = self._wait_ms(now)
                if wait + turn.est > left:
                    raise Refused(503, "overloaded",
                                  f"all {self.n} workers busy: about {wait:.0f} ms of waiting and "
                                  f"{turn.est:.0f} ms of scoring, over the {left:.0f} ms left to answer in "
                                  "(LAYA_WORKERS, LAYA_GATEWAY_TIMEOUT_MS)")
                self._queue.append(turn)
        if not turn.ready.wait(max(0.0, left - turn.est) / 1000):
            with self._lock:
                if not turn.ready.is_set():
                    self._queue.remove(turn)
                    raise Refused(503, "overloaded",
                                  f"all {self.n} workers still busy after "
                                  f"{(time.perf_counter() - now) * 1000:.0f} ms, too late for {turn.est:.0f} ms "
                                  f"of scoring in the {left:.0f} ms left to answer in "
                                  "(LAYA_WORKERS, LAYA_GATEWAY_TIMEOUT_MS)")
        t0 = time.perf_counter()
        scored = False
        try:
            yield (t0 - now) * 1000
            scored = True
        finally:
            ms = (time.perf_counter() - t0) * 1000
            with self._lock:
                self._running.discard(turn)
                if scored:
                    self.cost.observe(units, ms)
                if self._queue:
                    self._start(self._queue.popleft(), time.perf_counter())
                else:
                    self._free += 1


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

    def _content_length(self) -> int | None:
        """The body's length, or None when Content-Length is missing, sent
        twice with different values, or anything but ASCII digits. int()
        alone takes "-1", and rfile.read(-1) reads until the client closes,
        past LAYA_MAX_BODY_BYTES; it takes "+5", "1_0" and digits of other
        scripts too, which no gateway sends."""
        vals = {v.strip(" \t") for v in self.headers.get_all("Content-Length") or ()}
        if len(vals) != 1:
            return None
        v = vals.pop()
        return int(v) if v and v.isascii() and v.isdigit() else None

    def _drain(self) -> None:
        """Read (and drop) a body we are refusing, so the keepalive stream
        stays in step; a body too large, or of a length we cannot read,
        closes the connection instead. Never raises but ClientGone."""
        if self.headers.get("Content-Length") is None:
            return
        n = self._content_length()
        if n is None or n > self.max_body:
            self.close_connection = True
        elif n > 0:
            self._read(n)

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
            n = self._content_length()
            if n is None:
                self.close_connection = True
                raise Refused(411, "length_required", "Content-Length required")
            if n > self.max_body:
                self.close_connection = True
                raise Refused(413, "body_too_large", f"body over {self.max_body} bytes")
            raw = self._read(n)
            received = time.perf_counter()  # the gateway's read wait runs from here on
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
            with self.workers.slot(cost_units(req["state"], req["questions"]), since=received) as waited:
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


def make_server(env=os.environ, backend=None, cpus: tuple[int, str] | None = None) -> Server:
    """cpus: (count, where it comes from), by default cpu_budget()."""
    cpus = cpus or cpu_budget()
    if backend is None:
        kind = env.get("LAYA_BACKEND", "onnx")
    else:
        kind = ("onnx" if isinstance(backend, OnnxBackend) else
                "python" if isinstance(backend, PythonBackend) else "mock")
    workers, threads = pool_sizes(kind, env, cpus[0])
    gateway_timeout_ms = float(env.get("LAYA_GATEWAY_TIMEOUT_MS") or GATEWAY_TIMEOUT_MS_DEFAULT)
    backend = backend or load_backend(env, threads=threads)
    scorer = Scorer(
        backend,
        temperature=float(env.get("LAYA_TEMPERATURE", "1.0")),
        max_tokens=int(env.get("LAYA_MAX_TOKENS", "1024")),
        overlap=int(env.get("LAYA_WINDOW_OVERLAP", "64")),
        max_windows=int(env.get("LAYA_MAX_WINDOWS", "8")),
    )
    attrs = {
        "scorer": scorer,
        "workers": Workers(workers, ANSWER_SHARE * gateway_timeout_ms),
        "model_name": env.get("LAYA_MODEL_NAME", "laya"),
        "api_key": env.get("LAYA_API_KEY") or None,
        "max_body": int(env.get("LAYA_MAX_BODY_BYTES", "262144")),
        "access_log": env.get("LAYA_ACCESS_LOG", "1") != "0",
        "timeout": float(env.get("LAYA_IDLE_TIMEOUT_S", "120")) or None,
    }
    handler = type("LayaHandler", (Handler,), attrs)
    srv = Server((env.get("LAYA_HOST", "0.0.0.0"), int(env.get("LAYA_PORT", "8080"))), handler,
                 backlog=int(env.get("LAYA_BACKLOG", "1024")),
                 max_connections=int(env.get("LAYA_MAX_CONNECTIONS", "1024")))
    srv.cpus, srv.cpu_source, srv.ort_threads = cpus[0], cpus[1], threads if kind == "onnx" else None
    srv.gateway_timeout_ms = gateway_timeout_ms
    return srv


def startup_lines(srv: Server) -> list[str]:
    """What main() writes to stderr before serving: the sizes in effect,
    and a warning for each that works against the gateway."""
    host, port = srv.server_address[:2]
    h = srv.RequestHandlerClass
    providers = getattr(h.scorer.b, "providers", None)
    t = srv.ort_threads

    def count(n, what):
        return f"{n} {what}" + ("" if n == 1 else "s")

    threads = "" if t is None else ", " + (count(t, "onnxruntime thread") if t else "onnxruntime's own threads")
    pool = count(h.workers.n, "worker") + threads
    out = [f"laya-server on {host}:{port}{PATH}: {pool} on {count(srv.cpus, 'CPU')} ({srv.cpu_source}), "
           f"answering within {h.workers.answer_ms:g} ms of a {srv.gateway_timeout_ms:g} ms gateway timeout, "
           f"backlog {srv.request_queue_size}, "
           f"at most {srv.max_connections} connections"
           + (f", providers {','.join(providers)}" if providers else "")]
    if t == 0:
        out.append("laya-server: LAYA_ORT_THREADS=0 lets onnxruntime size its pool from the host's "
                   f"cores, not the {srv.cpus} CPUs this process may use")
    elif t is not None and h.workers.n * t > srv.cpus:
        out.append(f"laya-server: LAYA_WORKERS x LAYA_ORT_THREADS = {h.workers.n * t}, over the "
                   f"{srv.cpus} CPUs this process may use: requests in flight slow each other down")
    cap = somaxconn()
    if cap is not None and cap < srv.request_queue_size:
        out.append(f"laya-server: the kernel caps the listen backlog at {cap} "
                   f"(net.core.somaxconn), under LAYA_BACKLOG={srv.request_queue_size}")
    return out


def main() -> None:
    srv = make_server()
    for line in startup_lines(srv):
        sys.stderr.write(line + "\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
