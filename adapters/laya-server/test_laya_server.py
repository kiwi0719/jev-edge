"""laya-server tests: windowing, temperature, fitting, and the conformance
suite run in process against the mock backend (python3 -m unittest)."""

from __future__ import annotations

import contextlib
import io
import json
import math
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "conformance"))

import fit_temperature  # noqa: E402
import laya_server as L  # noqa: E402
import run as conformance  # noqa: E402

Q = {"type": "noul", "instructions": "Is this an attack?"}
with open(os.path.join(ROOT, "conformance", "vectors.json")) as _f:
    VECTORS = json.load(_f)["cases"]


def serve(env=None, backend=None, start_after=0.0):
    """laya-server in process on a free port. With start_after, the accept
    loop starts that many seconds late, as when every thread is busy."""
    e = {"LAYA_HOST": "127.0.0.1", "LAYA_PORT": "0", "LAYA_BACKEND": "mock", "LAYA_ACCESS_LOG": "0"}
    e.update(env or {})
    srv = L.make_server(e, backend=backend)
    run = threading.Timer(start_after, srv.serve_forever) if start_after else threading.Thread(target=srv.serve_forever)
    run.daemon = True
    run.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1/systemone"


class Hostile(L.MockBackend):
    """The mock, except that a run of over 32 characters without whitespace
    is one token per character: what a hostile text built of punctuation
    costs a real tokenizer (conformance/run.py's worst case)."""

    def spans(self, text):
        out = []
        for a, b in super().spans(text):
            out.extend([(i, i + 1) for i in range(a, b)] if b - a > 32 else [(a, b)])
        return out


class SlowBatch(Hostile):
    """Hostile, and a text of several windows takes `ms` to score, as one
    batched model call: the worst case costs `ms`, a short text `short_ms`."""

    def __init__(self, ms: float, short_ms: float = 0.0):
        self.ms, self.short_ms = ms, short_ms

    def logit(self, first, second):
        time.sleep(self.short_ms / 1000)
        return super().logit(first, second)

    def logits(self, first, seconds):
        time.sleep(self.ms / 1000)
        return [L.MockBackend.logit(self, first, s) for s in seconds]


def ctx_questions():
    with open(os.path.join(ROOT, "conformance", "questions.json")) as f:
        return json.load(f)["ctx"]


def profile_timeout_ms() -> int:
    with open(os.path.join(HERE, "jev-laya.conf.lua")) as f:
        return int(re.search(r"^\s*timeout_ms\s*=\s*(\d+)", f.read(), re.M).group(1))


def stop(srv):
    srv.shutdown()
    srv.server_close()


def post(url, state="hello", conn=None):
    t = conformance.Target(url, None, "laya", 5)
    body = json.dumps({"state": state, "questions": {"q": Q}}).encode()
    return t.request("POST", "/v1/systemone", body, conn=conn)


def conformance_run(endpoint, *extra) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = conformance.main(["--endpoint", endpoint, "--samples", "5", "--timeout", "5", *extra])
    return rc, out.getvalue()


class Windows(unittest.TestCase):
    def setUp(self):
        self.s = L.Scorer(L.MockBackend(), max_tokens=64, overlap=8, max_windows=4)

    def test_short_text_is_one_window(self):
        self.assertEqual(self.s.windows("q", "a b c"), ["a b c"])

    def test_long_text_is_covered_end_to_end_with_overlap(self):
        words = [f"w{i}" for i in range(120)]
        ws = self.s.windows("q", " ".join(words))
        self.assertGreater(len(ws), 1)
        self.assertLessEqual(len(ws), 4)
        seen = [w for win in ws for w in win.split()]
        self.assertEqual(set(seen), set(words))           # nothing dropped
        self.assertEqual(ws[0].split()[0], "w0")
        self.assertEqual(ws[-1].split()[-1], "w119")
        room = 64 - 3 - 1 - L.SLACK
        for a, b in zip(ws, ws[1:]):
            self.assertEqual(a.split()[-8:], b.split()[:8])  # overlap
            self.assertLessEqual(len(a.split()), room)

    def test_too_long_is_refused_not_cut(self):
        with self.assertRaises(L.Refused) as cm:
            self.s.windows("q", " ".join(["w"] * 1000))
        self.assertEqual((cm.exception.status, cm.exception.code), (413, "input_too_long"))

    def test_question_filling_the_model_is_refused(self):
        with self.assertRaises(L.Refused) as cm:
            self.s.windows(" ".join(["q"] * 60), "hello")
        self.assertEqual(cm.exception.code, "question_too_long")

    def test_attack_in_the_last_window_wins(self):
        text = " ".join(["benign"] * 150) + " ATTACK"
        ans, usage = self.s.score(text, {"injection": Q})
        self.assertGreater(ans["injection"]["noul"], 0.5)
        self.assertGreater(usage["windows"], 1)


class Temperature(unittest.TestCase):
    def test_noul_is_sigmoid_of_logit_over_t(self):
        for t in (0.5, 1.0, 2.0):
            s = L.Scorer(L.MockBackend(), temperature=t)
            ans, _ = s.score("ATTACK", {"q": Q})
            self.assertAlmostEqual(ans["q"]["noul"], 1 / (1 + math.exp(-4.0 / t)), places=5)

    def test_rejects_non_positive_t(self):
        with self.assertRaises(ValueError):
            L.Scorer(L.MockBackend(), temperature=0)

    def test_fit_recovers_the_temperature(self):
        # labels drawn from sigmoid(z / 2.5): the fitted T should come out near 2.5
        rng = random.Random(7)
        pairs = []
        for _ in range(4000):
            z = rng.uniform(-12, 12)
            pairs.append((z, 1 if rng.random() < L.sigmoid(z / 2.5) else 0))
        self.assertAlmostEqual(fit_temperature.fit(pairs), 2.5, delta=0.25)
        self.assertLess(fit_temperature.nll(pairs, 2.5), fit_temperature.nll(pairs, 1.0))

    def test_fit_cli_runs_the_server_path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for i in range(40):
                f.write(json.dumps({"text": f"hello {i} ATTACK" if i % 2 else f"hello {i}",
                                    "label": i % 2}) + "\n")
            f.write(json.dumps({"text": "x", "label": "maybe"}) + "\n")
            path = f.name
        old = os.environ.get("LAYA_BACKEND")
        os.environ["LAYA_BACKEND"] = "mock"
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = fit_temperature.main([path])
        finally:
            os.unlink(path)
            if old is None:
                del os.environ["LAYA_BACKEND"]
            else:
                os.environ["LAYA_BACKEND"] = old
        self.assertEqual(rc, 0)
        self.assertIn("LAYA_TEMPERATURE=", out.getvalue())
        self.assertIn("skipped", err.getvalue())


class Http(unittest.TestCase):
    def test_passes_conformance_strict_with_auth(self):
        # Hostile: the worst case is judged in several windows, and --mock
        # checks the attack at its tail is seen. At the profile's floor, 64
        # of it at once (max_inflight), with the default LAYA_GATEWAY_TIMEOUT_MS.
        srv, url = serve({"LAYA_API_KEY": "k"}, backend=Hostile())
        try:
            rc, out = conformance_run(url, "--strict", "--mock", "--api-key", "k",
                                      "--budget-ms", str(profile_timeout_ms()))
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"ok    worst case .* 64 at once: .*, [2-8] windows\)")
        self.assertRegex(out, r"ok    burst: 64 new connections at once")
        self.assertRegex(out, r"timeout_ms: \d+(-\d+)?, 2-3x the worst-case p99 of .* with 64 at once")

    def test_conformance_catches_silent_truncation(self):
        class Truncating(L.Scorer):
            def windows(self, first, text):
                return super().windows(first, text)[:1]   # the bug the suite exists for

        srv, url = serve()
        srv.RequestHandlerClass.scorer = Truncating(L.MockBackend())
        try:
            rc, out = conformance_run(url, "--mock")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL  long text: an attack at the tail is still seen", out)

    def test_backend_failure_is_a_500_never_a_score(self):
        srv, url = serve()
        try:
            t = conformance.Target(url, None, "laya", 5)
            body = json.dumps({"state": "x", "questions": {"q": {"type": "noul", "instructions": "FAIL now"}}})
            status, data, _ = t.request("POST", "/v1/systemone", body.encode())
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 500)
        self.assertNotIn("answers", json.loads(data))

    def test_malformed_text_is_judged_never_refused(self):
        # A tokenizer that refuses what the HF tokenizers library refuses: a
        # string that is not valid Unicode. A 400 or 500 for such text is an
        # L2 error, which the gateway answers by passing the request.
        class StrictTokenizer(L.MockBackend):
            def spans(self, text):
                text.encode("utf-8")
                return super().spans(text)

            def logit(self, first, second):
                first.encode("utf-8")
                second.encode("utf-8")
                return super().logit(first, second)

        q = json.dumps({"q": Q}).encode()
        bodies = {
            "lone surrogate escape": b'{"state":"\\ud800 ATTACK","questions":' + q + b"}",
            "lone low surrogate in the assistant": b'{"state":{"assistant":"bot \\udc00","user_message":"ATTACK"},'
                                                   b'"questions":' + q + b"}",
            "invalid UTF-8 byte": b'{"state":"\xff ATTACK","questions":' + q + b"}",
            "encoded surrogate bytes": b'{"state":"\xed\xa0\x80 ATTACK","questions":' + q + b"}",
        }
        srv, url = serve(backend=StrictTokenizer())
        try:
            t = conformance.Target(url, None, "laya", 5)
            for name, body in bodies.items():
                status, data, _ = t.request("POST", "/v1/systemone", body)
                self.assertEqual(status, 200, f"{name}: {data!r}")
                self.assertGreater(json.loads(data)["answers"]["q"]["noul"], 0.5, name)
            status, _, _ = t.request("POST", "/v1/systemone", b'{"state":"x",\xff}')
            self.assertEqual(status, 400)   # still not JSON
        finally:
            srv.shutdown()
            srv.server_close()

    def test_warm_connection_answers_without_waiting_for_an_ack(self):
        # headers and body are two writes: with Nagle on, a Linux client's
        # delayed ACK held every answer back about 40 ms
        srv, url = serve()
        try:
            t = conformance.Target(url, None, "laya", 5)
            body = json.dumps({"state": "hello", "questions": {"q": Q}}).encode()
            err, lat, _ = conformance.timed(t, body, 20)
        finally:
            stop(srv)
        self.assertIsNone(err)
        self.assertLess(conformance.pct(lat, 0.5), 20, lat)

    def test_body_over_the_limit_is_413(self):
        srv, url = serve({"LAYA_MAX_BODY_BYTES": "100"})
        try:
            t = conformance.Target(url, None, "laya", 5)
            body = json.dumps({"state": "x" * 200, "questions": {"q": Q}})
            status, _, _ = t.request("POST", "/v1/systemone", body.encode())
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 413)

    def test_conformance_catches_per_window_cost(self):
        # On CPU a text split in N windows costs about N model calls. A server
        # that answers a short text well inside the budget can still time out
        # on the longest text the gateway sends, and a timeout passes the
        # request: the worst-case check must fail where the short one passes.
        class PerWindow(Hostile):
            def logit(self, first, second):
                time.sleep(0.03)
                return super().logit(first, second)

        srv, url = serve({"LAYA_WORKERS": "4"}, backend=PerWindow())
        try:
            rc, out = conformance_run(url, "--budget-ms", "100", "--concurrency", "4")
        finally:
            stop(srv)
        self.assertEqual(rc, 1, out)
        self.assertIn("ok    latency within 100 ms with 2x headroom at p99", out)
        self.assertRegex(out, r"FAIL  worst case within 100 ms with 2x headroom at p99, 4 at once: "
                              r"4096 bytes .* windows\)\. Alone it needs a timeout_ms of \d+")
        self.assertRegex(out, r"timeout_ms: \d+-\d+, 2-3x the worst-case p99 of .* with 4 at once")

    def test_worst_case_refused_is_a_failure(self):
        # a 413 for a text inside max_judge_bytes is an L2 error: a bypass
        srv, url = serve({"LAYA_MAX_WINDOWS": "2"}, backend=Hostile())
        try:
            t = conformance.Target(url, None, "laya", 5)
            body = conformance.worst_body(t, 4096, conformance.DEFAULT_ASSISTANT, ctx_questions())
            err, _, _ = conformance.check_worst(t, body, conformance.short_body(t, VECTORS), 4096, 2, 4,
                                                1000, mock=False)
        finally:
            stop(srv)
        self.assertRegex(err, r"^status 413 for 4096 bytes .*LAYA_MAX_WINDOWS")

    def test_worst_text_is_fixed_ascii_of_the_asked_size(self):
        a, b = conformance.worst_text(4096), conformance.worst_text(4096)
        self.assertEqual(a, b)
        self.assertEqual(len(a.encode()), 4096)
        self.assertTrue(a.endswith(" ATTACK"))
        self.assertNotIn(" ", a[:-7])

    def test_worst_case_is_timed_at_the_gateways_concurrency(self):
        # Fast enough one at a time, but one worker: of 4 worst-case texts at
        # once (the gateway at max_inflight), 3 cannot be scored within the
        # 250 ms the server has at a 500 ms timeout, behind the first, and
        # get 503, which the gateway treats as an L2 error. The check fails
        # and says how many at once the server holds.
        srv, url = serve({"LAYA_WORKERS": "1"}, backend=SlowBatch(150))
        try:
            rc, out = conformance_run(url, "--budget-ms", "500", "--concurrency", "4")
        finally:
            stop(srv)
        self.assertEqual(rc, 1, out)
        self.assertIn("ok    burst: 4 new connections at once", out)  # short texts: fast
        self.assertRegex(out, r"FAIL  worst case within 500 ms with 2x headroom at p99, 4 at once: "
                              r"4096 bytes .* wording: \d+ of 8 not answered 200 \(503: \d+\)")
        self.assertIn("set max_inflight (summed over the gateways that call this server) to at most 1", out)
        self.assertNotIn("a 503 took", out)  # refused at once, while the gateway reads
        self.assertRegex(out, r"timeout_ms: \d+-\d+ for the worst case one at a time .* With 4 at once, "
                              r"1 per round were answered in time at timeout_ms 500: set max_inflight "
                              r"to at most 1")


class Verdicts(unittest.TestCase):
    """conformance/run.py's timing verdicts from given latencies: a check
    passes only with the headroom the run recommends, and a 503 must come
    while the gateway still reads."""

    t = conformance.Target("http://127.0.0.1:9/v1/systemone", None, "laya", 1)

    def worst(self, alone, rounds, budget=500.0):
        with mock.patch.object(conformance, "timed", return_value=(None, sorted(alone), b'{"answers": '
                               b'{"injection": {"noul": 0.9}}, "usage": {"windows": 6}}')), \
             mock.patch.object(conformance, "at_once", return_value=rounds):
            return conformance.check_worst(self.t, b"", b"", 4096, len(alone), len(rounds[0]), budget,
                                           mock=True)

    def test_latency_passes_only_with_headroom(self):
        for p99, ok in ((40.0, True), (50.0, True), (60.0, False), (99.0, False)):
            with mock.patch.object(conformance, "timed", return_value=(None, [10.0, p99], b"")):
                err, _, got = conformance.check_latency(self.t, VECTORS, 2, 100)
            self.assertEqual(got, p99)
            if ok:
                self.assertIsNone(err, p99)
            else:
                self.assertRegex(err, rf"^p99 {p99:.1f} ms needs a timeout_ms of {math.ceil(2 * p99)} at 2x "
                                      r"headroom, over the 100 ms budget \(the gateway reads for 60% of it\)")

    def test_worst_case_under_budget_but_without_headroom_fails(self):
        # every one answered 200 inside the 500 ms budget, yet the p99 of 300 ms
        # is all the gateway's read wait: the tail past it would time out
        err, _, w = self.worst([100.0] * 4, [[(200, 300.0)] * 4] * 2)
        self.assertRegex(err, r"^p99 300\.0 ms needs a timeout_ms of 600 at 2x headroom")
        self.assertIn("Raise timeout_ms to 600-900", err)
        self.assertEqual(w.together, 300.0)
        self.assertEqual(conformance.timeout_line(w, 5.0)[:48], "timeout_ms: 600-900, 2-3x the worst-case p99 of ")

    def test_worst_case_with_headroom_passes(self):
        err, info, w = self.worst([100.0] * 4, [[(200, 240.0)] * 4] * 2)
        self.assertIsNone(err, info)
        self.assertEqual((w.alone, w.together, w.fit), (100.0, 240.0, 4))

    def test_a_503_after_the_gateway_stopped_reading_is_flagged(self):
        # at 500 ms the gateway reads for 300: a 503 at 400 ms reaches no one
        late = [(200, 150.0), (200, 240.0), (503, 400.0), (503, 400.0)]
        err, _, w = self.worst([100.0] * 4, [late, late])
        self.assertIn("a 503 took 400 ms, after the gateway stopped reading at 300 ms", err)
        self.assertIn("LAYA_GATEWAY_TIMEOUT_MS at most the gateway's timeout_ms, 500 here", err)
        self.assertEqual(w.fit, 2)
        prompt = [(200, 150.0), (200, 240.0), (503, 60.0), (503, 60.0)]
        err, _, _ = self.worst([100.0] * 4, [prompt, prompt])
        self.assertNotIn("a 503 took", err)
        self.assertIn("to at most 2", err)

    def test_too_slow_alone_says_so_first(self):
        # max_inflight advice would be wrong here: one at a time already misses
        err, _, w = self.worst([400.0] * 4, [[(200, 900.0)] * 4] * 2)
        self.assertIn("Alone it needs a timeout_ms of 800 at 2x headroom", err)
        err, _, w = self.worst([400.0] * 4, [[(503, 50.0)] * 4] * 2)
        line = conformance.timeout_line(w, 0.0)
        self.assertIn("timeout_ms: 800-1200 for the worst case one at a time", line)
        self.assertIn("Run again with --budget-ms 800 or more", line)
        self.assertNotIn("max_inflight to at most", line)


class Load(unittest.TestCase):
    """lead-laya-python#31: the gateway opens up to jev.max_inflight (64)
    connections at once. socketserver's listen backlog of 5 dropped most of
    a burst; each dropped connection was an L2 timeout, which passes the
    request, and enough of them opened the breaker for every tenant."""

    def burst(self, env):
        # the accept loop starts 0.3 s late, as when the server is busy: the
        # burst must wait in the listen queue, not be dropped from it
        srv, url = serve(env, start_after=0.3)
        try:
            t = conformance.Target(url, None, "laya", 5)
            return conformance.check_burst(t, VECTORS, 64, 2000)
        finally:
            stop(srv)

    def test_listen_backlog_holds_a_burst(self):
        err, info = self.burst({})
        self.assertIsNone(err, info)

    def test_a_small_backlog_fails_the_burst_check(self):
        err, _ = self.burst({"LAYA_BACKLOG": "1"})
        self.assertRegex(err or "", r"not answered 200 \(connect")
        self.assertIn("(laya-server: LAYA_BACKLOG)", err)
        self.assertNotIn("A 503", err)

    def test_backlog_is_configurable(self):
        srv, _ = serve({"LAYA_BACKLOG": "200"})
        try:
            self.assertEqual(srv.request_queue_size, 200)
        finally:
            stop(srv)
        srv, _ = serve()
        try:
            self.assertEqual(srv.request_queue_size, 1024)
        finally:
            stop(srv)

    def test_busy_workers_answer_503_while_the_gateway_reads(self):
        started, release = threading.Event(), threading.Event()

        class Held(L.MockBackend):
            def logit(self, first, second):
                started.set()
                release.wait(5)
                return super().logit(first, second)

        # nothing scored yet, so no estimate: the second request waits
        # for the first as long as it can, half the gateway's timeout
        srv, url = serve({"LAYA_WORKERS": "1"}, backend=Held())
        first = []
        th = threading.Thread(target=lambda: first.append(post(url, "ATTACK")))
        try:
            th.start()
            self.assertTrue(started.wait(5))
            status, data, ms = post(url)
            release.set()
            th.join(5)
        finally:
            release.set()
            stop(srv)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(data)["error"]["code"], "overloaded")
        self.assertNotIn("answers", json.loads(data))
        # answered while the gateway at the profile's floor still reads
        self.assertLess(ms, conformance.READ_SHARE * profile_timeout_ms())
        self.assertEqual(first[0][0], 200)

    def test_answer_time_is_derived_from_the_profile(self):
        # LAYA_GATEWAY_TIMEOUT_MS is the profile's floor by default. The
        # gateway reads for 60% of it; the server answers or refuses within
        # half of it, the headroom conformance passes a server at
        floor = profile_timeout_ms()
        self.assertEqual(L.GATEWAY_TIMEOUT_MS_DEFAULT, floor)
        self.assertEqual(L.READ_SHARE, conformance.READ_SHARE)
        self.assertEqual(L.ANSWER_SHARE, 1 / conformance.HEADROOM[0])
        self.assertLess(L.ANSWER_SHARE, L.READ_SHARE)
        for env, want in (({}, floor / 2), ({"LAYA_GATEWAY_TIMEOUT_MS": "300"}, 150)):
            srv, _ = serve(env)
            try:
                self.assertEqual(srv.RequestHandlerClass.workers.answer_ms, want)
            finally:
                stop(srv)

    def test_connection_past_the_cap_gets_503_and_is_closed(self):
        srv, url = serve({"LAYA_MAX_CONNECTIONS": "1"})
        t = conformance.Target(url, None, "laya", 5)
        held = t.conn()
        try:
            self.assertEqual(post(url, conn=held)[0], 200)  # keepalive: holds the one slot
            c = t.conn()
            c.request("POST", "/v1/systemone", body=json.dumps({"state": "x", "questions": {"q": Q}}),
                      headers=t.headers())
            r = c.getresponse()
            data = r.read()
            c.close()
            self.assertEqual(r.status, 503)
            self.assertEqual(r.getheader("Connection"), "close")
            self.assertEqual(json.loads(data)["error"]["code"], "overloaded")
            self.assertEqual(t.request("GET", "/healthz", None)[0], 200)  # busy is not unhealthy
        finally:
            held.close()
        try:
            deadline = time.monotonic() + 5
            while srv.connections and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(post(url)[0], 200)
        finally:
            stop(srv)

    def test_workers_default(self):
        py = L.PythonBackend.__new__(L.PythonBackend)
        py.spans, py.count, py.logit, py.pair_overhead = L.MockBackend().spans, len, lambda f, s: 0.0, 0
        for env, backend, want in (({}, None, L.cpu_budget()[0]),
                                   ({}, py, 1),                      # may not be thread-safe
                                   ({"LAYA_WORKERS": "3"}, py, 3)):
            srv, _ = serve(env, backend=backend)
            try:
                self.assertEqual(srv.RequestHandlerClass.workers.n, want)
            finally:
                stop(srv)


class Pool(unittest.TestCase):
    """A request waits for a worker as long as it can still be answered in
    time, by its own estimated scoring time and that of the work ahead of
    it. A fixed 50 ms wait refused most of a burst of short texts the
    server would have answered while the gateway reads."""

    def test_size_is_about_the_tokens(self):
        # without the tokenizer, which holds the GIL: a short prompt, prose
        # of 4096 bytes, and the worst case of 4096 bytes (one token per
        # byte) come out in that order, each in a size class of its own
        t = conformance.Target("http://127.0.0.1:9/v1/systemone", None, "laya", 1)
        q = {"injection": ctx_questions()["injection"]}
        prose = ("Please summarise the attached invoice and tell me how refunds work. " * 70)[:4096]
        worst = json.loads(conformance.worst_body(t, 4096, conformance.DEFAULT_ASSISTANT, q))["state"]
        sizes = [L.cost_units({"assistant": conformance.DEFAULT_ASSISTANT, "user_message": "hello"}, q),
                 L.cost_units({"assistant": conformance.DEFAULT_ASSISTANT, "user_message": prose}, q),
                 L.cost_units(worst, q)]
        self.assertEqual(sizes, sorted(sizes))
        self.assertEqual(len({L.CostModel.size_class(n) for n in sizes}), 3, sizes)
        self.assertGreater(sizes[2], 4096 * 0.8)
        self.assertLess(sizes[1], sizes[2] / 2)

    def test_cost_is_learned_per_size_class(self):
        c = L.CostModel()
        self.assertEqual(c.estimate(100), 0.0)  # nothing scored yet
        c.observe(100, 5.0)     # a short text: 0.05 ms per unit
        c.observe(6000, 420.0)  # the worst case: 0.07 ms per unit
        self.assertAlmostEqual(c.estimate(120), 6.0)
        self.assertAlmostEqual(c.estimate(5000), 350.0)
        self.assertAlmostEqual(c.estimate(500), 25.0)   # a class not seen: the nearest one's rate
        self.assertAlmostEqual(c.estimate(1000), 70.0)  # halfway: the dearer one's
        c.observe(100, 15.0)  # a slower scoring moves its class's rate half way
        self.assertAlmostEqual(c.estimate(100), 10.0)
        c.observe(100, 5.0)   # a faster one a tenth of the way
        self.assertAlmostEqual(c.estimate(100), 9.5)

    def test_queue_takes_what_fits_in_order_and_refuses_the_rest_at_once(self):
        cost = L.CostModel()
        cost.observe(100, 400.0)  # 4 ms per unit: 400 ms for 100 units, 40 ms for 10
        w = L.Workers(1, 1000, cost)
        order = []

        def queued(name, units):
            with w.slot(units):
                order.append(name)

        held = w.slot(100)
        held.__enter__()  # scoring, about 400 ms
        a = threading.Thread(target=queued, args=("a", 100))
        a.start()  # 400 ms of waiting and 400 of scoring fit in 1000: it waits
        deadline = time.monotonic() + 5
        while not w._queue and time.monotonic() < deadline:
            time.sleep(0.001)
        t0 = time.perf_counter()
        with self.assertRaises(L.Refused) as cm:
            with w.slot(100):  # 800 ms of waiting and 400 of scoring do not
                pass
        self.assertLess((time.perf_counter() - t0) * 1000, 50)  # refused at once, not after a wait
        self.assertEqual((cm.exception.status, cm.exception.code), (503, "overloaded"))
        self.assertIn("LAYA_GATEWAY_TIMEOUT_MS", cm.exception.message)
        b = threading.Thread(target=queued, args=("b", 10))
        b.start()  # 800 ms of waiting and 40 of scoring fit: it waits behind a
        while len(w._queue) < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        held.__exit__(None, None, None)
        a.join(5)
        b.join(5)
        self.assertEqual(order, ["a", "b"])
        self.assertEqual(w._free, 1)

    def test_a_short_burst_is_served_and_a_long_text_behind_it_refused_at_once(self):
        # one worker, 10 ms per short text, 400 ms for the worst case; at a
        # 1000 ms gateway timeout the server answers within 500 ms
        srv, url = serve({"LAYA_WORKERS": "1", "LAYA_GATEWAY_TIMEOUT_MS": "1000"},
                         backend=SlowBatch(400, short_ms=10))
        pool = srv.RequestHandlerClass.workers
        t = conformance.Target(url, None, "laya", 5)
        short = conformance.short_body(t, VECTORS)
        worst = conformance.worst_body(t, 4096, conformance.DEFAULT_ASSISTANT, ctx_questions())
        try:
            conformance.timed(t, short, 3)  # the server learns what each costs
            conformance.timed(t, worst, 2)
            # 16 short texts at once: about 200 ms of scoring, all answered in time
            rounds = conformance.at_once(t, short, short, 16, 2)
            for r in rounds:
                self.assertEqual([s for s, _ in r], [200] * 16, r)
                self.assertLess(max(ms for _, ms in r), conformance.READ_SHARE * 1000)
            # a worst-case text sent behind 12 or more short ones cannot be
            # scored in time: 503 at once, not after a wait
            got = {}

            def send(name, body):
                got[name] = t.request("POST", "/v1/systemone", body)

            ths = [threading.Thread(target=send, args=(i, short)) for i in range(16)]
            with contextlib.redirect_stderr(io.StringIO()):
                for th in ths:
                    th.start()
                deadline = time.monotonic() + 5
                while len(pool._queue) < 12 and time.monotonic() < deadline:
                    time.sleep(0.001)
                send("worst", worst)
                for th in ths:
                    th.join(5)
        finally:
            stop(srv)
        self.assertEqual(sorted(got[i][0] for i in range(16)), [200] * 16)
        status, data, ms = got["worst"]
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"]["code"], "overloaded")
        self.assertLess(ms, 60)

    def test_burst_503s_are_blamed_on_the_workers_not_the_backlog(self):
        srv, url = serve({"LAYA_WORKERS": "1"}, backend=SlowBatch(0, short_ms=40))
        try:
            t = conformance.Target(url, None, "laya", 5)
            conformance.timed(t, conformance.short_body(t, VECTORS), 2)
            with contextlib.redirect_stderr(io.StringIO()):
                err, _ = conformance.check_burst(t, VECTORS, 16, 500)  # 640 ms of work for 250
        finally:
            stop(srv)
        self.assertRegex(err or "", r"not answered 200 \(503: \d+\)\. A 503 means the server could not score "
                                    r"that many at once in time: add capacity \(laya-server: LAYA_WORKERS")
        self.assertNotIn("LAYA_BACKLOG", err)


class ClientGone(unittest.TestCase):
    """A client that stalls or hangs up in the middle of its body is the
    client's doing: an access-log line, never a backend-fault warning."""

    def run_client(self, send):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            srv, url = serve({"LAYA_IDLE_TIMEOUT_S": "0.2", "LAYA_ACCESS_LOG": "1"})
            try:
                t = conformance.Target(url, None, "laya", 5)
                body = json.dumps({"state": "hello", "questions": {"q": Q}}).encode()
                s = conformance.raw_socket(t)
                try:
                    s.sendall(conformance.partial_request(t, body))
                    send(s)
                finally:
                    s.close()
                status = post(url)[0]
            finally:
                stop(srv)
        return status, err.getvalue()

    def test_stall_mid_body(self):
        def stall(s):
            s.settimeout(3)
            self.assertEqual(s.recv(100), b"")  # closed by the server after its idle timeout
        status, log = self.run_client(stall)
        self.assertEqual(status, 200)
        self.assertNotIn("backend error", log)
        self.assertNotIn("Traceback", log)
        self.assertRegex(log, r"client gone mid-request: \w+ after the headers, reading a \d+-byte body")

    def test_hang_up_mid_body(self):
        def hang_up(s):
            s.shutdown(socket.SHUT_WR)
            s.settimeout(3)
            s.recv(100)
        status, log = self.run_client(hang_up)
        self.assertEqual(status, 200)
        self.assertNotIn("backend error", log)
        self.assertRegex(log, r"client gone mid-request: hung up after \d+ of \d+ body bytes")


class ContentLength(unittest.TestCase):
    """python-adapters#8: Content-Length went through int(), which takes
    "-1" (rfile.read(-1) then read until the client closed, past
    LAYA_MAX_BODY_BYTES), "+5" and "1_0"; a length int() refused raised out
    of the 401 path as a 500 backend_error, and out of do_PUT."""

    def exchange(self, head: str, body: bytes = b"", env=None):
        """One raw request on a fresh connection, left open for writing (no
        EOF from the client): the answer's status and bytes, the status of a
        good request after it, and what the server wrote on stderr."""
        e = {"LAYA_MAX_BODY_BYTES": "1000", "LAYA_ACCESS_LOG": "1", "LAYA_IDLE_TIMEOUT_S": "30"}
        e.update(env or {})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            srv, url = serve(e)
            try:
                s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3)
                got = b""
                try:
                    s.sendall(head.encode("latin-1") + b"\r\n" + body)
                    while True:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        got += chunk
                except ConnectionResetError:
                    pass  # the server closed with our unread body: what it sent is in `got`
                finally:
                    s.close()
                after = post(url)[0]
            finally:
                stop(srv)
        self.assertTrue(got.startswith(b"HTTP/1.1 "), got)
        return int(got.split(b" ", 2)[1]), got, after, err.getvalue()

    @staticmethod
    def head(length: str, method: str = "POST", extra: str = "") -> str:
        return (f"{method} /v1/systemone HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                f"Content-Length: {length}\r\n{extra}")

    def test_a_negative_length_is_411_without_reading_to_eof(self):
        # before: 200 with a score for a body past the limit, once the
        # client closed; here the client never closes, and the answer
        # comes at once
        body = json.dumps({"state": "x " * 1000, "questions": {"q": Q}}).encode()[:2048]
        status, got, after, log = self.exchange(self.head("-1"), body)
        self.assertEqual(status, 411, got)
        self.assertIn(b"Connection: close", got)
        self.assertIn(b"length_required", got)
        self.assertEqual(after, 200)
        self.assertNotIn("Traceback", log)

    def test_lengths_int_takes_and_no_gateway_sends_are_411(self):
        for length in ["+5", "1_0", " -0", "5 5", "0x5", "5.0", "\xb2", "\xb3\xb9", ""]:
            status, got, after, log = self.exchange(self.head(length), b'{"a":1}')
            self.assertEqual(status, 411, (length, got))
            self.assertEqual(after, 200)
            self.assertNotIn("Traceback", log)
        # two different lengths: which one frames the body is anyone's guess
        status, got, _, _ = self.exchange(self.head("7", extra="Content-Length: 70\r\n"), b'{"a":1}')
        self.assertEqual(status, 411, got)

    def test_an_honest_length_is_read_and_one_over_the_limit_is_413(self):
        body = json.dumps({"state": "hello", "questions": {"q": Q}}).encode()
        status, got, _, _ = self.exchange(self.head(f" {len(body)}\t", extra="Connection: close\r\n"), body)
        self.assertEqual(status, 200, got)
        status, got, _, _ = self.exchange(self.head(str(len(body)), extra=f"Content-Length: {len(body)}\r\n"
                                                                          "Connection: close\r\n"), body)
        self.assertEqual(status, 200, got)  # the same length twice frames it the same way
        status, got, _, _ = self.exchange(self.head("5000"), b"x" * 100)
        self.assertEqual(status, 413, got)

    def test_a_bad_length_on_a_refused_request_is_that_refusal_not_a_500(self):
        status, got, after, log = self.exchange(self.head("abc"), b"xyz", env={"LAYA_API_KEY": "k"})
        self.assertEqual(status, 401, got)
        self.assertIn(b"Connection: close", got)  # the body's end is unknown: the stream is not reused
        self.assertEqual(after, 401)  # post() sends no key
        self.assertNotIn("backend error", log)
        for method in ("PUT", "DELETE", "PATCH"):
            status, got, _, log = self.exchange(self.head("-1", method=method), b"xyz")
            self.assertEqual(status, 405, got)
            self.assertIn(b"Connection: close", got)
            self.assertNotIn("Traceback", log)
        status, got, _, log = self.exchange(self.head("abc", method="POST").replace("/v1/systemone", "/nope"), b"x")
        self.assertEqual(status, 404, got)
        self.assertNotIn("Traceback", log)


class Cpus(unittest.TestCase):
    """Pool sizes come from the CPUs this process may use, not the host's
    count: a container limited to 2 CPUs on a 64-core host got 64 workers,
    each with onnxruntime's pool of one thread per host core."""

    def tree(self, files: dict) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        for path, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, path)), exist_ok=True)
            with open(os.path.join(d, path), "w") as f:
                f.write(text)
        return d

    def quota(self, files):
        d = self.tree(files)
        return L.cgroup_cpus(os.path.join(d, "sys"), os.path.join(d, "proc"))

    def test_cgroup_v2_container(self):
        self.assertEqual(self.quota({"proc": "0::/\n", "sys/cpu.max": "150000 100000\n"}), 1.5)
        self.assertIsNone(self.quota({"proc": "0::/\n", "sys/cpu.max": "max 100000\n"}))

    def test_cgroup_v2_nested_takes_the_lowest(self):
        self.assertEqual(self.quota({"proc": "0::/a/b\n", "sys/a/b/cpu.max": "max 100000\n",
                                     "sys/a/cpu.max": "200000 100000\n", "sys/cpu.max": "800000 100000\n"}), 2.0)

    def test_cgroup_v1_container_sees_its_group_at_the_mount(self):
        # without a cgroup namespace the path names the host's group
        self.assertEqual(self.quota({"proc": "12:memory:/docker/x\n4:cpu,cpuacct:/docker/x\n",
                                     "sys/cpu,cpuacct/cpu.cfs_quota_us": "300000\n",
                                     "sys/cpu,cpuacct/cpu.cfs_period_us": "100000\n"}), 3.0)
        self.assertIsNone(self.quota({"proc": "4:cpu,cpuacct:/\n",
                                      "sys/cpu,cpuacct/cpu.cfs_quota_us": "-1\n",
                                      "sys/cpu,cpuacct/cpu.cfs_period_us": "100000\n"}))

    def test_no_cgroups(self):
        self.assertIsNone(L.cgroup_cpus("/nonexistent", "/nonexistent/cgroup"))

    def test_budget_is_affinity_capped_by_the_quota_rounded_down(self):
        d = self.tree({"proc": "0::/\n", "sys/cpu.max": "250000 100000\n"})
        args = (os.path.join(d, "sys"), os.path.join(d, "proc"))
        with mock.patch.object(os, "sched_getaffinity", create=True, return_value=set(range(8))):
            self.assertEqual(L.cpu_budget(*args), (2, "cgroup CPU quota 2.5, of 8 CPUs this process may run on"))
        with mock.patch.object(os, "sched_getaffinity", create=True, return_value={0, 1}):
            self.assertEqual(L.cpu_budget(*args), (2, "CPUs this process may run on"))
        d = self.tree({"proc": "0::/\n", "sys/cpu.max": "50000 100000\n"})
        with mock.patch.object(os, "sched_getaffinity", create=True, return_value=set(range(8))):
            self.assertEqual(L.cpu_budget(os.path.join(d, "sys"), os.path.join(d, "proc"))[0], 1)

    def test_pool_sizes(self):
        for kind, env, cpus, want in (
                ("onnx", {}, 1, (1, 1)), ("onnx", {}, 2, (2, 1)), ("onnx", {}, 4, (2, 2)),
                ("onnx", {}, 8, (2, 4)), ("onnx", {}, 10, (2, 4)), ("onnx", {}, 64, (16, 4)),
                ("onnx", {"LAYA_WORKERS": "4"}, 8, (4, 2)),
                ("onnx", {"LAYA_WORKERS": "16"}, 8, (16, 1)),     # oversubscribed: warned at start
                ("onnx", {"LAYA_ORT_THREADS": "1"}, 8, (8, 1)),
                ("onnx", {"LAYA_ORT_THREADS": "0"}, 8, (1, 0)),   # onnxruntime's choice: the host's cores
                ("onnx", {"LAYA_WORKERS": "3", "LAYA_ORT_THREADS": "5"}, 8, (3, 5)),
                ("mock", {}, 6, (6, 0)), ("python", {}, 6, (1, 0)), ("python", {"LAYA_WORKERS": "2"}, 6, (2, 0))):
            self.assertEqual(L.pool_sizes(kind, env, cpus), want, (kind, env, cpus))
            w, t = want
            if kind == "onnx" and not env:
                self.assertLessEqual(w * t, cpus)
        with self.assertRaises(ValueError):
            L.pool_sizes("onnx", {"LAYA_ORT_THREADS": "-1"}, 4)

    def onnx_server(self, env, cpus=8):
        got = {}

        def fake_load(e, threads=None):
            got["threads"] = threads
            return L.MockBackend()

        e = {"LAYA_HOST": "127.0.0.1", "LAYA_PORT": "0", "LAYA_BACKEND": "onnx", **env}
        with mock.patch.object(L, "load_backend", fake_load):
            srv = L.make_server(e, cpus=(cpus, "test CPUs"))
        self.addCleanup(srv.server_close)
        return srv, got["threads"]

    def test_server_sizes_onnx_from_the_cpus(self):
        srv, threads = self.onnx_server({})
        self.assertEqual((srv.RequestHandlerClass.workers.n, threads), (2, 4))
        lines = L.startup_lines(srv)
        self.assertRegex(lines[0], r": 2 workers, 4 onnxruntime threads on 8 CPUs \(test CPUs\), "
                                   r"answering within 250 ms of a 500 ms gateway timeout")
        self.assertFalse(any("slow each other down" in x or "LAYA_ORT_THREADS=0" in x for x in lines), lines)

    def test_startup_warns_when_the_pool_outgrows_the_cpus(self):
        srv, _ = self.onnx_server({"LAYA_WORKERS": "8", "LAYA_ORT_THREADS": "2"})
        self.assertTrue(any("LAYA_WORKERS x LAYA_ORT_THREADS = 16, over the 8 CPUs" in x
                            for x in L.startup_lines(srv)))
        srv, threads = self.onnx_server({"LAYA_ORT_THREADS": "0"})
        self.assertEqual(threads, 0)
        self.assertTrue(any("LAYA_ORT_THREADS=0 lets onnxruntime size its pool from the host's cores" in x
                            for x in L.startup_lines(srv)))


class OrtOptions(unittest.TestCase):
    def test_providers(self):
        have = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        self.assertEqual(L.ort_providers(None, have), ["CPUExecutionProvider"])
        self.assertEqual(L.ort_providers(" CUDAExecutionProvider,CPUExecutionProvider ", have), have)
        # a provider missing from the build stops the server rather than
        # falling back to CPU under a timeout sized for a GPU
        with self.assertRaises(SystemExit) as cm:
            L.ort_providers("CUDAExecutionProvider", ["CPUExecutionProvider"])
        self.assertIn("CUDAExecutionProvider", str(cm.exception))

    def test_env_reaches_the_backend(self):
        with mock.patch.object(L, "OnnxBackend") as onnx:
            L.load_backend({"LAYA_BACKEND": "onnx", "LAYA_ORT_PROVIDERS": "CUDAExecutionProvider",
                            "LAYA_ORT_THREADS": "2"})
        onnx.assert_called_once_with("/model", 1, providers="CUDAExecutionProvider", threads=2)

    def test_threads_default_to_the_cpu_budget(self):
        # fit_temperature.py loads the backend without a server
        with mock.patch.object(L, "OnnxBackend") as onnx, \
             mock.patch.object(L, "cpu_budget", return_value=(8, "test")):
            L.load_backend({"LAYA_BACKEND": "onnx"})
        onnx.assert_called_once_with("/model", 1, providers=None, threads=4)


if __name__ == "__main__":
    unittest.main()
