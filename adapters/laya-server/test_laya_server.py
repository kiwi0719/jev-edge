"""laya-server tests: windowing, temperature, fitting, and the conformance
suite run in process against the mock backend (python3 -m unittest)."""

from __future__ import annotations

import contextlib
import io
import json
import math
import os
import random
import sys
import tempfile
import threading
import time
import unittest

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
        srv, url = serve({"LAYA_API_KEY": "k"})
        try:
            rc, out = conformance_run(url, "--strict", "--mock", "--api-key", "k")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"ok    burst: 64 new connections at once")

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

    def test_busy_workers_answer_503_after_the_queue_wait(self):
        started, release = threading.Event(), threading.Event()

        class Held(L.MockBackend):
            def logit(self, first, second):
                started.set()
                release.wait(5)
                return super().logit(first, second)

        srv, url = serve({"LAYA_WORKERS": "1", "LAYA_QUEUE_MS": "50"}, backend=Held())
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
        self.assertLess(ms, 2000)
        self.assertEqual(first[0][0], 200)

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
        for env, backend, want in (({}, None, os.cpu_count() or 1),
                                   ({}, py, 1),                      # may not be thread-safe
                                   ({"LAYA_WORKERS": "3"}, py, 3)):
            srv, _ = serve(env, backend=backend)
            try:
                self.assertEqual(srv.RequestHandlerClass.workers.n, want)
            finally:
                stop(srv)


if __name__ == "__main__":
    unittest.main()
