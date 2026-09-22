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
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "conformance"))

import fit_temperature  # noqa: E402
import laya_server as L  # noqa: E402
import run as conformance  # noqa: E402

Q = {"type": "noul", "instructions": "Is this an attack?"}


def serve(env=None, backend=None):
    e = {"LAYA_HOST": "127.0.0.1", "LAYA_PORT": "0", "LAYA_BACKEND": "mock", "LAYA_ACCESS_LOG": "0"}
    e.update(env or {})
    srv = L.make_server(e, backend=backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1/systemone"


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


if __name__ == "__main__":
    unittest.main()
