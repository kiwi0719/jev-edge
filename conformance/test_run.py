"""Tests for run.py's own checks, against local stub servers (standard library only)."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import run

VECTORS = [{"input": {"method": "POST", "path": "/v1/systemone",
                      "body": {"state": "hello", "questions": {"injection": {"type": "noul", "instructions": "x"}}}}}]


def stub(protocol: str, close: bool):
    """A System One stub: every POST gets a valid answer for the asked questions.
    Returns (server, number of TCP connections accepted so far)."""
    conns = [0]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = protocol

        def setup(self):
            conns[0] += 1
            super().setup()

        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = json.dumps({"model": "laya", "answers": {q: {"noul": 0.1} for q in body["questions"]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            if close:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, conns


class KeepaliveTest(unittest.TestCase):
    def check(self, protocol: str, close: bool):
        srv, conns = stub(protocol, close)
        try:
            t = run.Target(f"http://127.0.0.1:{srv.server_address[1]}/v1/systemone", None, "laya", 5.0)
            return run.check_keepalive(t, VECTORS), conns[0]
        finally:
            srv.shutdown()
            srv.server_close()

    def test_http10_fails(self):
        err, _ = self.check("HTTP/1.0", close=False)
        self.assertIsNotNone(err)
        self.assertIn("closes the connection", err)

    def test_connection_close_fails(self):
        err, _ = self.check("HTTP/1.1", close=True)
        self.assertIsNotNone(err)
        self.assertIn("closes the connection", err)

    def test_keepalive_passes_on_one_connection(self):
        err, n = self.check("HTTP/1.1", close=False)
        self.assertIsNone(err)
        self.assertEqual(n, 1)


class NfkcTimeoutTest(unittest.TestCase):
    """The closing timeout_ms line sizes from the slower of the ASCII worst
    case and the NFKC text: from the ASCII one alone it advised a timeout
    the NFKC text overran."""

    def worst(self, alone, together=None, fit=None, budget_ms=1000.0):
        w = run.Worst(4, budget_ms)
        w.alone, w.together, w.fit = alone, together, fit
        return w

    def test_check_nfkc_returns_its_p99(self):
        srv, _ = stub("HTTP/1.1", close=False)
        try:
            t = run.Target(f"http://127.0.0.1:{srv.server_address[1]}/v1/systemone", None, "laya", 5.0)
            body = json.dumps({"state": run.nfkc_text(64), "questions": {"injection": {"type": "noul"}}}).encode()
            err, info, p99 = run.check_nfkc(t, body, 64, 3, 1000.0, mock=False)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIsNone(err, err)
        self.assertIsInstance(p99, float)
        self.assertIn(f"alone p99 {p99:.1f} ms", info)

    def test_ascii_at_once_slower_than_nfkc(self):
        line = run.timeout_line(self.worst(100.0, 300.0, 4), 5.0, 150.0)
        self.assertTrue(line.startswith("timeout_ms: 600-900, 2-3x the worst-case p99 of 300.0 ms"), line)
        self.assertIn("NFKC text alone: 150.0 ms", line)

    def test_nfkc_slower_than_ascii_at_once(self):
        line = run.timeout_line(self.worst(100.0, 300.0, 4), 5.0, 500.0)
        self.assertTrue(line.startswith("timeout_ms: 1000-1500 or more, 2-3x the NFKC text's p99 of 500.0 ms"),
                        line)

    def test_nfkc_slower_one_at_a_time(self):
        line = run.timeout_line(self.worst(100.0, None, 1, budget_ms=500.0), 0.0, 400.0)
        self.assertTrue(line.startswith("timeout_ms: 800-1200 for the NFKC text one at a time (p99 400.0 ms"),
                        line)
        self.assertIn("Run again with --budget-ms 800 or more", line)

    def test_without_nfkc_the_ascii_case_decides(self):
        line = run.timeout_line(self.worst(400.0, None, 0, budget_ms=500.0), 0.0)
        self.assertTrue(line.startswith("timeout_ms: 800-1200 for the worst case one at a time"), line)


if __name__ == "__main__":
    unittest.main()
