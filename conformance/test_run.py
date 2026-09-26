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


if __name__ == "__main__":
    unittest.main()
