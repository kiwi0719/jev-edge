"""Check a judge server against the System One protocol as jev-edge speaks it.

    python3 conformance/run.py --endpoint http://127.0.0.1:8080/v1/systemone \\
        [--api-key KEY] [--model laya] [--strict] [--mock] [--budget-ms 250]

Replays conformance/vectors.json (generated from the gateway's own provider
and templates by conformance/gen.lua), then checks transport behaviour the
gateway depends on:

  keepalive     two requests on one connection (the gateway pools them)
  auth          with --api-key: no key and a wrong key are refused (401/403)
  aborted       a client that sends half a body and hangs up does not wedge
                the server: the next request is answered in budget
  stalled       while one client sits on an open request, others are served
  latency       --samples sequential requests; p99 must fit --budget-ms,
                the timeout_max_ms the gateway will run with

--strict requires the exact status codes this suite chose (400, 404, 405,
413); without it any 4xx passes where a 4xx is expected. --mock also checks
the scores against laya-server's mock backend (LAYA_BACKEND=mock), which is
what proves long text is judged whole rather than cut.

Standard library only. Exit status 0 when everything passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import socket
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))


class Target:
    def __init__(self, endpoint: str, api_key: str | None, model: str, timeout: float):
        u = urllib.parse.urlsplit(endpoint)
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.api_key, self.model, self.timeout = api_key, model, timeout

    def conn(self):
        cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        return cls(self.host, self.port, timeout=self.timeout)

    def map_path(self, p: str) -> str:
        # vectors are written against /v1/systemone; keep any prefix the endpoint has
        suffix = "/v1/systemone"
        if p == suffix:
            return self.path
        return (self.path[: -len(suffix)] if self.path.endswith(suffix) else "") + p

    def headers(self, auth: str | None = "default") -> dict:
        h = {"Content-Type": "application/json"}
        key = self.api_key if auth == "default" else auth
        if key:
            h["Authorization"] = "Bearer " + key
        return h

    def request(self, method, path, body: bytes | None, auth="default", conn=None):
        c = conn or self.conn()
        t0 = time.perf_counter()
        c.request(method, self.map_path(path), body=body, headers=self.headers(auth))
        r = c.getresponse()
        data = r.read()
        ms = (time.perf_counter() - t0) * 1000
        if conn is None:
            c.close()
        return r.status, data, ms


# ---------------------------------------------------------------------------
# vector cases
# ---------------------------------------------------------------------------


def build_body(inp: dict, model: str) -> bytes | None:
    if "raw" in inp:
        return inp["raw"].encode()
    if "long" in inp:
        L = inp["long"]
        text = L.get("prefix", "") + L["unit"] * L["times"] + L.get("suffix", "")
        return json.dumps({"model": model, "state": text, "questions": L["questions"]}).encode()
    if "body" in inp:
        b = dict(inp["body"])
        b["model"] = model
        return json.dumps(b, ensure_ascii=False).encode()
    return None


def check_answers(data: bytes, names: list[str]) -> tuple[str | None, dict]:
    try:
        doc = json.loads(data)
    except ValueError:
        return "response is not JSON", {}
    if not isinstance(doc, dict) or not isinstance(doc.get("answers"), dict):
        return "response has no `answers` object", {}
    ans = doc["answers"]
    if set(ans) != set(names):
        return f"answers for {sorted(ans)}, asked {sorted(names)}", {}
    scores = {}
    for n in names:
        a = ans[n]
        if not isinstance(a, dict) or "noul" not in a:
            return f"answers.{n} has no noul", {}
        p = a["noul"]
        if isinstance(p, bool) or not isinstance(p, (int, float)) or math.isnan(p) or not 0 <= p <= 1:
            return f"answers.{n}.noul = {p!r}, not a number in [0, 1]", {}
        scores[n] = float(p)
    if "usage" in doc and doc["usage"] is not None:
        u = doc["usage"]
        if not isinstance(u, dict) or not isinstance(u.get("input_tokens", 0), (int, float)):
            return "usage must be an object with numeric input_tokens", {}
    return None, scores


def check_error_body(data: bytes) -> str | None:
    try:
        doc = json.loads(data) if data else None
    except ValueError:
        return None  # a plain-text error is fine; the gateway does not read it
    if isinstance(doc, dict) and "answers" in doc:
        return "an error response carries `answers`"
    return None


def run_case(t: Target, case: dict, strict: bool, mock: bool) -> str | None:
    inp, exp = case["input"], case["expect"]
    status, data, _ = t.request(inp["method"], inp["path"], build_body(inp, t.model))

    if "statuses" in exp:
        want = [exp["strict_status"]] if strict and "strict_status" in exp else exp["statuses"]
        if status not in want:
            return f"status {status}, want one of {want}"
    else:
        want = exp["status"]
        if want >= 400 and not strict:
            if not 400 <= status < 500:
                return f"status {status}, want a 4xx"
        elif status != want:
            return f"status {status}, want {want}"

    if status != 200:
        return check_error_body(data)

    err, scores = check_answers(data, exp.get("answers", []))
    if err:
        return err
    if mock:
        for n, level in (exp.get("mock") or {}).items():
            p = scores[n]
            if (level == "high") != (p > 0.5):
                return f"mock: {n} = {p:.3f}, want {level}"
    if exp.get("deterministic"):
        s2, d2, _ = t.request(inp["method"], inp["path"], build_body(inp, t.model))
        err2, again = check_answers(d2, exp["answers"]) if s2 == 200 else (f"status {s2} on repeat", {})
        if err2:
            return "repeat: " + err2
        for n in scores:
            if abs(scores[n] - again[n]) > 1e-6:
                return f"{n} scored {scores[n]} then {again[n]} for the same request"
    return None


# ---------------------------------------------------------------------------
# transport checks
# ---------------------------------------------------------------------------


def short_body(t: Target, vectors) -> bytes:
    return build_body(vectors[0]["input"], t.model)


def check_keepalive(t: Target, vectors) -> str | None:
    c = t.conn()
    try:
        for i in range(2):
            s, _, _ = t.request("POST", "/v1/systemone", short_body(t, vectors), conn=c)
            if s != 200:
                return f"request {i + 1} on one connection: status {s}"
    except (http.client.HTTPException, OSError) as e:
        return f"second request on one connection failed: {e!r}"
    finally:
        c.close()
    return None


def check_auth(t: Target, vectors) -> str | None:
    for label, key in (("no key", None), ("wrong key", "wrong-" + t.api_key)):
        s, _, _ = t.request("POST", "/v1/systemone", short_body(t, vectors), auth=key)
        if s not in (401, 403):
            return f"{label}: status {s}, want 401 or 403"
    return None


def raw_socket(t: Target):
    s = socket.create_connection((t.host, t.port), timeout=t.timeout)
    if t.https:
        import ssl
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        s = ctx.wrap_socket(s, server_hostname=t.host)
    return s


def partial_request(t: Target, body: bytes) -> bytes:
    head = (f"POST {t.map_path('/v1/systemone')} HTTP/1.1\r\nHost: {t.host}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n")
    if t.api_key:
        head += f"Authorization: Bearer {t.api_key}\r\n"
    return (head + "\r\n").encode() + body[: len(body) // 2]


def check_aborted(t: Target, vectors, budget_ms: float) -> str | None:
    for _ in range(5):
        s = raw_socket(t)
        s.sendall(partial_request(t, short_body(t, vectors)))
        s.close()
    st, _, ms = t.request("POST", "/v1/systemone", short_body(t, vectors))
    if st != 200:
        return f"after 5 aborted requests: status {st}"
    if ms > budget_ms * 4:
        return f"after 5 aborted requests: {ms:.0f} ms"
    return None


def check_stalled(t: Target, vectors, budget_ms: float) -> str | None:
    s = raw_socket(t)
    try:
        s.sendall(partial_request(t, short_body(t, vectors)))  # and never send the rest
        out = {}

        def other():
            try:
                out["r"] = t.request("POST", "/v1/systemone", short_body(t, vectors))
            except Exception as e:  # noqa: BLE001
                out["e"] = e

        th = threading.Thread(target=other)
        th.start()
        th.join(max(2.0, budget_ms * 8 / 1000))
        if th.is_alive():
            return "a stalled client blocks every other request"
        if "e" in out:
            return f"request next to a stalled client failed: {out['e']!r}"
        if out["r"][0] != 200:
            return f"request next to a stalled client: status {out['r'][0]}"
    finally:
        s.close()
    return None


def check_latency(t: Target, vectors, samples: int, budget_ms: float) -> tuple[str | None, str]:
    c = t.conn()
    lat = []
    try:
        body = short_body(t, vectors)
        t.request("POST", "/v1/systemone", body, conn=c)  # warm the connection and the model
        for _ in range(samples):
            s, _, ms = t.request("POST", "/v1/systemone", body, conn=c)
            if s != 200:
                return f"status {s} during the latency run", ""
            lat.append(ms)
    finally:
        c.close()
    lat.sort()
    q = lambda f: lat[min(len(lat) - 1, int(math.ceil(f * len(lat))) - 1)]  # noqa: E731
    info = f"p50 {q(0.5):.1f} ms, p99 {q(0.99):.1f} ms over {samples}"
    if q(0.99) > budget_ms:
        return f"p99 {q(0.99):.1f} ms is over the {budget_ms:.0f} ms budget ({info})", info
    return None, info


# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--api-key", default=os.environ.get("JEV_CONFORMANCE_API_KEY") or None)
    ap.add_argument("--model", default="laya")
    ap.add_argument("--vectors", default=os.path.join(HERE, "vectors.json"))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--budget-ms", type=float, default=250.0)
    ap.add_argument("--samples", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds per request")
    args = ap.parse_args(argv)

    t = Target(args.endpoint, args.api_key, args.model, args.timeout)
    with open(args.vectors) as f:
        vectors = json.load(f)["cases"]

    failed = 0

    def report(name, err, info=""):
        nonlocal failed
        if err:
            failed += 1
            print(f"FAIL  {name}: {err}")
        else:
            print(f"ok    {name}" + (f"  ({info})" if info else ""))

    for case in vectors:
        try:
            err = run_case(t, case, args.strict, args.mock)
        except (http.client.HTTPException, OSError) as e:
            err = f"transport error: {e!r}"
        report(case["name"], err)

    checks = [("keepalive: two requests on one connection", lambda: check_keepalive(t, vectors))]
    if args.api_key:
        checks.append(("auth: missing or wrong key is refused", lambda: check_auth(t, vectors)))
    checks += [
        ("aborted requests do not wedge the server", lambda: check_aborted(t, vectors, args.budget_ms)),
        ("a stalled client does not block others", lambda: check_stalled(t, vectors, args.budget_ms)),
    ]
    for name, fn in checks:
        try:
            report(name, fn())
        except (http.client.HTTPException, OSError) as e:
            report(name, f"transport error: {e!r}")
    try:
        err, info = check_latency(t, vectors, args.samples, args.budget_ms)
        report(f"latency within {args.budget_ms:.0f} ms at p99", err, info)
    except (http.client.HTTPException, OSError) as e:
        report("latency", f"transport error: {e!r}")

    total = len(vectors) + len(checks) + 1
    print(f"\n{total - failed}/{total} passed" + ("" if args.strict else "  (not --strict: exact error codes not checked)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
