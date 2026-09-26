"""Check a judge server against the System One protocol as jev-edge speaks it.

    python3 conformance/run.py --endpoint http://127.0.0.1:8080/v1/systemone \\
        [--api-key KEY] [--model laya] [--strict] [--mock] [--budget-ms 250] \\
        [--judge-bytes 4096] [--concurrency 64] [--assistant TEXT]

Replays conformance/vectors.json (generated from the gateway's own provider
and templates by conformance/gen.lua), then checks transport behaviour the
gateway depends on:

  keepalive     two requests on one connection (the gateway pools them)
  auth          with --api-key: no key and a wrong key are refused (401/403)
  aborted       a client that sends half a body and hangs up does not wedge
                the server: the next request is answered in budget
  stalled       while one client sits on an open request, others are served
  burst         --concurrency new connections at once (the gateway's
                jev.max_inflight): each connects within the gateway's
                connect budget (30% of --budget-ms) and is answered 200,
                the slowest with 2x headroom. A listen backlog smaller than
                the burst drops connections, and the gateway sees each as a
                timeout; a server out of workers answers 503
  latency       --samples sequential short requests; p99 with 2x headroom
  worst case    the longest text the gateway sends (--judge-bytes, the
                profile's max_judge_bytes), built to tokenize at about one
                token per byte, in the deployment context wording: first
                --samples of it one at a time, then --concurrency of it at
                once, in rounds, on warm connections. The client picks
                both the text and how many it sends at once, up to the
                gateway's max_inflight. Every request is answered 200 (a
                413 here is a bypass, and so is a 503), and the p99 at
                that concurrency fits with 2x headroom. A 503 sent after
                the gateway stopped reading (60% of --budget-ms) is named
                on its own: the gateway logs a timeout instead

--budget-ms is the L2 timeout floor the gateway runs with (jev.timeout_ms).
Under steady traffic the adaptive timeout sits at the floor, so a hostile
text that forces the worst case must fit it too. The gateway reads the
answer for 60% of it (resty/jev/http.lua: connect 30%, send 10%, read 60%),
so a timing check passes only with the headroom the run recommends: its p99
at most half of --budget-ms. The run ends with the timeout_ms to set, 2-3x
the worst-case p99 at --concurrency, or, when the server cannot answer that
many at once in time, the max_inflight it can. On CPU the worst case can be
tens of times the short-text p99, because a text split in N windows costs
about N model calls, and several of them at once take several times as
long again.

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
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))

# resty/jev/http.lua splits the L2 timeout: connect 30%, send 10%, read 60%.
CONNECT_SHARE, READ_SHARE = 0.3, 0.6
# A timing check passes at p99 x HEADROOM[0] <= --budget-ms; the run
# recommends a timeout_ms of HEADROOM[0]-HEADROOM[1] x the worst-case p99.
# At 2x the gateway's read wait is 1.2x the p99, room for the tail past it.
HEADROOM = (2, 3)


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


def raw_socket(t: Target, timeout: float | None = None):
    s = socket.create_connection((t.host, t.port), timeout=timeout or t.timeout)
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


def check_burst(t: Target, vectors, n: int, budget_ms: float) -> tuple[str | None, str]:
    """n fresh connections at once, as the gateway opens them when its
    keepalive pool is cold or used up: each must connect within the
    gateway's connect budget and be answered 200, the slowest with the
    headroom. The client retries a SYN that the server's listen queue
    dropped only after about a second, far past the connect budget, so the
    gateway sees a timeout. A 503 is a server that could not score n short
    texts at once in time."""
    body = short_body(t, vectors)
    connect_s = max(0.01, CONNECT_SHARE * budget_ms / 1000)
    start = threading.Barrier(n)
    cls = http.client.HTTPSConnection if t.https else http.client.HTTPConnection

    def one(_):
        try:
            start.wait(timeout=30)
        except threading.BrokenBarrierError:
            return "could not start", 0.0
        t0 = time.perf_counter()
        try:
            s = raw_socket(t, connect_s)
        except OSError as e:
            return f"connect {type(e).__name__}", (time.perf_counter() - t0) * 1000
        s.settimeout(t.timeout)
        c = cls(t.host, t.port, timeout=t.timeout)
        c.sock = s
        try:
            c.request("POST", t.map_path("/v1/systemone"), body=body, headers=t.headers())
            r = c.getresponse()
            r.read()
            return r.status, (time.perf_counter() - t0) * 1000
        except (http.client.HTTPException, OSError) as e:
            return f"request {type(e).__name__}", (time.perf_counter() - t0) * 1000
        finally:
            c.close()

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(one, range(n)))
    bad = {}
    for status, _ in results:
        if status != 200:
            bad[status] = bad.get(status, 0) + 1
    slowest = max(ms for _, ms in results)
    info = f"{n} at once, slowest {slowest:.1f} ms"
    if bad:
        what = ", ".join(f"{k}: {v}" for k, v in sorted(bad.items(), key=str))
        why = []
        if any(str(k).startswith("connect") for k in bad):
            why.append("A connect failure means a listen backlog under the burst (laya-server: LAYA_BACKLOG).")
        if 503 in bad:
            why.append("A 503 means the server could not score that many at once in time: add capacity "
                       "(laya-server: LAYA_WORKERS, CPUs), keep laya-server's LAYA_GATEWAY_TIMEOUT_MS at the "
                       "gateway's timeout_ms, or lower max_inflight. laya-server also answers 503 past "
                       "LAYA_MAX_CONNECTIONS.")
        return f"{sum(bad.values())} of {n} not answered 200 ({what}). {' '.join(why)}".rstrip(), info
    if over_headroom(slowest, budget_ms):
        return f"slowest answer {slowest:.1f} ms {needs(slowest, budget_ms)} ({info})", info
    return None, info


def over_headroom(ms: float, budget_ms: float) -> bool:
    return ms * HEADROOM[0] > budget_ms


def needs(ms: float, budget_ms: float) -> str:
    return (f"needs a timeout_ms of {math.ceil(ms * HEADROOM[0])} at {HEADROOM[0]}x headroom, over the "
            f"{budget_ms:.0f} ms budget (the gateway reads for {READ_SHARE:.0%} of it)")


def timed(t: Target, body: bytes, samples: int) -> tuple[str | None, list, bytes]:
    """samples sequential requests of body on one connection, after one that
    warms the connection and the model. Returns (error, sorted ms, last body)."""
    c = t.conn()
    lat, data = [], b""
    try:
        t.request("POST", "/v1/systemone", body, conn=c)
        for _ in range(samples):
            s, data, ms = t.request("POST", "/v1/systemone", body, conn=c)
            if s != 200:
                return f"status {s}", lat, data
            lat.append(ms)
    finally:
        c.close()
    lat.sort()
    return None, lat, data


def pct(lat: list, f: float) -> float:
    return lat[min(len(lat) - 1, int(math.ceil(f * len(lat))) - 1)]


def check_latency(t: Target, vectors, samples: int, budget_ms: float) -> tuple[str | None, str, float]:
    err, lat, _ = timed(t, short_body(t, vectors), samples)
    if err:
        return f"{err} during the latency run", "", 0.0
    p99 = pct(lat, 0.99)
    info = f"p50 {pct(lat, 0.5):.1f} ms, p99 {p99:.1f} ms over {samples}"
    if over_headroom(p99, budget_ms):
        return f"p99 {p99:.1f} ms {needs(p99, budget_ms)} ({info})", info, p99
    return None, info, p99


# Punctuation and rare letters, no whitespace. Most tokenizers give each of
# these characters a token of its own (WordPiece splits off every
# punctuation mark; byte-level BPE and SentencePiece have few merges for
# these pairs), so the text costs about one token per byte: the most windows
# a text of that size can force.
WORST_ALPHABET = "!#$%&()*+,-./:;<=>?@[]^_`{|}~'\"\\QXZJqxzjKVkv"
DEFAULT_ASSISTANT = "A support assistant for Acme's billing product: invoices, payment methods and refunds."


def worst_text(nbytes: int) -> str:
    """nbytes of ASCII from WORST_ALPHABET, the same on every run (a fixed
    LCG). It ends in " ATTACK", so --mock also shows the tail was judged."""
    tail = " ATTACK"
    x, out = 20240607, []
    for _ in range(max(0, nbytes - len(tail))):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(WORST_ALPHABET[(x >> 16) % len(WORST_ALPHABET)])
    return "".join(out) + tail


def worst_body(t: Target, nbytes: int, assistant: str, ctx_questions: dict) -> bytes:
    """The request the gateway sends for that text under a deployment
    context: object state, the _ctx wording (longer, so less room per
    window) and the llm-endpoints rule's one question."""
    state = {"assistant": assistant, "user_message": worst_text(nbytes)}
    return json.dumps({"model": t.model, "state": state,
                       "questions": {"injection": ctx_questions["injection"]}}).encode()


def at_once(t: Target, body: bytes, warm: bytes, n: int, rounds: int) -> list:
    """n clients, each on its own connection warmed by one `warm` request,
    send `body` at the same moment, `rounds` times: the gateway at
    max_inflight, every slot taken by the client's worst text. Returns one
    list of (status, ms) per round; a status that is not a number names the
    transport error."""
    start = threading.Barrier(n)
    out = [[("not sent", 0.0)] * n for _ in range(rounds)]

    def client(i):
        c = t.conn()
        try:
            try:
                t.request("POST", "/v1/systemone", warm, conn=c)
            except (http.client.HTTPException, OSError):
                c.close()  # the round's request says what is wrong
            for r in range(rounds):
                try:
                    start.wait(timeout=t.timeout + 30)
                except threading.BrokenBarrierError:
                    return
                t0 = time.perf_counter()
                try:
                    s, _, ms = t.request("POST", "/v1/systemone", body, conn=c)
                    out[r][i] = (s, ms)
                except (http.client.HTTPException, OSError) as e:
                    timed_out = isinstance(e, (socket.timeout, TimeoutError))
                    out[r][i] = ("timeout" if timed_out else type(e).__name__, (time.perf_counter() - t0) * 1000)
                    c.close()  # http.client opens a new one for the next round
        finally:
            c.close()

    with ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(client, range(n)))
    return out


class Worst:
    """What the worst-case check measured, for its advice and the closing
    timeout_ms line."""

    def __init__(self, n: int, budget_ms: float):
        self.n, self.budget_ms = n, budget_ms
        self.alone = 0.0      # p99, one at a time
        self.together = None  # p99 with n at once, when every one was answered 200
        self.fit = None       # the fewest answered 200 within the headroom in one round of n

    def advice(self) -> str:
        if over_headroom(self.alone, self.budget_ms):
            return (f"Alone it {needs(self.alone, self.budget_ms)}: raise timeout_ms to {span(self.alone)} "
                    f"and run again to size max_inflight, lower max_judge_bytes, or run the model on a GPU")
        if self.together is not None:
            return (f"Raise timeout_ms to {span(self.together)}, or lower max_inflight (summed over the "
                    f"gateways that call this server) or add capacity (CPUs) and run again")
        return (f"About {self.fit} of {self.n} at once are answered in time: set max_inflight (summed over "
                f"the gateways that call this server) to at most {max(1, self.fit or 0)}, add capacity "
                f"(CPUs, LAYA_WORKERS), or lower max_judge_bytes")


def check_worst(t: Target, body: bytes, warm: bytes, nbytes: int, samples: int, n: int,
                budget_ms: float, mock: bool) -> tuple[str | None, str, Worst]:
    """The worst text one at a time (answered 200 and judged whole), then n
    of it at once: every one answered 200, the p99 with the headroom, and a
    503 soon enough for the gateway to read it."""
    w = Worst(n, budget_ms)
    err, lat, data = timed(t, body, samples)
    if err:
        why = (": lower max_judge_bytes, or let the server judge more (laya-server: LAYA_MAX_WINDOWS)"
               if err == "status 413" else "")
        return (f"{err} for {nbytes} bytes one at a time, a text the gateway sends as is (max_judge_bytes). "
                f"An L2 error passes the request unjudged{why}"), "", w
    aerr, scores = check_answers(data, ["injection"])
    if aerr:
        return aerr, "", w
    if mock and scores["injection"] <= 0.5:
        return f"mock: injection = {scores['injection']:.3f} with ATTACK at the tail, want high", "", w
    windows = ""
    try:
        nw = json.loads(data).get("usage", {}).get("windows")
        windows = f", {nw} window{'' if nw == 1 else 's'}" if isinstance(nw, int) else ""
    except (ValueError, AttributeError):
        pass
    w.alone = pct(lat, 0.99)

    rounds = at_once(t, body, warm, n, max(2, math.ceil(samples / n)))
    flat = [x for r in rounds for x in r]
    ok = sorted(ms for s, ms in flat if s == 200)
    w.fit = min(sum(1 for s, ms in r if s == 200 and not over_headroom(ms, budget_ms)) for r in rounds)
    info = (f"alone p99 {w.alone:.1f} ms; {n} at once"
            + (f" p50 {pct(ok, 0.5):.1f} ms, p99 {pct(ok, 0.99):.1f} ms" if ok else "")
            + f" over {len(flat)}{windows}")
    problems = []
    bad = {}
    for s, _ in flat:
        if s != 200:
            bad[s] = bad.get(s, 0) + 1
    if bad:
        what = ", ".join(f"{k}: {v}" for k, v in sorted(bad.items(), key=str))
        problems.append(f"{sum(bad.values())} of {len(flat)} not answered 200 ({what}); an L2 error "
                        f"passes the request unjudged")
    else:
        w.together = pct(ok, 0.99)
        if over_headroom(w.together, budget_ms):
            problems.append(f"p99 {w.together:.1f} ms {needs(w.together, budget_ms)}")
    read_ms = READ_SHARE * budget_ms
    late = max((ms for s, ms in flat if s == 503 and ms > read_ms), default=None)
    if late is not None:
        problems.append(f"a 503 took {late:.0f} ms, after the gateway stopped reading at {read_ms:.0f} ms, "
                        f"so it logs a timeout instead: the server must refuse sooner (laya-server: "
                        f"LAYA_GATEWAY_TIMEOUT_MS at most the gateway's timeout_ms, {budget_ms:.0f} here)")
    if problems:
        return f"{'; '.join(problems)} ({info}). {w.advice()}", info, w
    return None, info, w


# ---------------------------------------------------------------------------


def span(ms: float) -> str:
    lo, hi = (math.ceil(k * ms) for k in HEADROOM)
    return f"{lo}-{hi}" if hi > lo else f"{hi}"


def timeout_line(w: Worst, short: float) -> str:
    """The closing advice: the timeout_ms that covers the worst case at the
    gateway's concurrency; when the server did not answer that many at once,
    what one at a time needs and, if that fits the budget, the max_inflight
    the server holds at it."""
    also = f"; short text: {short:.1f} ms" if short else ""
    why = (". Size the gateway's floor from the worst case: the client chooses the text, and how many "
           "it sends at once.")
    if w.together is not None:
        return (f"timeout_ms: {span(w.together)}, {HEADROOM[0]}-{HEADROOM[1]}x the worst-case p99 of "
                f"{w.together:.1f} ms with {w.n} at once (alone: {w.alone:.1f} ms{also})" + why)
    head = f"timeout_ms: {span(w.alone)} for the worst case one at a time (p99 {w.alone:.1f} ms{also}). "
    if over_headroom(w.alone, w.budget_ms):
        return head + (f"Run again with --budget-ms {math.ceil(w.alone * HEADROOM[0])} or more to see how many "
                       f"at once the server answers in time") + why
    return head + (f"With {w.n} at once, {w.fit} per round were answered in time at timeout_ms "
                   f"{w.budget_ms:.0f}: set max_inflight to at most {max(1, w.fit or 0)} there, or add "
                   f"capacity, and run again") + why


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--api-key", default=os.environ.get("JEV_CONFORMANCE_API_KEY") or None)
    ap.add_argument("--model", default="laya")
    ap.add_argument("--vectors", default=os.path.join(HERE, "vectors.json"))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--budget-ms", type=float, default=250.0,
                    help="the gateway's L2 timeout floor, jev.timeout_ms")
    ap.add_argument("--samples", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds per request")
    ap.add_argument("--judge-bytes", type=int, default=4096,
                    help="the longest text the gateway sends: the profile's max_judge_bytes")
    ap.add_argument("--concurrency", type=int, default=64,
                    help="requests at once in the burst and worst-case checks: the gateway's jev.max_inflight")
    ap.add_argument("--assistant", default=DEFAULT_ASSISTANT,
                    help="deployment context for the worst case: your jev.deployment_context")
    ap.add_argument("--questions", default=os.path.join(HERE, "questions.json"))
    args = ap.parse_args(argv)

    t = Target(args.endpoint, args.api_key, args.model, args.timeout)
    with open(args.vectors) as f:
        vectors = json.load(f)["cases"]
    with open(args.questions) as f:
        ctx_questions = json.load(f)["ctx"]

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

    within = f"within {args.budget_ms:.0f} ms with {HEADROOM[0]}x headroom"
    worst = worst_body(t, args.judge_bytes, args.assistant, ctx_questions)
    timing = [
        (f"burst: {args.concurrency} new connections at once, each answered {within}",
         lambda: check_burst(t, vectors, args.concurrency, args.budget_ms) + (0.0,)),
        (f"latency {within} at p99",
         lambda: check_latency(t, vectors, args.samples, args.budget_ms)),
        (f"worst case {within} at p99, {args.concurrency} at once: {args.judge_bytes} bytes at ~1 token "
         f"per byte, deployment context wording",
         lambda: check_worst(t, worst, short_body(t, vectors), args.judge_bytes, args.samples,
                             args.concurrency, args.budget_ms, args.mock)),
    ]
    measured = []
    for name, fn in timing:
        try:
            err, info, m = fn()
        except (http.client.HTTPException, OSError) as e:
            err, info, m = f"transport error: {e!r}", "", None
        report(name, err, info)
        measured.append(m)
    short, w = measured[1] or 0.0, measured[2]

    total = len(vectors) + len(checks) + len(timing)
    print(f"\n{total - failed}/{total} passed" + ("" if args.strict else "  (not --strict: exact error codes not checked)"))
    if w is not None and w.alone:
        print(timeout_line(w, short))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
