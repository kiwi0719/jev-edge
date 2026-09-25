package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestCopyHeadersDropsClientIPAndVerdict(t *testing.T) {
	h := http.Header{}
	copyHeaders(h, "Host: api\r\nX-Envoy-External-Address: 6.6.6.6\r\nx-real-ip: 6.6.6.6\r\n"+
		"X-Forwarded-For: 6.6.6.6\r\nX-Jev-Verdict: allow\r\nAuthorization: Bearer t\r\nUser-Agent: ua\r\n")
	for _, k := range []string{"Host", "X-Envoy-External-Address", "X-Real-Ip", "X-Forwarded-For", "X-Jev-Verdict"} {
		if v := h.Get(k); v != "" {
			t.Errorf("%s forwarded as %q", k, v)
		}
	}
	if h.Get("Authorization") != "Bearer t" || h.Get("User-Agent") != "ua" {
		t.Errorf("ordinary headers dropped: %v", h)
	}
}

func TestSafePath(t *testing.T) {
	for p, want := range map[string]bool{"/v1/chat": true, "": false, "v1": false, "/a/../b": false, "/a/%2E%2E/b": false, "//x": false} {
		if got := safePath(p); got != want {
			t.Errorf("safePath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestPartialBody(t *testing.T) {
	for _, c := range []struct {
		declared string
		got      int
		want     bool
	}{{"200000", 131000, true}, {"100", 100, false}, {"", 50, false}, {"x", 50, false}} {
		if partialBody(c.declared, c.got) != c.want {
			t.Errorf("partialBody(%q, %d) != %v", c.declared, c.got, c.want)
		}
	}
}

// authz points the agent at a stub /_jev/authz for one test.
func authz(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	oldUp, oldClient, oldUnj := *upstream, client, *unjudged
	*upstream, client = ts.URL+"/_jev/authz", &http.Client{Timeout: time.Second}
	t.Cleanup(func() { *upstream, client, *unjudged = oldUp, oldClient, oldUnj })
}

func msg(args map[string]string) func(string) string {
	return func(k string) string { return args[k] }
}

// Every Content-Type the client sent reaches jev-edge, not only the last one
// (req.hdr(content-type) in an older spoe.conf), so a request is watched when
// any of them is. A stale `ct` argument is ignored.
func TestEveryContentTypeReachesJevEdge(t *testing.T) {
	var got []string
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values("Content-Type")
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "ct": "image/png",
		"hdrs": "host: api\r\ncontent-type: application/json\r\ncontent-type: image/png\r\n\r\n", "body": "{}"}))
	if want := []string{"application/json", "image/png"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Content-Type at jev-edge = %q, want %q", got, want)
	}
	check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions",
		"hdrs": "content-type: application/json; charset=utf-8, image/png\r\n\r\n", "body": "{}"}))
	if want := []string{"application/json; charset=utf-8, image/png"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Content-Type at jev-edge = %q, want %q", got, want)
	}
}

// An answer without X-Jev-Verdict (nginx refusing an oversized header or URI
// before jev-edge runs) is unjudgeable: marked skipped and passed, or blocked
// with -unjudged=block; never an unmarked pass or an `error`.
func TestAnswerWithoutVerdictIsUnjudgeable(t *testing.T) {
	for _, status := range []int{400, 413, 414, 404, 200} {
		authz(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		*unjudged = "pass"
		req := msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "body": "{}"})
		v := check(req)
		want := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
			"reason": "unjudgeable%3A+authz+answered+" + strconv.Itoa(status), "action": "pass", "rid": "", "status": "0"}
		if !reflect.DeepEqual(v, want) {
			t.Fatalf("status %d: vars = %v, want %v", status, v, want)
		}
		*unjudged = "block"
		v = check(req)
		if v["verdict"] != "skipped" || v["action"] != "block" || v["status"] != "403" {
			t.Fatalf("status %d, -unjudged=block: vars = %v", status, v)
		}
	}
}

// jev-edge's own answers are unchanged: a decision passes, a verdict with a
// status >= 400 blocks with that status. A 5xx without a verdict (the
// server failing) and an unreachable jev-edge fail open as `error`, even
// with -unjudged=block.
func TestDecisionBlockAndFailOpen(t *testing.T) {
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.WriteHeader(429)
	})
	*unjudged = "block"
	if v := check(msg(map[string]string{"path": "/v1/chat/completions"})); v["action"] != "block" || v["status"] != "429" || v["verdict"] != "malicious" {
		t.Fatalf("block: vars = %v", v)
	}
	authz(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })
	*unjudged = "block"
	if v := check(msg(map[string]string{"path": "/v1/chat/completions"})); v["verdict"] != "error" || v["action"] != "pass" || v["reason"] != "http 502" {
		t.Fatalf("502 without verdict: vars = %v", v)
	}
	*upstream = "http://127.0.0.1:1/_jev/authz"
	if v := check(msg(map[string]string{"path": "/v1/chat/completions"})); v["verdict"] != "error" || v["action"] != "pass" {
		t.Fatalf("unreachable: vars = %v", v)
	}
}
