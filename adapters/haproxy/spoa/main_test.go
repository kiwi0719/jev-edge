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

// normalizePath gives the path nginx reads into $uri (each case checked
// against openresty 1.31), escaped again: %XX decoded, a decoded '/' or '.'
// taken as path syntax, doubled slashes merged, "." and ".." resolved, a
// trailing slash kept; "" where nginx answers 400.
var normalized = map[string]string{
	"/v1/chat/completions": "/v1/chat/completions", "/": "/", "/v1/chat/": "/v1/chat/",
	"/a/../b": "/b", "/a/%2E%2E/b": "/b", "/a/%2e./b": "/b", "/a/.%2e/b": "/b", "/a/..%2Fb": "/b",
	"//x": "/x", "/v1//chat///completions": "/v1/chat/completions", "/a/%2F/b": "/a/b", "/a%2F%2Fb": "/a/b",
	"/a/./b/": "/a/b/", "/a/.": "/a/", "/a/b/..": "/a/", "/a/..": "/", "/.": "/", "//": "/", "/%2e": "/",
	"/a/%2e%2e%2f": "/", "/a/b%2f..%2fc": "/a/c",
	"/a/...": "/a/...", "/a/.b": "/a/.b", "/a/b..": "/a/b..",
	// a decoded '%' is only a '%': no second decoding
	"/a/%252e%252e/x": "/a/%252e%252e/x", "/a/%25": "/a/%25",
	// a decoded '?' or '#' is part of the path
	"/a/%3F": "/a/%3F", "/a/%23b": "/a/%23b",
	// bytes that are not UTF-8, the overlong %C0%AE included, are not a '.'
	"/a/%C0%AE%C0%AE/x": "/a/%C0%AE%C0%AE/x", "/a/%c0%ae": "/a/%C0%AE", "/a/%FF": "/a/%FF",
	"/a/%0a": "/a/%0A", "/a%20b": "/a%20b", "/a+b": "/a+b", "/a;b": "/a;b", "/a%5c..%5cb": "/a%5C..%5Cb",
	// what a path may carry as it is stays as it is (the path never grows)
	"/a/%21%24%26%27%28%29%2A%2B%2C%3B%3D%3A%40%5B%5D": "/a/!$&'()*+,;=:@[]", "/a/!*()": "/a/!*()",
	"/a/%63hat": "/a/chat", "/a/%7E%2D%2E%5F": "/a/~-._",
	// nginx: 400
	"/..": "", "/../x": "", "/a/../../x": "", "/%2e%2e/x": "", "/a/%2e%2e%2f%2e%2e/x": "", "/a/..%2f..%2fb": "",
	"": "", "v1": "", "*": "", "%2Fa": "",
}

func TestNormalizePath(t *testing.T) {
	for p, want := range normalized {
		got, ok := normalizePath(p)
		if !ok {
			got = ""
		}
		if got != want || (want == "") == ok {
			t.Errorf("normalizePath(%q) = %q, %v; want %q", p, got, ok, want)
		}
	}
}

// /_jev/authz trusts x-envoy-auth-partial-body as Envoy's cut flag and
// X-Jev-Body-Partial as the agent's. A client's copy of either would mark a
// whole body cut (with policy.partial = "unjudgeable", a request nobody
// judges): neither reaches jev-edge, and the agent sets its own flag from
// HAProxy's body size alone.
func TestClientCutFlagsNeverReachJevEdge(t *testing.T) {
	var got http.Header
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	forged := "content-type: application/json\r\nX-Envoy-Auth-Partial-Body: true\r\nx-envoy-auth-partial-body: true\r\n" +
		"X-Jev-Body-Partial: 1\r\n\r\n"
	check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "hdrs": forged, "body": "{}", "size": "2"}))
	if v := got.Values("X-Envoy-Auth-Partial-Body"); len(v) != 0 {
		t.Fatalf("a client's x-envoy-auth-partial-body reached jev-edge: %q", v)
	}
	if v := got.Values("X-Jev-Body-Partial"); len(v) != 0 {
		t.Fatalf("a client's X-Jev-Body-Partial reached jev-edge: %q", v)
	}
	check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "hdrs": forged, "body": "{}", "size": "200000"}))
	if v := got.Values("X-Jev-Body-Partial"); len(v) != 1 || v[0] != "1" || len(got.Values("X-Envoy-Auth-Partial-Body")) != 0 {
		t.Fatalf("cut body: X-Jev-Body-Partial %q, x-envoy-auth-partial-body %q", v, got.Values("X-Envoy-Auth-Partial-Body"))
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

// A path nginx refuses with 400 before jev-edge runs: a '%' without two hex
// digits after it (IIS-style %u0063, a bare %, %zz, a cut-off %4) or a %00;
// or a control character, which Go cannot put in a URL. cpp-httplib
// (llama.cpp) decodes %u0063 to 'c', so /v1/%u0063ompletions is
// /v1/completions there. It is blocked with 400 as nginx answers it inline,
// whatever -unjudged says, and jev-edge is not asked; before, Go could not
// build the authz URL for most of them and the agent failed open.
func TestMalformedPathIsBlockedWith400(t *testing.T) {
	called := false
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	want := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": "invalid+path", "action": "block", "rid": "", "status": "400"}
	for _, unj := range []string{"pass", "block"} {
		*unjudged = unj
		for _, p := range []string{
			"/v1/%u0063ompletions", "/%u0063ompletion", "/v1%u002fchat/completions", "/v1/chat/%U0063ompletions",
			"/v1/chat/completions%", "/v1/%zzchat/completions", "/v1/chat/completions%4",
			"/v1/chat/completions%00", "/v1/comp\x01letions", "/v1/comp\x7fletions",
			// refused with 400 even with a dot segment or a doubled slash
			"/v1//%u0063ompletions", "/v1/../%zz", "/v1/%2e%2e/%u002f", "v1/%u0063ompletions",
		} {
			if v := check(msg(map[string]string{"method": "POST", "path": p, "body": "{}"})); !reflect.DeepEqual(v, want) {
				t.Fatalf("-unjudged=%s %q: vars = %v, want %v", unj, p, v, want)
			}
		}
	}
	if called {
		t.Fatal("jev-edge was asked about a malformed path")
	}
}

// Well-formed escapes reach jev-edge as nginx reads them inline: UTF-8, an
// escaped control character, and escapes of bytes that are not UTF-8 (the
// overlong %C0%AE, %FF), which nginx and HAProxy take and jev-edge judges;
// a decoded '%' stays a '%'.
func TestWellFormedEscapesAreForwardedAsNginxReadsThem(t *testing.T) {
	var got string
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	for p, want := range map[string]string{
		"/v1/%63ompletions": "/v1/completions", "/v1/chat%2Fcompletions": "/v1/chat/completions",
		"/v1/models/%E6%A8%A1%E5%9E%8B": "/v1/models/%E6%A8%A1%E5%9E%8B", "/v1/a%25b": "/v1/a%25b", "/v1/%0a": "/v1/%0A",
		"/v1/%01x": "/v1/%01x", "/v1/%C0%AEchat/completions": "/v1/%C0%AEchat/completions",
		"/v1%C0%AFchat/completions": "/v1%C0%AFchat/completions", "/v1/%E0%80%AE/completions": "/v1/%E0%80%AE/completions",
		"/v1/%FFchat": "/v1/%FFchat", "/v1/%c0%ae": "/v1/%C0%AE", "/v1/a%2500": "/v1/a%2500",
		"/v1/chat/completions#x": "/v1/chat/completions", "/v1/chat%23x": "/v1/chat%23x",
	} {
		if v := check(msg(map[string]string{"method": "POST", "path": p, "body": "{}"})); v["verdict"] != "safe" || v["action"] != "pass" {
			t.Fatalf("%q: vars = %v", p, v)
		}
		if got != "/_jev/authz"+want {
			t.Fatalf("%q: jev-edge saw %q, want %q", p, got, "/_jev/authz"+want)
		}
	}
}

// A dot segment, an encoded dot or a doubled slash used to fail open
// (verdict=error, action=pass) while nginx inline resolves them and judges
// the path: /v1/x/../chat/completions passed unjudged. Now jev-edge judges
// the path nginx reads, and the forwarded one cannot climb out of
// /_jev/authz/: /x/../_jev/metrics is judged as the path /_jev/metrics. A
// ".." above the root is refused with 400, as nginx refuses it.
func TestDotSegmentsAndDoubledSlashesAreJudged(t *testing.T) {
	var got string
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.WriteHeader(403)
	})
	for p, want := range map[string]string{
		"/v1/x/../chat/completions": "/v1/chat/completions", "/v1/x/%2e%2e/chat/completions": "/v1/chat/completions",
		"/v1/x/%2E%2E/chat/completions": "/v1/chat/completions", "/v1/x/..%2fchat/completions": "/v1/chat/completions",
		"/v1//chat/completions": "/v1/chat/completions", "//v1/chat/completions": "/v1/chat/completions",
		"/v1/./chat/completions": "/v1/chat/completions", "/v1/chat/completions/.": "/v1/chat/completions/",
		"/x/../_jev/metrics": "/_jev/metrics", "/x/%2e%2e/_jev/authz/../metrics": "/_jev/metrics",
	} {
		for _, unj := range []string{"pass", "block"} {
			*unjudged = unj
			if v := check(msg(map[string]string{"method": "POST", "path": p, "body": "{}"})); v["verdict"] != "malicious" || v["action"] != "block" || v["status"] != "403" {
				t.Fatalf("-unjudged=%s %q: vars = %v", unj, p, v)
			}
			if got != "/_jev/authz"+want {
				t.Fatalf("%q: jev-edge saw %q, want %q", p, got, "/_jev/authz"+want)
			}
		}
	}
	want := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": "invalid+path", "action": "block", "rid": "", "status": "400"}
	for _, p := range []string{"/../v1/chat/completions", "/v1/../../_jev/metrics", "/v1/%2e%2e/%2e%2e/_jev/metrics", "/.."} {
		got = ""
		if v := check(msg(map[string]string{"method": "POST", "path": p, "body": "{}"})); !reflect.DeepEqual(v, want) || got != "" {
			t.Fatalf("%q: vars = %v, jev-edge saw %q", p, v, got)
		}
	}
}

// net/http refuses to send a header whose name is not a token or whose
// value has a control character in it, and that error failed the agent
// open (verdict=error, action=pass): one crafted header turned judging off.
// A name that is not a token is left out, as nginx leaves it out inline,
// and the request is judged.
func TestHeaderNameNetHTTPCannotSendIsLeftOut(t *testing.T) {
	var got http.Header
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.WriteHeader(403)
	})
	for _, name := range []string{"x(bad)", "x-bad\"", "x-\xffa", "x\x01a", "x/a", "x a"} {
		got = nil
		v := check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "body": "{}",
			"hdrs": "content-type: application/json\r\n" + name + ": 1\r\nx-ok: a\tb\r\n\r\n"}))
		if v["verdict"] != "malicious" || v["action"] != "block" || v["status"] != "403" {
			t.Fatalf("%q: vars = %v, want jev-edge's verdict", name, v)
		}
		if got.Get("Content-Type") != "application/json" || got.Get("X-Ok") != "a\tb" {
			t.Fatalf("%q: headers at jev-edge = %v", name, got)
		}
		for k := range got {
			if !validToken(k) {
				t.Fatalf("%q: forwarded as %q", name, k)
			}
		}
	}
}

// A header value with a control character is one nginx takes and jev-edge
// reads inline; left out, it could hide the Content-Type or the subject
// header jev-edge judges by. It is refused with 400, whatever -unjudged
// says, and jev-edge is not asked. A skipped header is never forwarded, so
// a control character in it changes nothing.
func TestHeaderValueNetHTTPCannotSendIsRefusedWith400(t *testing.T) {
	called := false
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	want := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": "invalid+header", "action": "block", "rid": "", "status": "400"}
	for _, unj := range []string{"pass", "block"} {
		*unjudged = unj
		for _, h := range []string{"content-type: application/json\x01", "x-a: a\x01b", "x-a: a\x7fb", "x-a: \x1b[31mred",
			"authorization: Bearer t\x0bu", "x-a: a\x00b"} {
			v := check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "body": "{}",
				"hdrs": "content-type: application/json\r\n" + h + "\r\n\r\n"}))
			if !reflect.DeepEqual(v, want) {
				t.Fatalf("-unjudged=%s %q: vars = %v, want %v", unj, h, v, want)
			}
		}
	}
	if called {
		t.Fatal("jev-edge was asked about a header net/http cannot send")
	}
	*unjudged = "pass"
	v := check(msg(map[string]string{"method": "POST", "path": "/v1/chat/completions", "body": "{}",
		"hdrs": "x-forwarded-for: 6.6.6.6\x01\r\nhost: a\x01\r\nx-jev-verdict: \x01\r\n\r\n"}))
	if v["verdict"] != "safe" || !called {
		t.Fatalf("control character in a skipped header: vars = %v", v)
	}
}

// A method net/http cannot send (not a token; nginx refuses it with 400
// too) is refused with 400 instead of failing open. One that is a token
// goes to jev-edge as before.
func TestMethodNetHTTPCannotSendIsRefusedWith400(t *testing.T) {
	var method string
	authz(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	want := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": "invalid+method", "action": "block", "rid": "", "status": "400"}
	for _, m := range []string{"GE(T", "GET POST", "G\x01T", "P\xffST", "GET/1"} {
		method = ""
		if v := check(msg(map[string]string{"method": m, "path": "/v1/chat/completions", "body": "{}"})); !reflect.DeepEqual(v, want) || method != "" {
			t.Fatalf("%q: vars = %v, jev-edge saw %q", m, v, method)
		}
	}
	for _, m := range []string{"PATCH", "get", "M-SEARCH"} {
		if v := check(msg(map[string]string{"method": m, "path": "/v1/chat/completions", "body": "{}"})); v["verdict"] != "safe" || method != m {
			t.Fatalf("%q: vars = %v, jev-edge saw %q", m, v, method)
		}
	}
}
