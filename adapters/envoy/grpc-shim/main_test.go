package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
)

func newServer(t *testing.T, h http.HandlerFunc) (*server, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &server{upstream: ts.URL + "/_jev/authz", client: &http.Client{Timeout: time.Second}}, ts
}

func checkReq(path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "POST", Path: path, Headers: headers, Body: `{"messages":[]}`,
		}},
	}}
}

func header(opts []*corev3.HeaderValueOption, key string) (string, bool) {
	for _, o := range opts {
		if o.Header.Key == key {
			return o.Header.Value, true
		}
	}
	return "", false
}

func TestDecisionCopiesHeadersAndRemovesMissing(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_jev/authz/v1/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("X-Jev-Verdict", "safe")
		w.Header().Set("X-Jev-Score", "0.20")
		w.WriteHeader(200)
	})
	res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions?x=1", map[string]string{"x-jev-verdict": "forged"}))
	ok := res.GetOkResponse()
	if res.Status.Code != int32(codes.OK) || ok == nil {
		t.Fatalf("expected OK, got %v", res)
	}
	if v, _ := header(ok.Headers, "X-Jev-Verdict"); v != "safe" {
		t.Fatalf("verdict = %q", v)
	}
	for _, o := range ok.Headers {
		if o.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Fatalf("%s not overwritten", o.Header.Key)
		}
	}
	if len(ok.HeadersToRemove) != 3 {
		t.Fatalf("headers_to_remove = %v", ok.HeadersToRemove)
	}
}

func TestBlockWithAnyStatusAndVerdict(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		w.Write([]byte(`{"error":"request rejected"}`))
	})
	res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
	d := res.GetDeniedResponse()
	if res.Status.Code != int32(codes.PermissionDenied) || d == nil {
		t.Fatalf("expected denied, got %v", res)
	}
	if int(d.Status.Code) != 429 || d.Body != `{"error":"request rejected"}` {
		t.Fatalf("status/body = %d %q", d.Status.Code, d.Body)
	}
}

// g2-block-response-verdict-oracle#3: Envoy puts DeniedHttpResponse.Headers
// on the reply to the client as they are, and the block handed it every
// X-Jev-* header of the authz answer: the score to two decimals, the
// question that fired and the source, an oracle to walk a prompt under the
// threshold. The client gets Content-Type, X-Jev-Verdict and
// X-Jev-Request-Id only; an allowed request still gets every header upstream.
func TestBlockHandsTheClientNoScoreReasonOrSource(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.Header().Set("X-Jev-Score", "0.97")
		w.Header().Set("X-Jev-Reason", "injection+0.97")
		w.Header().Set("X-Jev-Source", "cache")
		w.Header().Set("X-Jev-Request-Id", "req-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"request rejected"}`))
	})
	res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions", map[string]string{"x-jev-score": "forged"}))
	d := res.GetDeniedResponse()
	if res.Status.Code != int32(codes.PermissionDenied) || d == nil || d.Status.Code != 403 {
		t.Fatalf("expected a 403 deny, got %v", res)
	}
	for _, k := range []string{"X-Jev-Score", "X-Jev-Reason", "X-Jev-Source"} {
		if v, ok := header(d.Headers, k); ok {
			t.Fatalf("the blocked client gets %s: %q", k, v)
		}
	}
	want := map[string]string{"Content-Type": "application/json", "X-Jev-Verdict": "malicious", "X-Jev-Request-Id": "req-1"}
	if len(d.Headers) != len(want) {
		t.Fatalf("headers = %v, want %v", d.Headers, want)
	}
	for k, v := range want {
		if got, _ := header(d.Headers, k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	for _, o := range d.Headers {
		if o.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Fatalf("%s not overwritten", o.Header.Key)
		}
	}

	// without a request id or a content type, only the verdict
	s, _ = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.Header().Set("X-Jev-Score", "1.00")
		w.Header().Set("X-Jev-Reason", "ip+reputation")
		w.Header()["Content-Type"] = nil
		w.WriteHeader(429)
	})
	res, _ = s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
	d = res.GetDeniedResponse()
	if d == nil || len(d.Headers) != 1 {
		t.Fatalf("expected a deny with X-Jev-Verdict only, got %v", res)
	}
	if v, _ := header(d.Headers, "X-Jev-Verdict"); v != "malicious" {
		t.Fatalf("verdict = %q", v)
	}

	// the allow path still copies score, reason and source upstream
	s, _ = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jev-Verdict", "suspicious")
		w.Header().Set("X-Jev-Score", "0.60")
		w.Header().Set("X-Jev-Reason", "injection+0.60")
		w.Header().Set("X-Jev-Source", "l2")
		w.Header().Set("X-Jev-Request-Id", "req-2")
	})
	res, _ = s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
	ok := res.GetOkResponse()
	if ok == nil || len(ok.Headers) != 5 || len(ok.HeadersToRemove) != 0 {
		t.Fatalf("expected every X-Jev-* header upstream, got %v", res)
	}
}

// An answer without X-Jev-Verdict below 500 (nginx refusing an oversized
// header or URI with 400 / 414 before jev-edge runs, or something that is
// not jev-edge) is unjudgeable: passed marked skipped, never an unmarked
// pass or an `error`.
func TestUnjudgeableWithoutVerdictHeader(t *testing.T) {
	for _, status := range []int{400, 414, 413, 404, 403, 200} {
		s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
		ok := res.GetOkResponse()
		if res.Status.Code != int32(codes.OK) || ok == nil {
			t.Fatalf("status %d: expected OK, got %v", status, res)
		}
		for k, want := range map[string]string{"X-Jev-Verdict": "skipped", "X-Jev-Score": "0.00", "X-Jev-Source": "shim",
			"X-Jev-Reason": fmt.Sprintf("unjudgeable%%3A+authz+answered+%d", status)} {
			if v, _ := header(ok.Headers, k); v != want {
				t.Fatalf("status %d: %s = %q, want %q", status, k, v, want)
			}
		}
		for _, o := range ok.Headers {
			if o.AppendAction != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Fatalf("status %d: %s not overwritten", status, o.Header.Key)
			}
		}
		if len(ok.HeadersToRemove) != 1 || ok.HeadersToRemove[0] != "X-Jev-Request-Id" {
			t.Fatalf("status %d: headers_to_remove = %v", status, ok.HeadersToRemove)
		}
	}
}

// -unjudged=block denies the same answers with 403 and the default block body.
func TestUnjudgeableBlock(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) })
	s.unjudged = "block"
	res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
	d := res.GetDeniedResponse()
	if res.Status.Code != int32(codes.PermissionDenied) || d == nil {
		t.Fatalf("expected denied, got %v", res)
	}
	if int(d.Status.Code) != 403 || d.Body != `{"error":"request rejected"}` {
		t.Fatalf("status/body = %d %q", d.Status.Code, d.Body)
	}
	if v, _ := header(d.Headers, "Content-Type"); v != "application/json" {
		t.Fatalf("content-type = %q", v)
	}
}

// The adapter failing is still `error` (fail-open), not unjudgeable, even
// with -unjudged=block: a 5xx without X-Jev-Verdict, or no answer at all.
func TestFailOpenWhenAdapterFails(t *testing.T) {
	for _, status := range []int{500, 502, 503, 0} {
		s, ts := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		if status == 0 {
			ts.Close()
		}
		s.unjudged = "block"
		res, _ := s.Check(context.Background(), checkReq("/v1/chat/completions", nil))
		ok := res.GetOkResponse()
		if ok == nil {
			t.Fatalf("status %d: expected fail-open, got %v", status, res)
		}
		if v, _ := header(ok.Headers, "X-Jev-Verdict"); v != "error" {
			t.Fatalf("status %d: verdict = %q", status, v)
		}
		if v, _ := header(ok.Headers, "X-Jev-Source"); v != "shim" {
			t.Fatalf("status %d: source = %q", status, v)
		}
		if len(ok.HeadersToRemove) != 3 {
			t.Fatalf("status %d: headers_to_remove = %v", status, ok.HeadersToRemove)
		}
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

// A dot segment, an encoded dot or a doubled slash used to fail open
// (X-Jev-Verdict: error) while nginx inline resolves them and judges the
// path; Istio, for one, does not merge slashes by default, so
// /v1//chat/completions reached the shim and passed unjudged. Now the
// adapter judges the path nginx reads, and the forwarded one cannot climb
// out of /_jev/authz/: /x/../_jev/metrics is judged as the path
// /_jev/metrics. A ".." above the root, or a path that does not start with
// '/', is denied with 400, as nginx refuses it.
func TestDotSegmentsAndDoubledSlashesAreJudged(t *testing.T) {
	var got string
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.Header().Set("X-Jev-Verdict", "malicious")
		w.WriteHeader(403)
	})
	for p, want := range map[string]string{
		"/v1/x/../chat/completions": "/v1/chat/completions", "/v1/x/%2e%2e/chat/completions": "/v1/chat/completions",
		"/v1/x/%2E%2E/chat/completions": "/v1/chat/completions", "/v1/x/..%2fchat/completions": "/v1/chat/completions",
		"/v1//chat/completions": "/v1/chat/completions", "//v1/chat/completions": "/v1/chat/completions",
		"/v1/./chat/completions": "/v1/chat/completions", "/v1/chat/completions/.": "/v1/chat/completions/",
		"/x/../_jev/metrics": "/_jev/metrics", "/x/%2e%2e/_jev/authz/../metrics?a=/../b": "/_jev/metrics",
		"": "/",
	} {
		for _, unj := range []string{"pass", "block"} {
			s.unjudged = unj
			res, _ := s.Check(context.Background(), checkReq(p, nil))
			if d := res.GetDeniedResponse(); d == nil || d.Status.Code != 403 {
				t.Fatalf("-unjudged=%s %q: expected jev-edge's 403, got %v", unj, p, res)
			}
			if got != "/_jev/authz"+want {
				t.Fatalf("%q: adapter saw %q, want %q", p, got, "/_jev/authz"+want)
			}
		}
	}
	for _, p := range []string{"/../v1/chat/completions", "/v1/../../_jev/metrics", "/v1/%2e%2e/%2e%2e/_jev/metrics", "/..", "v1/chat", "*"} {
		got = ""
		res, _ := s.Check(context.Background(), checkReq(p, nil))
		if d := res.GetDeniedResponse(); d == nil || d.Status.Code != 400 || got != "" {
			t.Fatalf("%q: expected 400 without asking the adapter, got %v (adapter saw %q)", p, res, got)
		}
	}
}

// Paths nginx refuses with 400 before jev-edge runs: a '%' without two hex
// digits after it (IIS-style %u0063, a bare %, %zz, a cut-off %4) and a %00;
// and a control character, which Go cannot put in a URL. cpp-httplib
// (llama.cpp) decodes %u0063 to 'c', so /v1/%u0063ompletions is
// /v1/completions there.
var malformedPaths = []string{
	"/v1/%u0063ompletions", "/%u0063ompletion", "/v1%u002fchat/completions", "/v1/chat/%U0063ompletions",
	"/v1/chat/completions%", "/v1/%zzchat/completions", "/v1/chat/completions%4", "/v1/%u0063ompletions?stream=true",
	"/v1/chat/completions%00", "/v1/comp\x01letions", "/v1/comp\x7fletions",
	// refused with 400 even with a dot segment or a doubled slash
	"/v1//%u0063ompletions", "/v1/../%zz", "/v1/%2e%2e/%u002f", "v1/%u0063ompletions",
}

// They are denied with 400, as nginx answers them inline and Envoy's HTTP
// ext_authz hands that 400 on, whatever -unjudged says; before, Go could not
// build the authz URL for most of them and the shim failed open.
func TestMalformedPathIsDeniedWith400(t *testing.T) {
	called := false
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	for _, unj := range []string{"pass", "block"} {
		s.unjudged = unj
		for _, p := range malformedPaths {
			res, _ := s.Check(context.Background(), checkReq(p, nil))
			d := res.GetDeniedResponse()
			if res.Status.Code != int32(codes.PermissionDenied) || d == nil {
				t.Fatalf("-unjudged=%s %q: expected denied, got %v", unj, p, res)
			}
			if int(d.Status.Code) != 400 || d.Body != `{"error":"request rejected"}` {
				t.Fatalf("-unjudged=%s %q: status/body = %d %q", unj, p, d.Status.Code, d.Body)
			}
			if v, _ := header(d.Headers, "Content-Type"); v != "application/json" || len(d.Headers) != 1 {
				t.Fatalf("-unjudged=%s %q: headers = %v", unj, p, d.Headers)
			}
		}
	}
	if called {
		t.Fatal("adapter was called for a malformed path")
	}
}

// Well-formed escapes reach the adapter as nginx reads them inline: UTF-8,
// an escaped control character, and escapes of bytes that are not UTF-8
// (the overlong %C0%AE, %FF), which nginx, Envoy and HAProxy take and
// jev-edge judges; a decoded '%' stays a '%'. The query string is not the
// path and is not checked.
func TestWellFormedEscapesAreForwardedAsNginxReadsThem(t *testing.T) {
	var got string
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
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
		res, _ := s.Check(context.Background(), checkReq(p+"?x=%zz", nil))
		if res.GetOkResponse() == nil {
			t.Fatalf("%q: expected OK, got %v", p, res)
		}
		if got != "/_jev/authz"+want {
			t.Fatalf("%q: adapter saw %q, want %q", p, got, "/_jev/authz"+want)
		}
	}
}
