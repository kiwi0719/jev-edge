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

func TestUnsafePathsAreNotForwarded(t *testing.T) {
	called := false
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { called = true })
	for _, p := range []string{"/v1/../config", "/v1/%2e%2e/config", "/v1/%2E%2E/config", "/v1//config", "v1/chat"} {
		res, _ := s.Check(context.Background(), checkReq(p, nil))
		if v, _ := header(res.GetOkResponse().GetHeaders(), "X-Jev-Verdict"); v != "error" {
			t.Fatalf("%s: expected fail-open, got %v", p, res)
		}
	}
	if called {
		t.Fatal("adapter was called for an unsafe path")
	}
}

// Paths the shim cannot relay as the backend reads them: a '%' without two
// hex digits after it (IIS-style %u0063, a bare %, %zz, a cut-off %4), a %00,
// a control character, an overlong UTF-8 form. cpp-httplib (llama.cpp)
// decodes %u0063 to 'c', so /v1/%u0063ompletions is /v1/completions there.
var malformedPaths = []string{
	"/v1/%u0063ompletions", "/%u0063ompletion", "/v1%u002fchat/completions", "/v1/chat/%U0063ompletions",
	"/v1/chat/completions%", "/v1/%zzchat/completions", "/v1/chat/completions%4", "/v1/%u0063ompletions?stream=true",
	"/v1/chat/completions%00", "/v1/comp\x01letions", "/v1/comp\x7fletions",
	"/v1/%C0%AEchat/completions", "/v1%C0%AFchat/completions", "/v1/%E0%80%AE/completions", "/v1/%FFchat",
	// refused with 400 even when safePath would also refuse them
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

// Well-formed escapes, UTF-8 included, still reach the adapter as sent; the
// query string is not the path and is not checked.
func TestWellFormedEscapesAreForwardedAsSent(t *testing.T) {
	var got string
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.Header().Set("X-Jev-Verdict", "safe")
	})
	for _, p := range []string{"/v1/%63ompletions", "/v1/chat%2Fcompletions", "/v1/models/%E6%A8%A1%E5%9E%8B", "/v1/a%25b", "/v1/%0a"} {
		res, _ := s.Check(context.Background(), checkReq(p+"?x=%zz", nil))
		if res.GetOkResponse() == nil {
			t.Fatalf("%q: expected OK, got %v", p, res)
		}
		if got != "/_jev/authz"+p {
			t.Fatalf("%q: adapter saw %q", p, got)
		}
	}
}
