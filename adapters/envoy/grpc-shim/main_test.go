package main

import (
	"context"
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

func TestFailOpenWithoutVerdictHeader(t *testing.T) {
	for _, status := range []int{404, 403, 500, 200} {
		s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
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
