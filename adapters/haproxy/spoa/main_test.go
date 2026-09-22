package main

import (
	"net/http"
	"testing"
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
