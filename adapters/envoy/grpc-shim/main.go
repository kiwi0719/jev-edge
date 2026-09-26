// jev-edge gRPC ext_authz shim.
//
// Implements envoy.service.auth.v3.Authorization.Check by forwarding each
// request to the OpenResty adapter's HTTP ext_authz endpoint (/_jev/authz)
// and translating the answer into a CheckResponse. No judgment logic lives
// here: it is a protocol converter so gRPC-configured Envoy meshes can use the
// same Lua code path as everyone else.
//
// Contract: only an answer that carries X-Jev-Verdict is trusted. 200 with the
// header is a decision (OK, headers copied upstream); status >= 400 with the
// header is a block (PermissionDenied with that status and body, and only
// Content-Type, X-Jev-Verdict and X-Jev-Request-Id for the client).
// An answer without the header below 500 (nginx refusing the request before
// jev-edge runs: 400, 413, 414; a 404 from something that is not jev-edge)
// means nobody judged it: X-Jev-Verdict: skipped with reason
// "unjudgeable: ...", passed or denied (403) as -unjudged says, like
// jev-edge's policy.unjudgeable. Any other answer (a 5xx without the
// header included), and any error talking to the adapter, fails open: OK
// with X-Jev-Verdict: error and X-Jev-Source: shim, matching the adapter's
// own behaviour. Every X-Jev-* header is overwritten on the way upstream so
// a forged inbound value never survives. The path the adapter judges is
// the one nginx reads inline: escapes decoded, "." and ".." segments
// (%2e%2e too) resolved and doubled slashes merged, then escaped again, so
// it cannot climb out of /_jev/authz/ to the adapter's admin endpoints. A
// path nginx refuses with 400 before jev-edge runs (a '%' without two hex
// digits after it, such as the IIS-style %u0063 that cpp-httplib under
// llama.cpp decodes to 'c', a %00, a ".." above the root) or that Go cannot
// put in a URL (a control character) is denied with 400, as nginx answers
// it inline, whatever -unjudged says: it is the client's error, so it
// never fails open.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var jevHeaders = []string{"X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id"}

type server struct {
	authv3.UnimplementedAuthorizationServer
	upstream string // e.g. http://openresty:8080/_jev/authz
	client   *http.Client
	unjudged string // "pass" or "block": an answer without X-Jev-Verdict
}

func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return failOpen("no http attributes"), nil
	}

	method := httpReq.GetMethod()
	if method == "" {
		method = http.MethodGet
	}
	path := httpReq.GetPath()
	if path == "" {
		path = "/"
	}
	// the query, and a fragment: nginx ends $uri at a '#' (net/url would
	// have taken the rest for the URL's fragment and not sent it). A :path
	// of "?x" leaves nothing, which normalizePath refuses with 400, as nginx
	// refuses a target that does not start with '/' (Envoy itself answers
	// such a :path with 404 before ext_authz runs)
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	// a dot segment, an encoded dot or a doubled slash (Istio, for one, does
	// not merge slashes by default) is judged the way nginx reads it inline,
	// never failed open: forwarded as sent, it could reach the adapter's
	// admin endpoints next to /_jev/authz
	norm, ok := "", wellFormedPath(path)
	if ok {
		norm, ok = normalizePath(path)
	}
	if !ok {
		return badPath(path), nil
	}
	url := s.upstream + norm

	var body io.Reader
	if raw := httpReq.GetRawBody(); len(raw) > 0 {
		body = bytes.NewReader(raw)
	} else if b := httpReq.GetBody(); b != "" {
		body = strings.NewReader(b)
	}

	out, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return failOpen(err.Error()), nil
	}
	for k, v := range httpReq.GetHeaders() {
		if strings.HasPrefix(k, ":") { // pseudo-headers
			continue
		}
		out.Header.Set(k, v)
	}
	// The adapter takes the client address from x-envoy-external-address /
	// x-forwarded-for; make sure the source address is visible either way.
	if src := req.GetAttributes().GetSource().GetAddress().GetSocketAddress(); src != nil {
		if out.Header.Get("x-envoy-external-address") == "" {
			out.Header.Set("x-envoy-external-address", src.GetAddress())
		}
	}
	// Envoy already applied its size cap (with_request_body.max_request_bytes);
	// tell the adapter the length so its own gate sees it.
	if body != nil {
		out.ContentLength = int64(len(httpReq.GetRawBody()) + len(httpReq.GetBody()))
	}

	resp, err := s.client.Do(out)
	if err != nil {
		return failOpen(err.Error()), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.Header.Get("X-Jev-Verdict") == "" {
		// a 5xx is the server (or a proxy in front of it) failing, like an
		// unreachable adapter; anything else refused this request
		if resp.StatusCode >= 500 {
			return failOpen(fmt.Sprintf("adapter answered %d without X-Jev-Verdict", resp.StatusCode)), nil
		}
		return unjudgeable(fmt.Sprintf("authz answered %d", resp.StatusCode), s.unjudged), nil
	}

	// Overwrite every X-Jev-* header the adapter set and remove the ones it
	// did not, so nothing the client sent survives.
	headers := make([]*corev3.HeaderValueOption, 0, len(jevHeaders)+1)
	var remove []string
	for _, h := range jevHeaders {
		if v := resp.Header.Get(h); v != "" {
			headers = append(headers, overwrite(h, v))
		} else {
			remove = append(remove, h)
		}
	}

	if resp.StatusCode == http.StatusOK {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{Headers: headers, HeadersToRemove: remove},
			},
		}, nil
	}
	if resp.StatusCode < 400 {
		return failOpen(fmt.Sprintf("adapter answered %d", resp.StatusCode)), nil
	}

	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(resp.StatusCode)},
				Headers: clientHeaders(resp.Header),
				Body:    string(respBody),
			},
		},
	}, nil
}

// clientHeaders are the headers a block hands to the client: Envoy puts
// DeniedHttpResponse.Headers on its local reply as they are, so only
// Content-Type, X-Jev-Verdict and X-Jev-Request-Id (jev-edge's client
// contract, verdict.client_headers). X-Jev-Score, X-Jev-Reason and
// X-Jev-Source stay in jev-edge's log: on a block they would tell the
// client how far over the threshold it is, which question fired and
// whether the answer came from the cache, a score oracle to walk a prompt
// under block_threshold. (envoy-http.yaml's allowed_client_headers hands
// on Content-Type alone.)
func clientHeaders(h http.Header) []*corev3.HeaderValueOption {
	out := make([]*corev3.HeaderValueOption, 0, 3)
	for _, k := range []string{"Content-Type", "X-Jev-Verdict", "X-Jev-Request-Id"} {
		if v := h.Get(k); v != "" {
			out = append(out, overwrite(k, v))
		}
	}
	return out
}

// normalizePath returns the path nginx reads from p into $uri, the path
// jev-edge judges inline, escaped again for the authz URL; ok is false
// where nginx answers 400 instead: a path that does not start with '/', or
// a ".." that climbs above the root. nginx decodes every %XX and takes a
// decoded '/' or '.' as path syntax (%2e%2e is "..", %2F a slash; %25 is
// only a '%'), merges doubled slashes and resolves "." and "..", keeping a
// trailing slash. Forwarded as sent, "/_jev/authz" followed by such a path
// could climb out of /_jev/authz/ to the adapter's admin endpoints; this
// one has no "." or ".." segment and no empty one, so jev-edge's nginx
// decodes it once into the same $uri and has nothing left to resolve.
// p must be well formed (wellFormedPath).
func normalizePath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	dec, err := url.PathUnescape(p)
	if err != nil {
		return "", false
	}
	segs := strings.Split(dec[1:], "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "", ".":
		case "..":
			if len(out) == 0 {
				return "", false
			}
			out = out[:len(out)-1]
		default:
			out = append(out, escapeSegment(s))
		}
	}
	norm := "/" + strings.Join(out, "/")
	if last := segs[len(segs)-1]; len(out) > 0 && (last == "" || last == "." || last == "..") {
		norm += "/"
	}
	return norm, true
}

// escapeSegment escapes one decoded path segment for the authz URL: '%',
// '/', '?', '#', controls, spaces, bytes past ASCII and the other bytes
// net/url would not send as they are. The rest (letters, digits,
// "-._~!$&'()*+,;=:@[]") goes as it is, so the forwarded path is no longer
// than the client's but for bytes it sent raw that a URL cannot carry
// (net/url escaped those before too), and fits jev-edge's header buffers
// as before (README: size contract).
func escapeSegment(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("-._~!$&'()*+,;=:@[]", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// wellFormedPath reports whether p is a path nginx would take: every '%'
// starts a two-digit hex escape, none of them is %00, and there is no
// control character. nginx answers anything else with 400 before jev-edge
// runs, so the inline deployment never judges such a path, and Go cannot
// build the authz URL from an invalid escape or a control character.
// Backends may still decode it (cpp-httplib, under llama.cpp, reads %u0063
// as 'c'). An escape of a byte that is not UTF-8 (%FF, the overlong %C0%AE)
// is well formed: nginx, Envoy and HAProxy take it, and jev-edge judges the
// path as sent.
func wellFormedPath(p string) bool {
	if _, err := url.PathUnescape(p); err != nil {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return false
		}
	}
	return !strings.Contains(p, "%00")
}

// badPath denies a request whose path is not well formed with 400 (the
// status nginx gives it inline and Envoy's HTTP ext_authz hands on) and the
// default block body. The client's error, not jev-edge's: never fail-open,
// whatever -unjudged says.
func badPath(path string) *authv3.CheckResponse {
	log.Printf("jev-edge shim: refusing malformed path %.256q with 400", path)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_BadRequest},
				Headers: []*corev3.HeaderValueOption{overwrite("Content-Type", "application/json")},
				Body:    `{"error":"request rejected"}`,
			},
		},
	}
}

func overwrite(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, Value: value},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func failOpen(reason string) *authv3.CheckResponse {
	log.Printf("jev-edge shim: failing open: %s", reason)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					overwrite("X-Jev-Verdict", "error"),
					overwrite("X-Jev-Source", "shim"),
				},
				HeadersToRemove: []string{"X-Jev-Score", "X-Jev-Reason", "X-Jev-Request-Id"},
			},
		},
	}
}

// unjudgeable: the request reached the adapter's server but was never
// judged. Marked skipped like jev-edge's own "unjudgeable: ..." verdicts
// (reason URL-encoded the same way), and denied with 403 and the default
// block body when policy is "block".
func unjudgeable(reason, policy string) *authv3.CheckResponse {
	log.Printf("jev-edge shim: unjudgeable (%s): %s", policy, reason)
	headers := []*corev3.HeaderValueOption{
		overwrite("X-Jev-Verdict", "skipped"),
		overwrite("X-Jev-Score", "0.00"),
		overwrite("X-Jev-Source", "shim"),
		overwrite("X-Jev-Reason", url.QueryEscape("unjudgeable: "+reason)),
	}
	if policy == "block" {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Headers: []*corev3.HeaderValueOption{overwrite("Content-Type", "application/json")},
					Body:    `{"error":"request rejected"}`,
				},
			},
		}
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: headers, HeadersToRemove: []string{"X-Jev-Request-Id"}},
		},
	}
}

func main() {
	listen := flag.String("listen", ":9001", "gRPC listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:8080/_jev/authz", "adapter HTTP ext_authz base URL (no trailing slash)")
	timeout := flag.Duration("timeout", 1500*time.Millisecond, "HTTP timeout to the adapter (fail-open when exceeded); keep it above the adapter's L2 ceiling and below the ext_authz grpc_service timeout in envoy-grpc.yaml so the fail-open answer still reaches Envoy")
	unjudged := flag.String("unjudged", "pass", "a request the adapter's server answered without X-Jev-Verdict (refused before judging): pass, marked X-Jev-Verdict: skipped, or block with 403; keep it equal to jev-edge's policy.unjudgeable")
	flag.Parse()
	if *unjudged != "pass" && *unjudged != "block" {
		log.Fatalf("-unjudged must be pass or block, got %q", *unjudged)
	}

	s := &server{
		upstream: strings.TrimRight(*upstream, "/"),
		client: &http.Client{
			Timeout:   *timeout,
			Transport: &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second},
		},
		unjudged: *unjudged,
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, s)
	healthpb.RegisterHealthServer(g, health.NewServer())
	fmt.Printf("jev-edge grpc shim listening on %s, forwarding to %s\n", *listen, s.upstream)
	log.Fatal(g.Serve(lis))
}
