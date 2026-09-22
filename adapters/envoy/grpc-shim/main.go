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
// header is a block (PermissionDenied with that status, body and headers);
// anything else, including a 404 / 5xx from something that is not jev-edge,
// or any error talking to the adapter, fails open: OK with X-Jev-Verdict:
// error and X-Jev-Source: shim, matching the adapter's own behaviour. Every
// X-Jev-* header is overwritten on the way upstream so a forged inbound
// value never survives. Paths containing "..", "%2e" or "//" are not
// forwarded at all (they could reach the adapter's admin endpoints).
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
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if !safePath(path) {
		return failOpen("refusing path " + path), nil
	}
	url := s.upstream + path

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
		return failOpen(fmt.Sprintf("adapter answered %d without X-Jev-Verdict", resp.StatusCode)), nil
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

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		headers = append(headers, overwrite("Content-Type", ct))
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(resp.StatusCode)},
				Headers: headers,
				Body:    string(respBody),
			},
		},
	}, nil
}

// safePath rejects anything that could escape /_jev/authz/ once the adapter
// (or a proxy in between) normalises it: dot segments, encoded dots, and
// doubled slashes. The adapter's admin endpoints live next to the authz
// prefix, so these must never be forwarded.
func safePath(p string) bool {
	if p == "" {
		return true
	}
	if p[0] != '/' {
		return false
	}
	lower := strings.ToLower(p)
	return !strings.Contains(p, "..") && !strings.Contains(lower, "%2e") && !strings.Contains(p, "//")
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

func main() {
	listen := flag.String("listen", ":9001", "gRPC listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:8080/_jev/authz", "adapter HTTP ext_authz base URL (no trailing slash)")
	timeout := flag.Duration("timeout", 2*time.Second, "HTTP timeout to the adapter; must exceed the adapter's L2 ceiling")
	flag.Parse()

	s := &server{
		upstream: strings.TrimRight(*upstream, "/"),
		client: &http.Client{
			Timeout:   *timeout,
			Transport: &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second},
		},
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
