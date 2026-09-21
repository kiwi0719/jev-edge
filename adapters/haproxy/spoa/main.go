// jev-spoa: HAProxy SPOE agent that asks a running jev-edge (/_jev/authz)
// and hands the verdict back as transaction variables.
//
// HAProxy sends one message per request with method, path, client IP,
// content type and (with `option http-buffer-request`) the body. The agent
// sets txn.jev.verdict / score / source / reason / action / rid; haproxy.cfg
// turns action=block into a 403 and copies the rest to X-Jev-* headers.
// Any failure to reach jev-edge sets verdict=error, action=pass (fail-open).
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

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
)

var (
	listen   = flag.String("listen", ":9000", "SPOE listen address")
	upstream = flag.String("upstream", "http://127.0.0.1:8080/_jev/authz", "jev-edge authz URL prefix")
	timeout  = flag.Duration("timeout", 2*time.Second, "per-check timeout (fail-open when exceeded)")
	message  = flag.String("message", "check-request", "SPOE message name")
)

var client *http.Client

func str(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case net.IP:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func failOpen(reason string) map[string]string {
	return map[string]string{"verdict": "error", "score": "0.00", "source": "adapter", "reason": reason, "action": "pass"}
}

func setVars(req *request.Request, vars map[string]string) {
	for k, v := range vars {
		req.Actions.SetVar(action.ScopeTransaction, k, v)
	}
}

func handler(req *request.Request) {
	msg, err := req.Messages.GetByName(*message)
	if err != nil {
		return
	}
	get := func(k string) string {
		v, ok := msg.KV.Get(k)
		if !ok {
			return ""
		}
		return str(v)
	}
	method, path, ip, ct, hdrs := get("method"), get("path"), get("ip"), get("ct"), get("hdrs")
	body := []byte(get("body"))
	if path == "" {
		path = "/"
	}
	if method == "" {
		method = "POST"
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(*upstream, "/")+path, bytes.NewReader(body))
	if err != nil {
		setVars(req, failOpen(err.Error()))
		return
	}
	// forward the original headers (req.hdrs is the raw header block) so
	// jev-edge sees the same request Envoy or nginx would; hop-by-hop and
	// framing headers are recomputed by the client
	for _, line := range strings.Split(hdrs, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding", "connection", "x-forwarded-for", "content-type":
			continue
		}
		hreq.Header.Add(name, strings.TrimSpace(line[i+1:]))
	}
	if ct != "" {
		hreq.Header.Set("Content-Type", ct)
	}
	if ip != "" {
		hreq.Header.Set("X-Forwarded-For", ip)
	}
	res, err := client.Do(hreq)
	if err != nil {
		log.Printf("jev-spoa: jev-edge unreachable, failing open: %v", err)
		setVars(req, failOpen("unreachable"))
		return
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	vars := map[string]string{
		"verdict": res.Header.Get("X-Jev-Verdict"),
		"score":   res.Header.Get("X-Jev-Score"),
		"source":  res.Header.Get("X-Jev-Source"),
		"reason":  res.Header.Get("X-Jev-Reason"),
		"rid":     res.Header.Get("X-Jev-Request-Id"),
		"action":  "pass",
	}
	switch {
	case res.StatusCode == 403:
		vars["action"] = "block"
	case res.StatusCode != 200:
		log.Printf("jev-spoa: jev-edge answered %d, failing open", res.StatusCode)
		vars["verdict"], vars["source"], vars["reason"] = "error", "adapter", fmt.Sprintf("http %d", res.StatusCode)
	}
	if vars["verdict"] == "" {
		vars["verdict"] = "error"
	}
	setVars(req, vars)
}

func main() {
	flag.Parse()
	client = &http.Client{Timeout: *timeout}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("jev-spoa listening on %s, upstream %s", *listen, *upstream)
	a := agent.New(handler, logger.NewDefaultLog())
	if err := a.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
