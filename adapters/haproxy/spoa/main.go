// jev-spoa: HAProxy SPOE agent that asks a running jev-edge (/_jev/authz)
// and hands the verdict back as transaction variables.
//
// HAProxy sends one message per request with method, path, client IP,
// content type and (with `option http-buffer-request`) the body. The agent
// sets txn.jev.verdict / score / source / reason / action / rid / status;
// haproxy.cfg turns action=block into a deny (status from txn.jev.status)
// and copies the rest to X-Jev-* headers.
//
// Contract: only an answer carrying X-Jev-Verdict is trusted. 200 with the
// header is a decision; any status >= 400 with the header is a block, with
// that status in txn.jev.status; anything else, and any failure to reach
// jev-edge, sets verdict=error, action=pass (fail-open). Paths containing
// "..", "%2e" or "//" are never forwarded (they could reach the adapter's
// admin endpoints next to /_jev/authz) and fail open too.
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
	"strconv"
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
	timeout  = flag.Duration("timeout", 1500*time.Millisecond, "per-check timeout (fail-open when exceeded); keep it below spoe.conf's `timeout processing` so the fail-open answer still reaches HAProxy")
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
	return map[string]string{"verdict": "error", "score": "0.00", "source": "adapter", "reason": reason, "action": "pass", "rid": "", "status": "0"}
}

// safePath rejects anything that could escape /_jev/authz/ once normalised:
// dot segments, encoded dots and doubled slashes.
func safePath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	return !strings.Contains(p, "..") && !strings.Contains(strings.ToLower(p), "%2e") && !strings.Contains(p, "//")
}

// headers HAProxy or the HTTP client own; never copied from req.hdrs
var skipHeader = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"x-forwarded-for": true, "content-type": true, "expect": true, "accept-encoding": true,
	"te": true, "upgrade": true, "keep-alive": true, "proxy-connection": true,
	// never trust a client-supplied verdict
	"x-jev-verdict": true, "x-jev-score": true, "x-jev-source": true, "x-jev-reason": true,
	"x-jev-request-id": true, "x-jev-subject": true,
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
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if method == "" {
		method = "POST"
	}
	if !safePath(path) {
		log.Printf("jev-spoa: refusing path %q, failing open", path)
		setVars(req, failOpen("bad path"))
		return
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
		if skipHeader[strings.ToLower(name)] {
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

	if res.Header.Get("X-Jev-Verdict") == "" {
		log.Printf("jev-spoa: jev-edge answered %d without X-Jev-Verdict, failing open", res.StatusCode)
		setVars(req, failOpen(fmt.Sprintf("http %d", res.StatusCode)))
		return
	}
	vars := map[string]string{
		"verdict": res.Header.Get("X-Jev-Verdict"),
		"score":   res.Header.Get("X-Jev-Score"),
		"source":  res.Header.Get("X-Jev-Source"),
		"reason":  res.Header.Get("X-Jev-Reason"),
		"rid":     res.Header.Get("X-Jev-Request-Id"),
		"action":  "pass",
		"status":  "0",
	}
	switch {
	case res.StatusCode == 200:
	case res.StatusCode >= 400:
		vars["action"] = "block"
		vars["status"] = strconv.Itoa(res.StatusCode)
	default:
		log.Printf("jev-spoa: jev-edge answered %d, failing open", res.StatusCode)
		setVars(req, failOpen(fmt.Sprintf("http %d", res.StatusCode)))
		return
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
