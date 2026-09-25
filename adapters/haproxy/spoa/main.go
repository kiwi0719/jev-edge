// jev-spoa: HAProxy SPOE agent that asks a running jev-edge (/_jev/authz)
// and hands the verdict back as transaction variables.
//
// HAProxy sends one message per request with method, path, client IP, the
// raw header block and (with `option http-buffer-request`) the body. The
// agent sets txn.jev.verdict / score / source / reason / action / rid /
// status; haproxy.cfg turns action=block into a deny (status from
// txn.jev.status) and copies the rest to X-Jev-* headers.
//
// Contract: only an answer carrying X-Jev-Verdict is trusted. 200 with the
// header is a decision; any status >= 400 with the header is a block, with
// that status in txn.jev.status. An answer without the header below 500
// (the server in front of jev-edge refused the request before it ran: 400,
// 413, 414) means nobody judged it: verdict=skipped, reason
// "unjudgeable: ...", and action pass or block (403) as -unjudged says,
// like jev-edge's policy.unjudgeable. Any other answer (a 5xx without the
// header included), and any failure to reach jev-edge, sets
// verdict=error, action=pass (fail-open). A path the agent cannot relay as
// the backend reads it (a '%' without two hex digits after it, such as the
// IIS-style %u0063 that cpp-httplib under llama.cpp decodes to 'c'; a %00;
// a control character; bytes that are not UTF-8) is blocked with 400
// (verdict=skipped, reason "invalid path"), as nginx answers it inline,
// whatever -unjudged says: it is the client's error, so it never fails
// open. Paths containing "..", "%2e" or "//" are never forwarded (they
// could reach the adapter's admin endpoints next to /_jev/authz) and fail
// open.
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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	unjudged = flag.String("unjudged", "pass", "a request jev-edge's server answered without X-Jev-Verdict (refused before judging): pass, marked verdict=skipped, or block with 403; keep it equal to jev-edge's policy.unjudgeable")
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

// partialBody reports whether HAProxy's declared body size (req.body_size)
// exceeds the bytes it passed in req.body.
func partialBody(declared string, got int) bool {
	n, err := strconv.Atoi(strings.TrimSpace(declared))
	return err == nil && n > got
}

func failOpen(reason string) map[string]string {
	return map[string]string{"verdict": "error", "score": "0.00", "source": "adapter", "reason": reason, "action": "pass", "rid": "", "status": "0"}
}

// unjudgeable: the request reached jev-edge's server but was never judged.
// Marked skipped like jev-edge's own "unjudgeable: ..." verdicts, reason
// URL-encoded the same way; blocked with 403 when policy is "block".
func unjudgeable(reason, policy string) map[string]string {
	v := map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": url.QueryEscape("unjudgeable: " + reason), "action": "pass", "rid": "", "status": "0"}
	if policy == "block" {
		v["action"], v["status"] = "block", "403"
	}
	return v
}

// safePath rejects anything that could escape /_jev/authz/ once normalised:
// dot segments, encoded dots and doubled slashes.
func safePath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	return !strings.Contains(p, "..") && !strings.Contains(strings.ToLower(p), "%2e") && !strings.Contains(p, "//")
}

// wellFormedPath reports whether p can be relayed as the backend reads it:
// every '%' starts a two-digit hex escape, no escape decodes to NUL, there
// is no control character and the decoded bytes are UTF-8 (no overlong
// forms such as %C0%AE for '.'). nginx refuses the first three with 400
// before jev-edge runs, so the inline deployment never judges such a path
// either; Go cannot even build the authz URL for most of them. Backends may
// still decode them (cpp-httplib, under llama.cpp, reads %u0063 as 'c').
func wellFormedPath(p string) bool {
	dec, err := url.PathUnescape(p)
	if err != nil {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return false
		}
	}
	return strings.IndexByte(dec, 0) < 0 && utf8.ValidString(dec)
}

// badPath blocks a request whose path is not well formed with 400, the
// status nginx gives it inline (haproxy.cfg needs its deny_status 400 line
// for that; without it the catch-all denies with 403). The client's error,
// not jev-edge's: never fail-open, whatever -unjudged says.
func badPath() map[string]string {
	return map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": url.QueryEscape("invalid path"), "action": "block", "rid": "", "status": "400"}
}

// headers HAProxy or the HTTP client own; never copied from req.hdrs.
// Content-Type is copied, every occurrence: jev-edge watches a request when
// any of its content types is watched, since the backend may read any one.
var skipHeader = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"x-forwarded-for": true, "expect": true, "accept-encoding": true,
	"te": true, "upgrade": true, "keep-alive": true, "proxy-connection": true,
	// client-IP headers jev-edge consults before X-Forwarded-For; a client
	// copy would override the source address set below
	"x-envoy-external-address": true, "x-real-ip": true,
	// never trust a client-supplied verdict
	"x-jev-verdict": true, "x-jev-score": true, "x-jev-source": true, "x-jev-reason": true,
	"x-jev-request-id": true, "x-jev-subject": true,
	// set below from HAProxy's own body size, never taken from the client
	"x-jev-body-partial": true,
}

// copyHeaders adds each "Name: value" line of a raw header block to dst,
// minus skipHeader.
func copyHeaders(dst http.Header, hdrs string) {
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
		dst.Add(name, strings.TrimSpace(line[i+1:]))
	}
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
	setVars(req, check(func(k string) string {
		v, ok := msg.KV.Get(k)
		if !ok {
			return ""
		}
		return str(v)
	}))
}

// check asks jev-edge about one SPOE message (get returns its arguments)
// and returns the txn.jev.* variables to set.
func check(get func(string) string) map[string]string {
	// An older spoe.conf may still send `ct` (req.hdr(content-type): the last
	// value only). It is ignored; Content-Type comes from hdrs.
	method, path, ip, hdrs := get("method"), get("path"), get("ip"), get("hdrs")
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
	// before safePath: a malformed path is refused even when it also has a
	// dot segment or a doubled slash
	if !wellFormedPath(path) {
		log.Printf("jev-spoa: refusing malformed path %.256q with 400", path)
		return badPath()
	}
	if !safePath(path) {
		log.Printf("jev-spoa: refusing path %q, failing open", path)
		return failOpen("bad path")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(*upstream, "/")+path, bytes.NewReader(body))
	if err != nil {
		return failOpen(err.Error())
	}
	// forward the original headers (req.hdrs is the raw header block) so
	// jev-edge sees the same request Envoy or nginx would; hop-by-hop and
	// framing headers are recomputed by the client
	copyHeaders(hreq.Header, hdrs)
	if ip != "" {
		hreq.Header.Set("X-Forwarded-For", ip)
	}
	// HAProxy hands over at most tune.bufsize of the body, and spoe.conf cuts
	// it further so the message fits one frame: when the declared size is
	// larger, jev-edge must scan what it got as the head of a larger body,
	// not parse it as a whole (truncated JSON would read as "no text").
	if partialBody(get("size"), len(body)) {
		hreq.Header.Set("X-Jev-Body-Partial", "1")
	}
	res, err := client.Do(hreq)
	if err != nil {
		log.Printf("jev-spoa: jev-edge unreachable, failing open: %v", err)
		return failOpen("unreachable")
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	if res.Header.Get("X-Jev-Verdict") == "" {
		// a 5xx is the server (or a proxy in front of it) failing, like an
		// unreachable jev-edge; anything else refused this request
		if res.StatusCode >= 500 {
			log.Printf("jev-spoa: jev-edge answered %d without X-Jev-Verdict, failing open", res.StatusCode)
			return failOpen(fmt.Sprintf("http %d", res.StatusCode))
		}
		log.Printf("jev-spoa: jev-edge answered %d without X-Jev-Verdict, unjudgeable (-unjudged=%s)", res.StatusCode, *unjudged)
		return unjudgeable(fmt.Sprintf("authz answered %d", res.StatusCode), *unjudged)
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
		return failOpen(fmt.Sprintf("http %d", res.StatusCode))
	}
	return vars
}

func main() {
	flag.Parse()
	if *unjudged != "pass" && *unjudged != "block" {
		log.Fatalf("-unjudged must be pass or block, got %q", *unjudged)
	}
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
