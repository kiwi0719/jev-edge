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
// verdict=error, action=pass (fail-open). The path jev-edge judges is the
// one nginx reads inline: escapes decoded, "." and ".." segments (%2e%2e
// too) resolved and doubled slashes merged, then escaped again, so it
// cannot climb out of /_jev/authz/ to the adapter's admin endpoints. A path
// nginx refuses with 400 before jev-edge runs (a '%' without two hex digits
// after it, such as the IIS-style %u0063 that cpp-httplib under llama.cpp
// decodes to 'c', a %00, a ".." above the root) or that Go cannot put in a
// URL (a control character) is blocked with 400 (verdict=skipped, reason
// "invalid path"), as nginx answers it inline, whatever -unjudged says: it
// is the client's error, so it never fails open. So is a header value or a
// method net/http cannot send (a control character in the value; a method
// that is not a token), blocked with 400 and reason "invalid header" /
// "invalid method"; a header name that is not a token is left out, as
// nginx leaves it out, and the request is judged.
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

// refuse blocks with 400 a request the agent cannot relay because of what
// the client sent (a malformed path, a header value or a method Go cannot
// send), the status nginx gives a malformed path inline (haproxy.cfg needs
// its deny_status 400 line for that; without it the catch-all denies with
// 403). The client's error, not jev-edge's: never fail-open, whatever
// -unjudged says.
func refuse(reason string) map[string]string {
	return map[string]string{"verdict": "skipped", "score": "0.00", "source": "adapter",
		"reason": url.QueryEscape(reason), "action": "block", "rid": "", "status": "400"}
}

// validToken reports whether s is an RFC 9110 token, what net/http takes as
// a method or a header name (httpguts.ValidHeaderFieldName).
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether net/http sends v as a header value
// (httpguts.ValidHeaderFieldValue): no control character but a tab.
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
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
// minus skipHeader. net/http refuses to send a header whose name is not a
// token or whose value has a control character in it, and that error used
// to fail the agent open: a client could turn judging off with one such
// header. A name that is not a token is left out, as nginx leaves out a
// header name it does not take (ignore_invalid_headers), so jev-edge
// inline never reads it either. A value with a control character is one
// nginx takes and jev-edge reads inline; leaving it out could hide the
// Content-Type or the subject header jev-edge judges by, so copyHeaders
// stops and returns that header's name for check to refuse the request.
// It returns "" when every header was copied or left out.
func copyHeaders(dst http.Header, hdrs string) (badValue string) {
	for _, line := range strings.Split(hdrs, "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if skipHeader[strings.ToLower(name)] || !validToken(name) {
			continue
		}
		value := strings.TrimSpace(line[i+1:])
		if !validHeaderValue(value) {
			return name
		}
		dst.Add(name, value)
	}
	return ""
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
	// the query, and a fragment: nginx ends $uri at a '#' (net/url would
	// have taken the rest for the URL's fragment and not sent it)
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if method == "" {
		method = "POST"
	}
	// net/http cannot send a method that is not a token (nginx refuses it
	// inline with 400 too)
	if !validToken(method) {
		log.Printf("jev-spoa: refusing method %.64q with 400", method)
		return refuse("invalid method")
	}
	// a dot segment, an encoded dot or a doubled slash is judged the way
	// nginx reads it inline, never failed open: forwarded as sent, it could
	// reach the adapter's admin endpoints next to /_jev/authz
	norm, ok := "", wellFormedPath(path)
	if ok {
		norm, ok = normalizePath(path)
	}
	if !ok {
		log.Printf("jev-spoa: refusing malformed path %.256q with 400", path)
		return refuse("invalid path")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(*upstream, "/")+norm, bytes.NewReader(body))
	if err != nil {
		return failOpen(err.Error())
	}
	// forward the original headers (req.hdrs is the raw header block) so
	// jev-edge sees the same request Envoy or nginx would; hop-by-hop and
	// framing headers are recomputed by the client
	if name := copyHeaders(hreq.Header, hdrs); name != "" {
		log.Printf("jev-spoa: refusing header %.64q with a control character in its value with 400", name)
		return refuse("invalid header")
	}
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
