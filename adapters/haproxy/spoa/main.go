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
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/negasus/haproxy-spoe-go/worker"
)

var (
	listen   = flag.String("listen", "127.0.0.1:9000", "SPOE listen address; SPOP has no authentication, so keep it on loopback or a network only HAProxy reaches")
	upstream = flag.String("upstream", "http://127.0.0.1:8080/_jev/authz", "jev-edge authz URL prefix")
	timeout  = flag.Duration("timeout", 1500*time.Millisecond, "per-check timeout (fail-open when exceeded); keep it below spoe.conf's `timeout processing` so the fail-open answer still reaches HAProxy")
	message  = flag.String("message", "check-request", "SPOE message name")
	unjudged = flag.String("unjudged", "pass", "a request jev-edge's server answered without X-Jev-Verdict (refused before judging): pass, marked verdict=skipped, or block with 403; keep it equal to jev-edge's policy.unjudgeable")
	maxIdle  = flag.Int("max-idle", 64, "idle keepalive connections kept open to jev-edge; at least the checks in flight at once, or each check past it opens a new connection")
	maxConns = flag.Int("max-conns", 256, "SPOP connections served at once; one past it is closed as it is accepted")
	maxFrame = flag.Uint("max-frame-size", 131072, "largest SPOP frame taken, in bytes after the 4-byte length; at least HAProxy's tune.bufsize (131072 in the reference haproxy.cfg), or a message that fills it is refused and unjudgeable")
	frameTTL = flag.Duration("frame-timeout", 5*time.Second, "time a frame may take to arrive once its first byte has; idle time between frames has no limit")
)

var client *http.Client

// maxDrain is how much of an answer's body is read so its connection goes
// back to the pool; a longer one (jev-edge's block body is a few bytes)
// closes it instead.
const maxDrain = 64 << 10

// newClient is the client the agent asks jev-edge with: net/http's default
// transport keeps 2 idle connections per host, so with more checks than
// that in flight every answer past the second closed its connection and
// the next check opened a new one (a TCP handshake, and a TIME_WAIT socket,
// per request under load).
func newClient(timeout time.Duration, maxIdle int) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 4 * maxIdle
	tr.MaxIdleConnsPerHost = maxIdle
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Timeout: timeout, Transport: tr}
}

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
	// Envoy's cut flag, which /_jev/authz trusts as Envoy's: a client's copy
	// would mark a whole body cut, and with policy.partial = "unjudgeable"
	// turn judging off for the request
	"x-envoy-auth-partial-body": true,
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
	io.Copy(io.Discard, io.LimitReader(res.Body, maxDrain))

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

// minFrame is the shortest well-formed SPOP frame after its length: type,
// 4 bytes of flags, and a stream id and a frame id of a byte each.
// haproxy-spoe-go allocates the declared length minus one before it reads
// the frame, so a length of 0 asks it for 4 GiB, and 1 to 4 make it slice
// past the end.
const minFrame = 7

var errFrameSize = errors.New("frame length out of bounds")

// frameConn guards one SPOP connection. haproxy-spoe-go reads a frame's
// 4-byte big-endian length and allocates that many bytes without a check,
// then waits for all of them with no deadline: one connection declaring
// 4 GiB, or a thousand declaring 128 KiB and sending none of it, took the
// agent's memory. frameConn follows the frame boundaries in the bytes as
// they are read, refuses a length outside [minFrame, max] before the
// library sees it, and gives a frame `ttl` from its first byte to arrive
// whole. Between frames there is no deadline: HAProxy keeps SPOP
// connections open and idle between requests.
type frameConn struct {
	net.Conn
	max     uint32
	ttl     time.Duration
	release func()

	hdr   [4]byte
	nhdr  int       // bytes of the current length read
	left  uint32    // bytes of the current frame still to come
	start time.Time // the current frame's first byte; zero between frames
	err   error
	once  sync.Once
}

func (c *frameConn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	deadline := time.Time{}
	if !c.start.IsZero() {
		deadline = c.start.Add(c.ttl)
	}
	if err := c.Conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	now := time.Now()
	for i := 0; i < n; {
		if c.left == 0 { // in the length
			if c.nhdr == 0 {
				c.start = now
			}
			c.hdr[c.nhdr] = p[i]
			c.nhdr++
			i++
			if c.nhdr < 4 {
				continue
			}
			c.nhdr = 0
			l := binary.BigEndian.Uint32(c.hdr[:])
			if l < minFrame || l > c.max {
				c.err = fmt.Errorf("%w: %d bytes, not %d to %d (-max-frame-size)", errFrameSize, l, minFrame, c.max)
				log.Printf("jev-spoa: closing %s: %v", c.RemoteAddr(), c.err)
				c.Conn.Close()
				return 0, c.err
			}
			c.left = l
			continue
		}
		k := uint32(n - i)
		if k > c.left {
			k = c.left
		}
		c.left -= k
		i += int(k)
		if c.left == 0 {
			c.start = time.Time{}
		}
	}
	return n, err
}

func (c *frameConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// guardListener hands out at most `max` connections at once, each guarded
// by a frameConn; one past the cap is closed as it is accepted, so the
// agent's goroutines and buffers stay bounded whoever connects.
type guardListener struct {
	net.Listener
	max, active int64
	frame       uint32
	ttl         time.Duration
	refused     atomic.Int64
	lastLog     atomic.Int64
}

func (l *guardListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if atomic.AddInt64(&l.active, 1) > l.max {
			atomic.AddInt64(&l.active, -1)
			c.Close()
			n := l.refused.Add(1)
			// one line a second at most, whatever the rate
			if now := time.Now().Unix(); l.lastLog.Swap(now) != now {
				log.Printf("jev-spoa: over %d connections (-max-conns): closed %s (%d refused so far)", l.max, c.RemoteAddr(), n)
			}
			continue
		}
		return &frameConn{Conn: c, max: l.frame, ttl: l.ttl,
			release: func() { atomic.AddInt64(&l.active, -1) }}, nil
	}
}

// serve runs the SPOP worker on each connection ln hands out, as
// agent.Serve does, and survives a frame haproxy-spoe-go panics on (a
// varint or a list cut short): that connection is closed and the others
// carry on.
func serve(ln net.Listener, h func(*request.Request), lg logger.Logger) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("jev-spoa: closing %s: malformed frame: %v", c.RemoteAddr(), r)
					c.Close()
				}
			}()
			worker.Handle(c, h, lg)
		}()
	}
}

func main() {
	flag.Parse()
	if *unjudged != "pass" && *unjudged != "block" {
		log.Fatalf("-unjudged must be pass or block, got %q", *unjudged)
	}
	if *maxIdle < 1 {
		log.Fatalf("-max-idle must be at least 1, got %d", *maxIdle)
	}
	client = newClient(*timeout, *maxIdle)
	if *maxConns < 1 || *maxFrame < minFrame || *maxFrame > 1<<31 || *frameTTL <= 0 {
		log.Fatalf("-max-conns must be at least 1, -max-frame-size %d to %d, -frame-timeout above 0", minFrame, 1<<31)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("jev-spoa listening on %s, upstream %s", *listen, *upstream)
	gl := &guardListener{Listener: ln, max: int64(*maxConns), frame: uint32(*maxFrame), ttl: *frameTTL}
	if err := serve(gl, handler, logger.NewDefaultLog()); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
