package crlf

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

// Bounds for raw I/O. A hostile or broken server must never be able to keep the
// prober reading, or to make it allocate without limit.
const (
	dialTimeout      = 5 * time.Second
	ioTimeout        = 5 * time.Second
	maxHeaderBytes   = 64 << 10
	maxBodyBytes     = 4 << 10
	rawPayloadPrefix = "%0d%0a" + canaryHeader + ":%20"
)

// errHeaderSectionTooLarge aborts a response whose header section exceeds
// maxHeaderBytes. It is an error rather than a silent truncation so a parser can
// never read a body out of a half-consumed header block.
var errHeaderSectionTooLarge = errors.New("crlf: header section exceeds the size cap")

// ProbeRaw sends a hand-built HTTP/1.1 request that carries a literal
// %0d%0aX-SoliTools-Canary ... sequence in the query, then parses the reply with
// net/textproto.
//
// This exists because net/http and httpx cannot answer two questions: whether a
// proxy decodes an over-encoded query, and whether the target emits a second
// response (response splitting). The request line is legal — the newline lives
// inside the percent-encoded parameter value — so a compliant server is not
// harmed; only a server that decodes the value straight into a header will show
// the canary.
//
// client.Wait is called before any socket is opened, so a raw connection always
// pays for its slot in the shared rate limiter. The dial goes straight at the
// target, which means -proxy is not honoured here, and the TLS configuration
// never disables certificate verification: a self-signed target produces no raw
// finding.
func ProbeRaw(ctx context.Context, client *httpx.Client, targetURL, param string) (*finding.Finding, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	// A parameter name is pasted into the request line, so it must not be able
	// to alter it.
	if client == nil || param == "" || strings.ContainsAny(param, " \t\r\n&=") {
		return nil, false
	}
	target, err := url.Parse(targetURL)
	if err != nil || target.Host == "" {
		return nil, false
	}
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, false
	}

	// The limiter comes first: no socket exists before the slot is granted.
	if err := client.Wait(ctx); err != nil {
		return nil, false
	}

	token := newCanary()

	// A fragment is never sent, so dropping it keeps the reported URL honest.
	target.Fragment = ""
	target.RawFragment = ""
	reportedURL := target.String()
	injectQuery(target, param, rawPayloadPrefix+token)

	requestTarget := target.EscapedPath()
	if requestTarget == "" {
		requestTarget = "/"
	}
	if target.RawQuery != "" {
		requestTarget += "?" + target.RawQuery
	}

	conn, err := dial(ctx, scheme, target)
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	deadline := time.Now().Add(ioTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, false
	}
	// Cancellation without a deadline still has to unblock the read.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	request := methodGet + " " + requestTarget + " HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"User-Agent: " + httpx.DefaultUserAgent + "\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, false
	}

	reader := bufio.NewReaderSize(&boundedReader{r: conn, left: maxHeaderBytes}, 4096)
	text := textproto.NewReader(reader)

	statusLine, err := text.ReadLine()
	if err != nil {
		return nil, false
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.HasPrefix(statusLine, "HTTP/1.") {
		return nil, false
	}

	headers, err := text.ReadMIMEHeader()
	if err != nil {
		return nil, false
	}

	// Hard gate: the canary must be the value of the injected header after MIME
	// parsing. A token that only appears elsewhere in the headers or in the body
	// is a reflection, not an injection, and is dropped here.
	headerValue := mimeCanary(headers, token)
	if headerValue == "" {
		return nil, false
	}

	bodyReader := io.Reader(reader)
	if strings.Contains(strings.ToLower(headers.Get("Transfer-Encoding")), "chunked") {
		bodyReader = httputil.NewChunkedReader(reader)
	}
	// The body is bounded and only used for the splitting check; it can never
	// create a finding on its own.
	body, _ := io.ReadAll(io.LimitReader(bodyReader, maxBodyBytes))

	builder := confidence.New(baseConfidence)
	builder.Add(signalHeaderParsed, 30, fmt.Sprintf("%s was parsed as a response header with value %q", canaryHeader, snippet(headerValue)))

	split := hasSecondStatusLine(body)
	if split {
		builder.Add(signalSplitting, 25, "a second HTTP status line starts a line inside the bounded body")
	}
	score := builder.Build()

	title := fmt.Sprintf("HTTP Header Injection / CRLF (%s)", score.Band)
	if split {
		title = fmt.Sprintf("HTTP Response Splitting / CRLF Injection (%s)", score.Band)
	}

	candidate := finding.Finding{
		Kind:       kindCRLF,
		Category:   categoryCRLF,
		RuleID:     ruleIDCRLF,
		Title:      title,
		URL:        reportedURL,
		Value:      token,
		Context:    fmt.Sprintf("%s: %s | %s", canaryHeader, snippet(headerValue), singleLine(statusLine)),
		Confidence: score,
	}
	candidate.WithField("Parameter", param)
	candidate.WithField("Method", methodGet)
	candidate.WithField("Injected Header", canaryHeader)
	candidate.WithField("Value", token)
	candidate.WithField("Status Line", singleLine(statusLine))
	if split {
		candidate.WithField("Response Splitting", "second status line observed in the body stream")
	}
	return &candidate, true
}

// dial opens the TCP or TLS connection the probe needs.
func dial(ctx context.Context, scheme string, target *url.URL) (net.Conn, error) {
	port := target.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(target.Hostname(), port)
	dialer := &net.Dialer{Timeout: dialTimeout}

	if scheme != "https" {
		return dialer.DialContext(ctx, "tcp", address)
	}

	// InsecureSkipVerify is deliberately absent: the raw path must not be the
	// soft spot that silently accepts a forged certificate. NextProtos pins the
	// handshake to HTTP/1.1, because a raw request cannot produce HTTP/2 frames.
	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName: target.Hostname(),
			NextProtos: []string{"http/1.1"},
		},
	}
	return tlsDialer.DialContext(ctx, "tcp", address)
}

// injectQuery replaces the value of param in target's raw query with payload,
// leaving every other pair byte-for-byte intact.
//
// The payload is written literally, without re-encoding: that is the whole point
// of the raw probe. Keys are compared after decoding so an escaped parameter name
// still matches, and a missing parameter is appended rather than duplicated.
func injectQuery(target *url.URL, param, payload string) {
	parts := make([]string, 0, 4)
	if target.RawQuery != "" {
		parts = strings.Split(target.RawQuery, "&")
	}

	replaced := false
	for i, part := range parts {
		key := part
		if j := strings.IndexByte(part, '='); j >= 0 {
			key = part[:j]
		}
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = key
		}
		if decoded == param {
			parts[i] = url.QueryEscape(param) + "=" + payload
			replaced = true
		}
	}
	if !replaced {
		parts = append(parts, url.QueryEscape(param)+"="+payload)
	}
	target.RawQuery = strings.Join(parts, "&")
}

// mimeCanary returns the value of the injected header when it carries the token.
func mimeCanary(headers textproto.MIMEHeader, token string) string {
	if token == "" {
		return ""
	}
	for _, value := range headers[textproto.CanonicalMIMEHeaderKey(canaryHeader)] {
		if strings.Contains(value, token) {
			return value
		}
	}
	return ""
}

// hasSecondStatusLine reports whether any line of the body is an HTTP/1.x status
// line.
//
// Scanning line by line is the point: a status line inside a paragraph, a JSON
// string or an HTML attribute is body content, not a response boundary, and must
// not be mistaken for splitting. bufio.ScanLines already drops a trailing CR, so
// each token is exactly what a parser would see between line breaks.
func hasSecondStatusLine(body []byte) bool {
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		if isStatusLine(scanner.Text()) {
			return true
		}
	}
	return false
}

// isStatusLine reports whether line is exactly "HTTP/1.x NNN ...".
func isStatusLine(line string) bool {
	if !strings.HasPrefix(line, "HTTP/1.") {
		return false
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 || len(fields[1]) != 3 {
		return false
	}
	for _, digit := range fields[1] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return fields[1][0] >= '1' && fields[1][0] <= '5'
}

// boundedReader hard-stops reads at a fixed byte count. Without it a server
// could stream headers forever and drive the prober's memory use.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errHeaderSectionTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}
