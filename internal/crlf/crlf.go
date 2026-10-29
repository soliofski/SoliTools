// Package crlf detects CRLF injection and HTTP response header injection.
//
// The false positive that ruins this class of detection is a body reflection: a
// server that echoes "...%0d%0aX-SoliTools-Canary: soli_1" inside an HTML error
// page looks identical to a real injection to any scanner that greps the
// response text. This package therefore never takes the body as evidence. A
// finding is raised only when the canary was parsed as a key-value pair in the
// response header section — http.Header for the encoded probes, net/textproto
// for the raw one. A body that contains the canary is explicitly not a finding,
// no matter how often or how plainly it appears.
//
// Two probes share one canary:
//
//   - Analyzer.Probe sends four URL-encoded variants through httpx: CRLF, lone
//     LF, lone CR, and a double-encoded payload that survives one extra decode
//     pass in an upstream proxy. It can only see what net/http parses, which by
//     construction cannot include a second response on the wire.
//   - ProbeRaw writes a hand-built HTTP/1.1 request over net.Dialer or
//     tls.Dialer and parses the reply with net/textproto. That is the only way
//     to observe a second status line, i.e. full response splitting.
//
// Both probes inject one inert header, X-SoliTools-Canary, whose value is a
// random "soli_<hex>" token. The token overwrites nothing: it is not a session
// cookie, it does not redirect, and it carries no executable syntax, so a probe
// cannot poison a cache or a real user's state.
//
// Every raw connection consumes the shared httpx rate limiter before dialing, so
// the raw path stays inside the same budget as every other request. Raw probing
// dials the target directly and therefore ignores -proxy; TLS certificates are
// always verified, so a target with a self-signed certificate yields no raw
// finding even though the encoded probes may still reach it.
package crlf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

const (
	// canaryHeader is the inert header injected by every payload. Its value is
	// the only thing that proves a response header was synthesised.
	canaryHeader = "X-SoliTools-Canary"
	methodGet    = "GET"

	// baseConfidence is the score of a candidate that reached the hard gate.
	// The gate itself adds nothing: only parsed evidence earns points.
	baseConfidence = 50.0
)

// Finding metadata. The Kind value lives here rather than in the shared finding
// package: the model package must not grow a case for every detector.
const (
	kindCRLF     finding.Kind = "CRLF"
	categoryCRLF              = "HTTP Header Injection"
	ruleIDCRLF                = "crlf.header.injection"
)

// Signal names, matching the derivation table in Instruction/ROADMAP.md §5.4.4.
const (
	signalHeaderParsed   = "signal.header-parsed-valid"
	signalSetCookie      = "signal.set-cookie-injected"
	signalSplitting      = "signal.response-splitting-confirmed"
	signalDoubleEncoding = "signal.double-encoding-bypass"
	signalSyntaxError    = "signal.status-400-syntax-error"
	signalSanitized      = "signal.sanitized-replacement"
)

// Target is one parameter to test.
type Target struct {
	// URL is the page that consumes the parameter.
	URL string
	// Param is the query parameter whose value is replaced by each payload.
	Param string
}

// Analyzer probes query parameters through a shared client.
type Analyzer struct {
	client *httpx.Client
}

// New builds an Analyzer. A nil client makes Probe a no-op.
func New(client *httpx.Client) *Analyzer { return &Analyzer{client: client} }

// Probe reports header injection when one of the encoded payloads is parsed
// back as a response header.
//
// All four encodings are attempted and the best-scoring evidence wins, because a
// proxy may reject one encoding while decoding another; stopping at the first
// response would hide the double-encoding signal. A response whose canary only
// appears in the body fails the hard gate and contributes nothing.
//
// Probe costs up to four requests per parameter. A candidate that clears the hard
// gate is returned even when its score lands in the medium band (a sanitised echo
// scores 55): the gate is the only place a result is suppressed, and the display
// threshold belongs to internal/report so the same evidence stays visible under
// --all.
func (a *Analyzer) Probe(ctx context.Context, target Target) (*finding.Finding, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.client == nil || target.URL == "" || target.Param == "" {
		return nil, false
	}

	token := newCanary()
	var best finding.Finding
	found := false
	for _, v := range variants(token) {
		if ctx.Err() != nil {
			break
		}
		probeURL, err := withParam(target.URL, target.Param, v.value)
		if err != nil {
			continue
		}
		response, err := a.client.Get(ctx, probeURL)
		if err != nil {
			continue
		}
		candidate, ok := evaluate(response, target.URL, probeURL, target.Param, v, token)
		if !ok {
			continue
		}
		if !found || candidate.Confidence.Value > best.Confidence.Value {
			best = candidate
			found = true
		}
		if best.Confidence.Value >= confidence.MaxScore {
			break
		}
	}
	if !found {
		return nil, false
	}
	return &best, true
}

// evaluate applies the hard gate and the score derivation to one response.
func evaluate(response *httpx.Response, targetURL, probeURL, param string, v variant, token string) (finding.Finding, bool) {
	if response == nil {
		return finding.Finding{}, false
	}

	// Hard gate: the canary must have been parsed as a header. The body is not
	// consulted here, so an echoed error page cannot produce a finding.
	headerValue := response.Header.Get(canaryHeader)
	headerParsed := token != "" && strings.Contains(headerValue, token)
	cookieValue := canaryCookie(response.Header, token)
	if !headerParsed && cookieValue == "" {
		return finding.Finding{}, false
	}

	builder := confidence.New(baseConfidence)
	if headerParsed {
		builder.Add(signalHeaderParsed, 30, fmt.Sprintf("%s was parsed as a response header with value %q", canaryHeader, snippet(headerValue)))
	}
	if cookieValue != "" {
		builder.Add(signalSetCookie, 25, fmt.Sprintf("the canary was parsed as a Set-Cookie value: %q", snippet(cookieValue)))
	}
	if v.double {
		builder.Add(signalDoubleEncoding, 15, "the double-encoded payload (%250d%250a) reached the header after a second decode")
	}
	if response.Status == http.StatusBadRequest || response.Status == http.StatusRequestHeaderFieldsTooLarge {
		builder.Add(signalSyntaxError, -20, fmt.Sprintf("the target rejected the request with %d", response.Status))
	}
	if sanitized := sanitizedEcho(response.Header, token); sanitized != "" {
		builder.Add(signalSanitized, -25, fmt.Sprintf("a second copy of the payload was neutralised inside %s", sanitized))
	}
	score := builder.Build()

	detail := fmt.Sprintf("%s: %s (status %d)", canaryHeader, snippet(headerValue), response.Status)
	if !headerParsed {
		detail = fmt.Sprintf("Set-Cookie: %s (status %d)", snippet(cookieValue), response.Status)
	}

	candidate := finding.Finding{
		Kind:       kindCRLF,
		Category:   categoryCRLF,
		RuleID:     ruleIDCRLF,
		Title:      fmt.Sprintf("HTTP Header Injection / CRLF (%s)", score.Band),
		URL:        targetURL,
		Value:      token,
		Context:    detail,
		Confidence: score,
	}
	candidate.WithField("Parameter", param)
	candidate.WithField("Method", methodGet)
	candidate.WithField("Injected Header", canaryHeader)
	candidate.WithField("Value", token)
	candidate.WithField("Status", strconv.Itoa(response.Status))
	if !headerParsed {
		candidate.WithField("Evidence", "Set-Cookie value carried the canary")
	}
	candidate.WithField("Encoding", v.name)
	candidate.WithField("Request URL", probeURL)
	return candidate, true
}

// variant is one encoding of the injection payload.
type variant struct {
	// name labels the encoding in the finding's audit trail.
	name string
	// value is the literal parameter value; httpx encodes it, so the request
	// itself never contains a stray newline in the request line.
	value string
	// double marks the payload that only lands after a second URL decode.
	double bool
}

// variants returns the encoding matrix: CRLF, lone LF, lone CR, and the
// double-encoded form.
//
// The lone encodings are not decoration. A parser that splits on LF alone, or a
// legacy one that splits on CR alone, turns each of them into a header line while
// rejecting the full CRLF pair.
func variants(token string) []variant {
	header := canaryHeader + ": " + token
	return []variant{
		{name: "crlf", value: "\r\n" + header},
		{name: "lf", value: "\n" + header},
		{name: "cr", value: "\r" + header},
		{name: "double-encoded", value: "%0d%0a" + header, double: true},
	}
}

// withParam returns rawURL with name set to value, encoded so the outgoing
// request stays a legal HTTP request line.
func withParam(rawURL, name, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("crlf: want an absolute http(s) URL, got %q", rawURL)
	}
	query := parsed.Query()
	query.Set(name, value)
	parsed.RawQuery = query.Encode()
	// A fragment is never sent, so dropping it keeps the reported URL honest.
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

// canaryCookie reports whether a Set-Cookie value is exactly the canary, and
// returns that cookie header.
//
// The check is deliberately stricter than "contains the token". A server that
// echoes the whole encoded payload into a cookie produces a value like
// "theme= X-SoliTools-Canary: soli_1", which contains the token without any
// injection having happened. Only a cookie whose value is the bare token proves
// that a header line was synthesised, so a reflected payload cannot pass the
// gate this way.
func canaryCookie(header http.Header, token string) string {
	if token == "" {
		return ""
	}
	for _, cookie := range header.Values("Set-Cookie") {
		for _, part := range strings.Split(cookie, ";") {
			name, value, ok := strings.Cut(part, "=")
			if !ok || strings.TrimSpace(name) == "" {
				continue
			}
			if strings.TrimSpace(value) == token {
				return cookie
			}
		}
	}
	return ""
}

// sanitizedEcho returns the name of a response header that carries a mangled
// copy of the payload, or "" when there is none.
//
// "Mangled" means the injected colon was replaced by a space or an underscore,
// or the whole line was flattened into a value with the colon intact. All three
// shapes mean a sanitiser rewrote the newline, so a finding that also carries a
// cleanly parsed canary deserves less trust: the two copies disagree about
// whether the target is vulnerable. The penalty therefore demotes a partially
// sanitised result into the medium band, where only --all shows it.
func sanitizedEcho(header http.Header, token string) string {
	if token == "" {
		return ""
	}
	markers := []string{
		strings.ToLower(canaryHeader + ": " + token),
		strings.ToLower(canaryHeader + " " + token),
		strings.ToLower(canaryHeader + "_" + token),
	}

	matches := make([]string, 0, 2)
	for name, values := range header {
		if strings.EqualFold(name, canaryHeader) {
			continue
		}
		for _, value := range values {
			lower := strings.ToLower(value)
			for _, marker := range markers {
				if strings.Contains(lower, marker) {
					matches = append(matches, name)
					break
				}
			}
		}
	}
	if len(matches) == 0 {
		return ""
	}
	// Map iteration is randomised; sorting keeps the reported reason stable for
	// identical evidence.
	sort.Strings(matches)
	return matches[0]
}

// maxSnippet bounds how much of a server-controlled value reaches the report.
const maxSnippet = 200

// singleLine collapses a header value to one printable line for the audit trail.
func singleLine(text string) string { return strings.Join(strings.Fields(text), " ") }

// snippet is singleLine with a hard length cap and a rune-safe cut, so a hostile
// header value can neither bloat a report nor leave invalid UTF-8 that would
// break JSON output.
func snippet(text string) string {
	line := singleLine(text)
	if len(line) <= maxSnippet {
		return line
	}
	cut := maxSnippet
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "..."
}

// newCanary returns a fresh inert token. The value is random rather than
// time-derived so two probes in the same nanosecond, or two workers in the same
// scan, can never share a token and mask each other's evidence.
func newCanary() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return "soli_" + hex.EncodeToString(buf[:])
	}
	return "soli_" + strconv.FormatInt(time.Now().UnixNano(), 16)
}
