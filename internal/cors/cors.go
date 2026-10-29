// Package cors detects CORS misconfigurations.
//
// The question this module answers is not "does the response carry CORS
// headers" but "does it accept an origin the site cannot have meant to trust".
// A literal "*" is not rated: browsers refuse it for credentialed requests, and
// for anonymous ones it grants nothing the public web did not already have. A
// hard-coded allowlist entry for some other site is not rated either, because
// the attacker's origin was refused.
//
// Each probe therefore sends a canary Origin that no deployment can have
// legitimately allowlisted — an RFC 2606 ".invalid" name, the RFC 6454 "null"
// literal, and two shapes that only a naive suffix or subdomain comparison
// would accept — and a finding exists only when that exact string comes back in
// Access-Control-Allow-Origin. The matrix is bounded at four requests and is
// deliberately non-fatal: one variant being refused, or answered without a CORS
// header, is ordinary evidence and never stops the remaining variants.
//
// Scores are returned as measured, including medium ones. The module applies
// hard gates only — exchanges that cannot be exploited at all — and leaves the
// display threshold to the report, so a 25.0 stays visible with -all instead of
// disappearing silently inside the detector.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

// Probe kinds, also reported as the ProbeType field.
const (
	probeArbitrary = "arbitrary"
	probeNull      = "null"
	probeSuffix    = "suffix"
	probeSubdomain = "subdomain"
)

// Base scores from the derivation table. Access-Control-Allow-Credentials alone
// picks between them: without it the browser's fetch is anonymous, so a
// reflected origin cannot read session-scoped data.
const (
	baseUncredentialed = 25.0
	baseCredentialed   = 65.0
)

// kindCORS is the report kind for this module. It is declared here because the
// shared finding package has no CORS constant yet, and this module must not
// edit shared packages.
const kindCORS finding.Kind = "CORS"

// Target is one endpoint to evaluate.
type Target struct {
	// URL is the absolute endpoint to probe. It is requested with a GET and is
	// never modified: each probe only adds an Origin header.
	URL string
	// IsAPI marks a JSON/API endpoint. It is carried for reporting only; the
	// response body decides whether anything sensitive is exposed, so a
	// mislabelled target cannot inflate a score.
	IsAPI bool
	// HasAuth records that the scan is authenticated against this target, so a
	// cross-origin read would return session-scoped data.
	HasAuth bool
}

// Analyzer probes CORS policy through a shared client.
type Analyzer struct {
	client *httpx.Client
}

// New builds an Analyzer. A nil client makes Probe a no-op.
func New(client *httpx.Client) *Analyzer { return &Analyzer{client: client} }

// Probe reports whether target accepts a canary origin, and how badly.
//
// It issues at most four GET requests, one per Origin value, and keeps the
// best-scoring accepted variant. A variant that fails at the transport level,
// that answers without Access-Control-Allow-Origin, or that is turned away for
// a structural reason is skipped rather than ending the probe: the cheapest
// real-world misconfigurations — null, suffix and subdomain trust — are exactly
// the ones a single arbitrary-origin request misses.
func (a *Analyzer) Probe(ctx context.Context, target Target) (*finding.Finding, bool) {
	if a == nil || a.client == nil {
		return nil, false
	}
	parsed, err := url.Parse(strings.TrimSpace(target.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, false
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, false
	}

	staticAsset := isStaticAsset(parsed.Path)
	var best *finding.Finding
	for _, candidate := range probesFor(host) {
		if ctx.Err() != nil {
			break
		}
		response, err := a.send(ctx, target.URL, candidate.origin)
		if err != nil {
			// A variant that could not be sent is evidence neither way.
			continue
		}
		scored, ok := evaluate(observation{
			kind:     candidate.kind,
			origin:   candidate.origin,
			response: response,
		}, target, staticAsset)
		if !ok {
			continue
		}
		if best == nil || scored.Confidence.Value > best.Confidence.Value {
			best = &scored
		}
	}
	return best, best != nil
}

// send issues one GET with an Origin header through the shared client, so the
// global rate limiter, timeout and body cap all apply. Redirects are not
// followed: a 3xx says nothing about the policy that governs a real response.
func (a *Analyzer) send(ctx context.Context, targetURL, origin string) (*httpx.Response, error) {
	header := make(http.Header, 1)
	header.Set("Origin", origin)
	return a.client.Do(ctx, httpx.Request{URL: targetURL, Method: http.MethodGet, Headers: header})
}

// probe is one Origin value to send.
type probe struct {
	kind   string
	origin string
}

// probesFor returns the canary origin matrix for host.
//
// Four requests are the whole budget: one arbitrary RFC 2606 name that proves
// verbatim reflection, the RFC 6454 "null" literal, one name that only a suffix
// comparison would accept, and one subdomain that only a wildcard comparison
// would accept. The order is by strength of expected evidence, so the first
// candidate wins a tie.
func probesFor(host string) []probe {
	probes := []probe{
		{kind: probeArbitrary, origin: "https://soli-" + canaryID() + ".invalid"},
		{kind: probeNull, origin: "null"},
	}
	// An IPv6 literal cannot be turned into a hostname-shaped canary without
	// inventing a syntax the target never sees, so it gets the two
	// origin-agnostic probes only.
	if strings.Contains(host, ":") {
		return probes
	}
	return append(probes,
		probe{kind: probeSuffix, origin: "https://" + host + ".soli-canary.invalid"},
		probe{kind: probeSubdomain, origin: "https://soli-check." + host},
	)
}

// canaryID returns the eight-hex-digit suffix of the arbitrary canary. The
// value changes on every call, so a cached Access-Control-Allow-Origin from an
// earlier run cannot be mistaken for a live reflection.
func canaryID() string {
	return fmt.Sprintf("%08x", uint32(time.Now().UnixNano()))
}

// isStaticAsset reports whether p addresses an asset whose bytes cannot carry
// session-scoped data. The list mirrors the gates in the module design.
func isStaticAsset(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico":
		return true
	}
	return false
}

// observation is one probe exchange: the origin that was sent and what came
// back.
type observation struct {
	kind     string
	origin   string
	response *httpx.Response
}

// evaluate scores one probe exchange, or drops it.
//
// Everything dropped here is dropped for a structural reason: no policy, an
// origin that was not accepted, a pair the browser refuses, or a response that
// cannot carry data. Everything that merely lowers confidence is recorded as a
// signal, so the finding still reaches the report — and -all — with its
// reasoning intact.
func evaluate(o observation, target Target, staticAsset bool) (finding.Finding, bool) {
	if o.response == nil {
		return finding.Finding{}, false
	}
	header := o.response.Header
	acao := strings.TrimSpace(header.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return finding.Finding{}, false
	}
	acac := strings.EqualFold(strings.TrimSpace(header.Get("Access-Control-Allow-Credentials")), "true")
	status := o.response.Status
	body := o.response.BodyString()

	// Gate: browsers reject "*" together with credentials, so the pair grants
	// no cross-origin read no matter what the server intended.
	if acao == "*" && acac {
		return finding.Finding{}, false
	}
	// Gate: only an accepted canary origin is a misconfiguration. A fixed
	// allowlist entry for another site, or a bare "*", hands an attacker
	// nothing it did not already have.
	if !originAccepted(o.kind, o.origin, acao) {
		return finding.Finding{}, false
	}
	// Gate: asset bytes carry no session-scoped data, so an uncredentialed
	// reflection on one is noise.
	if staticAsset && !acac {
		return finding.Finding{}, false
	}
	// Gate: an error page is not a data source.
	if status >= 400 && !acac {
		return finding.Finding{}, false
	}

	base := baseUncredentialed
	if acac {
		base = baseCredentialed
	}
	builder := confidence.New(base)

	switch o.kind {
	case probeArbitrary:
		// The canary is a name no deployment can allowlist by accident, so a
		// verbatim echo means the policy reflects whatever it is given.
		delta, reason := 15.0, "Arbitrary canary origin echoed in Access-Control-Allow-Origin"
		if acac {
			delta = 20.0
			reason = "Arbitrary canary origin echoed alongside Access-Control-Allow-Credentials: true"
		}
		builder.Add("arbitrary-origin-reflected", delta, reason)
	case probeNull:
		// "null" only buys an attacker something when credentials ride along:
		// the sandboxed document that produces it is otherwise anonymous.
		if acac {
			builder.Add("null-origin-trusted", 10, "Origin: null accepted alongside Access-Control-Allow-Credentials: true")
		}
	case probeSuffix:
		builder.Add("regex-suffix-bypass", 15, "Origin <host>.soli-canary.invalid accepted, so the origin check is a suffix match")
	case probeSubdomain:
		builder.Add("subdomain-wildcard-trust", 10, "Origin soli-check.<host> accepted, so any subdomain is trusted")
	}

	if key, ok := sensitiveJSONKey(body); ok {
		builder.Add("sensitive-api-data", 15, fmt.Sprintf("JSON response exposes the %q field", key))
	}
	if reason, ok := authEvidence(target.HasAuth, header); ok {
		builder.Add("auth-cookies-present", 10, reason)
	}
	if name := sensitiveExposedHeader(header); name != "" {
		builder.Add("exposed-sensitive-headers", 10, fmt.Sprintf("Access-Control-Expose-Headers exposes %s", name))
	}

	if status >= 400 {
		builder.Add("error-status", -30, fmt.Sprintf("Response status %d: an error page is not a data source", status))
	}
	cacheControl := strings.ToLower(header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "public") && strings.Contains(cacheControl, "max-age") {
		builder.Add("public-cacheable", -15, "Cache-Control marks the response public and cacheable")
	}
	if len(body) == 0 {
		builder.Add("empty-body", -15, "Response body is empty, so no data can leak")
	}
	if looksLikeLoginPage(body) {
		builder.Add("unauthenticated-login-page", -20, "Body is an unauthenticated login form")
	}

	score := builder.Build()
	f := finding.Finding{
		Kind:       kindCORS,
		Category:   "CORS Misconfiguration",
		RuleID:     "cors.misconfiguration",
		Title:      fmt.Sprintf("Insecure CORS Policy (%s)", score.Band),
		URL:        target.URL,
		Value:      acao,
		Context:    fmt.Sprintf("ACAO: %s | ACAC: %t | Probe: %s", acao, acac, o.kind),
		Confidence: score,
	}
	f.WithField("ACAO", acao)
	f.WithField("ACAC", fmt.Sprintf("%t", acac))
	f.WithField("Status", fmt.Sprintf("%d", status))
	f.WithField("ProbeType", o.kind)
	return f, true
}

// originAccepted reports whether the server returned exactly the canary origin
// it was sent.
//
// Browsers compare Access-Control-Allow-Origin byte for byte against the
// requesting origin (ASCII case-insensitive), so a near miss such as a trailing
// slash is a refusal, not an acceptance, and must not be scored as one.
func originAccepted(kind, origin, acao string) bool {
	if kind == probeNull {
		return strings.EqualFold(strings.TrimSpace(acao), "null")
	}
	return strings.EqualFold(acao, origin)
}

// authHints are the cookie-name fragments that mark a response as
// session-bearing.
var authHints = []string{"session", "jwt", "token", "auth"}

// authEvidence reports whether the exchange is authenticated: either the scan
// sent credentials, or the response sets a cookie whose name carries one of the
// usual session markers.
func authEvidence(hasAuth bool, header http.Header) (string, bool) {
	for _, raw := range header.Values("Set-Cookie") {
		name := raw
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		for _, hint := range authHints {
			if strings.Contains(name, hint) {
				return fmt.Sprintf("Response sets the authentication cookie %q", name), true
			}
		}
	}
	if hasAuth {
		return "Target is scanned with credentials, so a cross-origin read returns session-scoped data", true
	}
	return "", false
}

// sensitiveExposedHeader returns the first sensitive header named by
// Access-Control-Expose-Headers, which is what makes a response readable to
// cross-origin script beyond the safelisted headers.
func sensitiveExposedHeader(header http.Header) string {
	for _, raw := range header.Values("Access-Control-Expose-Headers") {
		for _, part := range strings.Split(raw, ",") {
			name := strings.TrimSpace(part)
			switch strings.ToLower(name) {
			case "set-cookie", "authorization", "x-csrf-token":
				return name
			}
		}
	}
	return ""
}

// sensitiveJSONKey returns the first sensitive field name used as a JSON key in
// body.
//
// The scan is lexical rather than a full decode, because a body capped by the
// client is often truncated and json.Unmarshal would then reject the whole
// document. Only a quoted string followed by a colon and a value counts as a
// key, so a value that merely reads "email", or a document cut off before the
// value, cannot trigger the signal.
func sensitiveJSONKey(body string) (string, bool) {
	if !looksLikeJSON(body) {
		return "", false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != '"' {
			continue
		}
		end := closingQuote(body, i+1)
		if end < 0 {
			return "", false
		}
		key := body[i+1 : end]
		if colon := skipSpace(body, end+1); colon < len(body) && body[colon] == ':' {
			// A key without a value — a body truncated at the cap, for
			// instance — proves nothing about what the field holds.
			if value := skipSpace(body, colon+1); value < len(body) && sensitiveJSONField(key) {
				return key, true
			}
		}
		i = end
	}
	return "", false
}

// sensitiveJSONField reports whether a JSON key conventionally names
// user-scoped or credential data.
func sensitiveJSONField(key string) bool {
	switch strings.ToLower(key) {
	case "email", "user_id", "token", "access_token", "refresh_token",
		"api_key", "account", "account_id", "balance", "password", "secret",
		"session_id", "ssn", "credit_card":
		return true
	}
	return false
}

// looksLikeJSON reports whether body starts with a JSON container, which keeps
// key-shaped text inside an HTML page or a plain-text log from counting.
func looksLikeJSON(body string) bool {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// closingQuote returns the index of the quote that ends the string starting at
// start, or -1 when the string is unterminated.
func closingQuote(body string, start int) int {
	for i := start; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

// skipSpace returns the index of the first non-space byte at or after start.
func skipSpace(body string, start int) int {
	for i := start; i < len(body); i++ {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return i
		}
	}
	return len(body)
}

// looksLikeLoginPage reports whether body is an unauthenticated login form,
// which holds no data worth a cross-origin read.
func looksLikeLoginPage(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) {
		return true
	}
	return strings.Contains(lower, "<form") && strings.Contains(lower, "login")
}
