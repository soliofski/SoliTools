// Package redirect detects open redirects.
//
// The distinction that matters for accuracy is between a redirect that leaves
// the site and one that stays inside it. Only an external Location counts: a
// relative redirect is normal application behaviour, not a finding.
package redirect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/param"
)

// Canary host and path used for every probe.
//
// example.com is reserved for documentation by RFC 2606. The tool never follows
// the redirect, so no third party is contacted; only the Location header is
// inspected.
const (
	canaryHost = "example.com"
	canaryPath = "/solitools-redirect-check"
)

// Payloads returns the redirect payload styles: absolute, scheme-relative and
// backslash-mangled, which many naive filters let through.
func Payloads() []string {
	absolute := "https://" + canaryHost + canaryPath
	return []string{
		absolute,
		"//" + canaryHost + canaryPath,
		`/\` + canaryHost + canaryPath,
	}
}

// IsRedirectParam reports whether a parameter name conventionally controls a
// redirect. Only these parameters are probed by the redirect module.
func IsRedirectParam(name string) bool {
	_, ok := redirectParams[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// redirectParams is the redirect-specific subset of high-interest names. A
// generic "path" or "file" parameter belongs to the path module, not here.
var redirectParams = map[string]struct{}{
	"redirect": {}, "redirect_uri": {}, "redirect_url": {}, "redirecturi": {},
	"url": {}, "uri": {}, "next": {}, "callback": {}, "return": {},
	"return_url": {}, "returnurl": {}, "return_to": {}, "returnto": {},
	"dest": {}, "destination": {}, "goto": {}, "out": {}, "link": {},
	"forward": {}, "continue": {}, "target": {},
}

// Target is one parameter to test.
type Target struct {
	URL  string
	Name string
	// Interest is carried through for reporting and prioritisation.
	Interest param.Interest
	// Method is empty or "GET" for a query parameter, "POST" for a form field.
	Method string
	// Fields holds the form's default values; the probed field is replaced.
	Fields url.Values
}

// Analyzer probes redirect-capable parameters through a shared client.
type Analyzer struct {
	client *httpx.Client
}

// New builds an Analyzer. A nil client makes Probe a no-op.
func New(client *httpx.Client) *Analyzer { return &Analyzer{client: client} }

// Probe reports an open redirect only when the response actually redirects to
// the canary host.
func (a *Analyzer) Probe(ctx context.Context, target Target) (finding.Finding, bool) {
	if a == nil || a.client == nil || target.Name == "" || target.URL == "" {
		return finding.Finding{}, false
	}

	for _, payload := range Payloads() {
		response, probeURL, err := a.send(ctx, target, payload)
		if err != nil {
			continue
		}
		if !httpx.IsRedirect(response.Status) {
			continue
		}
		location := strings.TrimSpace(response.Location())
		if location == "" {
			continue
		}
		if !leavesSite(location, probeURL) {
			continue
		}

		builder := confidence.New(60)
		builder.Add("external-location", 30, "Location header points at the canary host")
		builder.Add("verified-redirect", 5, fmt.Sprintf("response was a %d with a Location header", response.Status))

		candidate := finding.Finding{
			Kind:       finding.KindRedirect,
			Category:   "Open Redirect",
			RuleID:     "redirect.open",
			Title:      "Open Redirect",
			URL:        probeURL,
			Value:      payload,
			Context:    location,
			Confidence: builder.Build(),
		}
		candidate.WithField("Parameter", target.Name)
		if strings.EqualFold(target.Method, http.MethodPost) {
			candidate.WithField("Method", http.MethodPost)
		}
		candidate.WithField("Payload", payload)
		candidate.WithField("Location", location)
		candidate.WithField("Status", fmt.Sprintf("%d", response.Status))
		return candidate, true
	}
	return finding.Finding{}, false
}

// leavesSite reports whether location resolves to the canary host and carries
// the canary path. Relative and internal targets are rejected.
//
// base is accepted for call-site symmetry and cannot change the verdict: a
// Location that only becomes absolute through base is, by definition, internal.
func leavesSite(location, base string) bool {
	parsed, err := url.Parse(normalizeLocation(location))
	if err != nil {
		return false
	}
	// Hostnames are case-insensitive; a server may normalise the case of the
	// echoed value.
	if !strings.EqualFold(parsed.Hostname(), canaryHost) {
		return false
	}
	return strings.Contains(parsed.Path, "solitools-redirect-check")
}

// normalizeLocation rewrites a scheme-relative Location into an absolute URL.
//
// Browsers treat a backslash as a slash in the authority position, so "/\host",
// "\/host" and "\\host" all mean "//host". A filter that only blocks "//" lets
// those through, and the server may echo the value back verbatim; normalising
// the leading run before parsing turns such an echo into a detectable external
// redirect instead of an unparseable relative path.
//
// A single leading slash is a path and must stay one, otherwise every internal
// redirect would look external.
func normalizeLocation(location string) string {
	candidate := strings.TrimSpace(location)

	separators := 0
	for separators < len(candidate) && (candidate[separators] == '/' || candidate[separators] == '\\') {
		separators++
	}
	if separators >= 2 {
		return "https://" + candidate[separators:]
	}
	return candidate
}

// send issues one probe and reports the URL that was actually requested: the
// payload stays visible in a query string, while a POST is identified by its
// action URL plus the payload field.
func (a *Analyzer) send(ctx context.Context, target Target, payload string) (*httpx.Response, string, error) {
	if strings.EqualFold(target.Method, http.MethodPost) {
		values := make(url.Values, len(target.Fields)+1)
		for name, list := range target.Fields {
			values[name] = append([]string(nil), list...)
		}
		values.Set(target.Name, payload)
		response, err := a.client.PostForm(ctx, target.URL, values)
		return response, target.URL, err
	}

	probeURL, err := withParam(target.URL, target.Name, payload)
	if err != nil {
		return nil, "", err
	}
	response, err := a.client.Get(ctx, probeURL)
	return response, probeURL, err
}

func withParam(rawURL, name, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(name, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
