package redirect

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/waf"
)

// MethodJSON labels a redirect that was requested with a JSON body, so a report
// never implies a query string was involved.
const MethodJSON = "POST (JSON)"

// JSON findings use their own rule id: a query probe and a JSON probe share a
// URL, and dedupe is keyed on rule|URL.
const jsonRuleID = "redirect.json"

// JSONTarget is one redirect-capable parameter reached through a JSON body.
type JSONTarget struct {
	URL  string
	Name string
}

// ProbeJSON posts each redirect payload as a JSON value and verifies the
// Location header exactly as the query path does. A WAF block page ends the
// attempt: its 403 is not a redirect.
func (a *Analyzer) ProbeJSON(ctx context.Context, target JSONTarget) (finding.Finding, bool) {
	if a == nil || a.client == nil || target.Name == "" || target.URL == "" {
		return finding.Finding{}, false
	}

	for _, payload := range Payloads() {
		body, err := json.Marshal(map[string]string{target.Name: payload})
		if err != nil {
			continue
		}
		response, err := a.client.PostJSON(ctx, target.URL, body)
		if err != nil || waf.IsBlockPage(response) {
			continue
		}
		if !httpx.IsRedirect(response.Status) {
			continue
		}
		location := strings.TrimSpace(response.Location())
		if location == "" || !leavesSite(location, target.URL) {
			continue
		}

		builder := confidence.New(60)
		builder.Add("external-location", 30, "Location header points at the canary host")
		builder.Add("verified-redirect", 5, "response was a redirect with a Location header")

		candidate := finding.Finding{
			Kind:       finding.KindRedirect,
			Category:   "Open Redirect",
			RuleID:     jsonRuleID,
			Title:      "Open Redirect",
			URL:        target.URL,
			Value:      payload,
			Context:    location,
			Confidence: builder.Build(),
		}
		candidate.WithField("Parameter", target.Name)
		candidate.WithField("Method", MethodJSON)
		candidate.WithField("Payload", payload)
		candidate.WithField("Location", location)
		candidate.WithField("Status", strconv.Itoa(response.Status))
		return candidate, true
	}
	return finding.Finding{}, false
}
