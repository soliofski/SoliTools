// Package reflect probes parameters for input reflection and grades how
// dangerous the reflected position is.
//
// The canaries are deliberately inert: they break quotes and tags but contain no
// event handler and no executable script. A probe can therefore never fire code
// on the target, and a "detected" result still needs a human to confirm
// exploitability.
package reflect

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

// Context is where in the response the payload landed.
type Context string

const (
	// ContextHTMLText is a payload between tags, the classic injection point.
	ContextHTMLText Context = "HTML body"
	// ContextAttribute is a payload inside a tag, e.g. an href value.
	ContextAttribute Context = "HTML attribute"
	// ContextScript is a payload inside a script block.
	ContextScript Context = "JavaScript"
	// ContextComment is a payload inside an HTML comment: not executable.
	ContextComment Context = "HTML comment"
	// ContextJSON is a payload in a JSON response.
	ContextJSON Context = "JSON body"
	// ContextUnknown means the position could not be classified.
	ContextUnknown Context = "unknown"
)

// Payloads returns the canaries used for every probe.
//
// Three payloads of different length and character class satisfy the product
// requirement and make encoding visible: if only the alphanumeric canary
// survives, the response is escaping the interesting characters.
func Payloads() []string {
	return []string{
		"solix1z9q",
		`soli"x2z'q`,
		"soli<x3z>yq",
	}
}

// Target is one parameter to probe.
type Target struct {
	// URL is the page or endpoint carrying the parameter.
	URL string
	// Name is the parameter name.
	Name string
	// Interest is the classification used to prioritise probing.
	Interest param.Interest
	// Method is empty or "GET" for a query parameter, "POST" for a form field.
	Method string
	// Fields holds the form's default values; the probed field is replaced and
	// every other field keeps its original value, CSRF tokens included.
	Fields url.Values
}

// Analyzer sends reflection probes through a shared, rate-limited client.
type Analyzer struct {
	client *httpx.Client
}

// New builds an Analyzer. A nil client makes Probe a no-op.
func New(client *httpx.Client) *Analyzer { return &Analyzer{client: client} }

// Classify reports where in body the offset falls.
func Classify(body string, offset int) Context {
	if offset < 0 {
		offset = 0
	}
	if offset > len(body) {
		offset = len(body)
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return ContextJSON
	}

	prefix := body[:offset]
	lower := strings.ToLower(prefix)

	if open := strings.LastIndex(prefix, "<!--"); open >= 0 && !strings.Contains(prefix[open:], "-->") {
		return ContextComment
	}
	if lastOpen, lastClose := strings.LastIndex(prefix, "<"), strings.LastIndex(prefix, ">"); lastOpen > lastClose {
		return ContextAttribute
	}
	if strings.LastIndex(lower, "<script") > strings.LastIndex(lower, "</script") {
		return ContextScript
	}
	return ContextHTMLText
}

// Probe replaces the parameter with each canary and reports a reflection.
//
// A finding needs either two reflected canaries or the tag-breaking canary
// intact: a lone alphanumeric echo is usually an error page repeating the
// query, which is exactly the false positive this module must not produce.
func (a *Analyzer) Probe(ctx context.Context, target Target) (finding.Finding, bool) {
	if a == nil || a.client == nil || target.Name == "" || target.URL == "" {
		return finding.Finding{}, false
	}

	canaries := Payloads()
	reflected := make(map[string]bool, len(canaries))
	status := 0
	body := ""
	payloadUsed := ""
	point := ContextUnknown

	for _, payload := range canaries {
		response, err := a.send(ctx, target, payload)
		if err != nil {
			continue
		}
		status = response.Status
		text := response.BodyString()

		offset := strings.Index(text, payload)
		if offset < 0 {
			continue // escaped or absent: not a raw reflection
		}
		reflected[payload] = true
		if payloadUsed == "" {
			payloadUsed = payload
			body = text
			point = Classify(text, offset)
		}
	}

	// The tag-breaking canary is the most informative one.
	strong := reflected[canaries[2]]
	if len(reflected) < 2 && !strong {
		return finding.Finding{}, false
	}

	builder := confidence.New(45)
	builder.Add("unencoded", 15, "canary reflected without encoding")

	switch point {
	case ContextHTMLText, ContextAttribute:
		builder.Add("context", 20, "reflected in "+string(point))
	case ContextScript:
		builder.Add("context", 12, "reflected inside JavaScript")
	case ContextComment:
		builder.Add("context", -25, "reflected inside a comment: not executable")
	}
	if len(reflected) >= 2 {
		builder.Add("consistent", 10, fmt.Sprintf("%d of %d canaries reflected", len(reflected), len(canaries)))
	}
	if status >= 400 {
		builder.Add("error-response", -10, fmt.Sprintf("reflection on a %d response", status))
	}
	if looksLikeErrorPage(body) {
		builder.Add("error-page", -10, "response body looks like a generic error page")
	}

	candidate := finding.Finding{
		Kind:       finding.KindReflect,
		Category:   "Reflected XSS",
		RuleID:     "reflect.html",
		Title:      "Potential Reflected XSS",
		URL:        target.URL,
		Value:      payloadUsed,
		Context:    snippet(body, payloadUsed),
		Confidence: builder.Build(),
	}
	candidate.WithField("Parameter", target.Name)
	if isFormPost(target.Method) {
		candidate.WithField("Method", http.MethodPost)
	}
	candidate.WithField("Reflection Point", string(point))
	candidate.WithField("Payload", payloadUsed)
	candidate.WithField("Status", fmt.Sprintf("%d", status))
	return candidate, true
}

// looksLikeErrorPage detects the generic "nothing found" responses that echo
// the query string back without executing anything.
func looksLikeErrorPage(body string) bool {
	if body == "" {
		return false
	}
	head := body
	if len(head) > 2000 {
		head = head[:2000]
	}
	lower := strings.ToLower(head)
	for _, marker := range []string{"not found", "no results", "page not found", "invalid request", "error occurred", "does not exist"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// snippet returns a short window around the payload inside body.
func snippet(body, payload string) string {
	if payload == "" {
		return ""
	}
	offset := strings.Index(body, payload)
	if offset < 0 {
		return ""
	}
	const radius = 40
	from := offset - radius
	if from < 0 {
		from = 0
	}
	to := offset + len(payload) + radius
	if to > len(body) {
		to = len(body)
	}
	text := collapse(body[from:to])
	if from > 0 {
		text = "..." + text
	}
	if to < len(body) {
		text += "..."
	}
	return text
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// send issues one probe: a query parameter for a URL, or a form body field for
// a POST form.
func (a *Analyzer) send(ctx context.Context, target Target, payload string) (*httpx.Response, error) {
	if isFormPost(target.Method) {
		values := cloneValues(target.Fields)
		values.Set(target.Name, payload)
		return a.client.PostForm(ctx, target.URL, values)
	}
	probeURL, err := withParam(target.URL, target.Name, payload)
	if err != nil {
		return nil, err
	}
	return a.client.Get(ctx, probeURL)
}

// isFormPost reports whether the target is a form field rather than a query
// parameter.
func isFormPost(method string) bool {
	return strings.EqualFold(method, http.MethodPost)
}

// cloneValues copies form defaults so one probe cannot leak into the next.
func cloneValues(values url.Values) url.Values {
	out := make(url.Values, len(values)+1)
	for name, list := range values {
		out[name] = append([]string(nil), list...)
	}
	return out
}

// withParam returns rawURL with the named query parameter replaced by value.
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
