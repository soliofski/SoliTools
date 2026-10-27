// Package form extracts HTML forms so the scanner can reach parameters that
// never appear in a URL.
//
// Parsing is deliberately best-effort: a real HTML parser would be an external
// dependency, and a scanner only needs the action, the method and the named
// controls. Anything it cannot understand is skipped rather than guessed at.
package form

import (
	"net/url"
	"regexp"
	"strings"
)

// Field is one named control inside a form.
type Field struct {
	// Name is the submitted parameter name.
	Name string
	// Value is the default value, empty when the markup has none.
	Value string
	// Type is the input type, or the tag name for textarea and select.
	Type string
	// Probe is false for CSRF, nonce and framework fields: they must be
	// submitted with their original value and never replaced by a canary.
	Probe bool
}

// Form is one parsed <form> element.
type Form struct {
	// Action is the absolute, resolved submission URL.
	Action string
	// Method is "GET" or "POST" (uppercased).
	Method string
	// Fields holds every named control, in document order.
	Fields []Field
	// HasFile marks a form with a file input; such forms are never submitted,
	// because a body cannot be reconstructed from markup alone.
	HasFile bool
}

var (
	// formPattern captures the attribute list and body of a form. An unclosed
	// form is skipped: guessing where it ends risks attributing another form's
	// fields to it.
	formPattern = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	// controlPattern captures input, textarea and select tags.
	controlPattern = regexp.MustCompile(`(?is)<(input|textarea|select)\b([^>]*)>`)
	// attrPattern captures name=value pairs in any quoting style.
	attrPattern = regexp.MustCompile(`(?is)([a-z_:][a-z0-9_.:-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// nonSubmitTypes are controls that never carry a value to the server.
var nonSubmitTypes = map[string]struct{}{
	"submit": {}, "button": {}, "reset": {}, "image": {},
}

// csrfNames are submitted unchanged and never probed. Replacing a CSRF token
// makes every other probe fail, and a token is never a sink.
var csrfNames = map[string]struct{}{
	"_token": {}, "csrf": {}, "csrf_token": {}, "csrftoken": {}, "_csrf": {},
	"csrfmiddlewaretoken": {}, "authenticity_token": {}, "__requestverificationtoken": {},
	"_method": {}, "nonce": {}, "state": {},
}

// destructiveTokens mark a form whose submission could change or destroy state.
// The list is intentionally short: it is a safety net for the opt-in POST mode,
// not a substitute for a human deciding what is in scope.
var destructiveTokens = map[string]struct{}{
	"delete": {}, "remove": {}, "destroy": {}, "drop": {}, "purge": {},
	"checkout": {}, "payment": {}, "purchase": {}, "transfer": {}, "withdraw": {},
	"unsubscribe": {}, "deactivate": {}, "cancel": {},
}

// Parse returns every well-formed form in the document.
//
// The action is resolved against base; relative actions are kept, cross-site
// actions are returned as absolute URLs and filtered by the caller.
func Parse(html []byte, base *url.URL) []Form {
	if base == nil {
		return nil
	}
	document := string(html)

	forms := make([]Form, 0, 4)
	for _, match := range formPattern.FindAllStringSubmatch(document, -1) {
		attributes := parseAttrs(match[1])

		method := strings.ToUpper(strings.TrimSpace(attributes["method"]))
		if method != "GET" && method != "POST" {
			// Missing method means GET; an unknown verb is not worth guessing.
			if attributes["method"] != "" {
				continue
			}
			method = "GET"
		}

		action, ok := resolveAction(attributes["action"], base)
		if !ok {
			continue
		}

		candidate := Form{Action: action, Method: method}
		for _, control := range controlPattern.FindAllStringSubmatch(match[2], -1) {
			tag := strings.ToLower(control[1])
			attrs := parseAttrs(control[2])

			name := strings.TrimSpace(attrs["name"])
			if name == "" {
				continue
			}

			fieldType := tag
			if tag == "input" {
				fieldType = strings.ToLower(strings.TrimSpace(attrs["type"]))
				if fieldType == "" {
					fieldType = "text"
				}
			}
			if _, skip := nonSubmitTypes[fieldType]; skip {
				continue
			}
			if fieldType == "file" {
				candidate.HasFile = true
				continue
			}

			value := attrs["value"]
			if fieldType == "checkbox" || fieldType == "radio" {
				// An unchecked box is not submitted by a browser, but the
				// parameter still exists server-side, so it stays probeable.
				if value == "" {
					value = "on"
				}
			}

			candidate.Fields = append(candidate.Fields, Field{
				Name:  name,
				Value: value,
				Type:  fieldType,
				Probe: probeEligible(name),
			})
		}

		forms = append(forms, candidate)
	}
	return forms
}

// Values returns the form's default submission, which is what a probe starts
// from: every field keeps its original value except the one under test.
func (f Form) Values() url.Values {
	values := make(url.Values, len(f.Fields))
	for _, field := range f.Fields {
		values.Set(field.Name, field.Value)
	}
	return values
}

// ProbeFields returns the fields that are worth replacing with a canary.
func (f Form) ProbeFields() []Field {
	out := make([]Field, 0, len(f.Fields))
	for _, field := range f.Fields {
		if field.Probe {
			out = append(out, field)
		}
	}
	return out
}

// LooksDestructive reports whether submitting this form could delete or move
// money. POST probing is opt-in already; this keeps the obvious traps out.
func (f Form) LooksDestructive() bool {
	for _, token := range actionTokens(f.Action) {
		if _, bad := destructiveTokens[token]; bad {
			return true
		}
	}
	for _, field := range f.Fields {
		if _, bad := destructiveTokens[strings.ToLower(field.Name)]; bad {
			return true
		}
	}
	return false
}

// probeEligible reports whether a field may be replaced with a canary.
func probeEligible(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "__") {
		return false // framework state such as __VIEWSTATE
	}
	_, isCSRF := csrfNames[lower]
	return !isCSRF
}

// resolveAction turns the action attribute into an absolute URL.
func resolveAction(raw string, base *url.URL) (string, bool) {
	action := strings.TrimSpace(raw)
	if action == "" {
		return base.String(), true
	}
	reference, err := url.Parse(action)
	if err != nil {
		return "", false
	}
	absolute := base.ResolveReference(reference)
	if absolute.Scheme != "http" && absolute.Scheme != "https" {
		return "", false // mailto:, javascript:, tel:
	}
	absolute.Fragment = ""
	return absolute.String(), true
}

// parseAttrs extracts name=value pairs, lowercasing names. Boolean attributes
// without a value are not captured; nothing here depends on them.
func parseAttrs(raw string) map[string]string {
	attributes := make(map[string]string, 8)
	for _, match := range attrPattern.FindAllStringSubmatch(raw, -1) {
		value := match[3]
		if value == "" {
			value = match[4]
		}
		if value == "" {
			value = match[5]
		}
		attributes[strings.ToLower(match[1])] = unescape(value)
	}
	return attributes
}

// unescape handles the entity forms that appear in attributes often enough to
// matter for a scanner.
func unescape(value string) string {
	if !strings.Contains(value, "&") {
		return value
	}
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&quot;", `"`,
		"&#39;", "'",
		"&lt;", "<",
		"&gt;", ">",
	)
	return replacer.Replace(value)
}

// actionTokens splits the action URL into lowercase alphanumeric tokens.
func actionTokens(raw string) []string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	fields := strings.FieldsFunc(parsed.Path+" "+parsed.RawQuery, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9')
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		tokens = append(tokens, strings.ToLower(field))
	}
	return tokens
}
