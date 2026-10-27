// Package finding defines the result type shared by every SoliTools module.
//
// A Finding is deliberately data-only: it carries the evidence needed to
// re-verify a result (source, location, context, score trace) and can render
// itself in the tool's report format. Detectors never print; they return data.
package finding

import (
	"fmt"
	"strings"

	"solitools/internal/confidence"
)

// Kind is the module that produced a finding. It is the first column of the
// report, e.g. "[SECRET]".
type Kind string

const (
	// KindSecret is a credential candidate found in a response body.
	KindSecret Kind = "SECRET"
	// KindReflect is a reflected-input (potential XSS) candidate.
	KindReflect Kind = "REFLECT"
	// KindRedirect is an open-redirect candidate.
	KindRedirect Kind = "REDIRECT"
	// KindPath is a sensitive path that answered with a meaningful status.
	KindPath Kind = "PATH"
)

// Field is one ordered, module-specific detail line, such as
// {"Reflection Point", "HTML attribute"}.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Finding is one reported candidate.
type Finding struct {
	Kind Kind `json:"kind"`

	// Category groups findings by provider or vulnerability class: "AWS",
	// "GitHub", "JWT", "Generic Secret", "Open Redirect", "Sensitive Path".
	Category string `json:"category"`
	// RuleID is the stable machine identifier, e.g. "secret.aws-access-key-id".
	RuleID string `json:"rule_id"`
	// Title is the human headline, e.g. "AWS Access Key".
	Title string `json:"title"`

	// URL is where the evidence came from: the response URL for secrets and
	// reflections, the probed URL for redirects and paths.
	URL string `json:"url"`

	// Value is the matched secret or the payload that produced the finding.
	// It is masked at render time when masking is requested.
	Value string `json:"value,omitempty"`
	// Context is a short snippet around the evidence, with newlines collapsed.
	Context string `json:"context,omitempty"`
	// Fingerprint is a stable hash used for deduplication and correlation.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Fields holds module-specific details in display order.
	Fields []Field `json:"fields,omitempty"`

	Confidence confidence.Score `json:"confidence"`
}

// WithField appends a detail line if the value is not empty.
func (f *Finding) WithField(name, value string) *Finding {
	if strings.TrimSpace(value) == "" {
		return f
	}
	f.Fields = append(f.Fields, Field{Name: name, Value: value})
	return f
}

// DedupeKey returns the identity used to collapse duplicate findings.
//
// Secrets are identified by rule plus value fingerprint, so the same key found
// on ten pages is reported once; network findings are identified by rule plus
// URL, because two different payloads at the same URL are the same result.
func (f Finding) DedupeKey() string {
	switch f.Kind {
	case KindSecret:
		return string(f.Kind) + "|" + f.RuleID + "|" + f.Fingerprint
	default:
		return string(f.Kind) + "|" + f.RuleID + "|" + f.URL
	}
}

// Header renders the report headline, e.g. "[SECRET] [93] AWS Access Key".
func (f Finding) Header() string {
	return fmt.Sprintf("[%s] [%d] %s", f.Kind, int(f.Confidence.Value+0.5), f.Title)
}
