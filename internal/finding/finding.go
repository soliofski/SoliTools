// Package finding defines the data shared by every SoliTools detector.
//
// A Finding is deliberately data-only: it carries the evidence needed to
// re-verify a result (location, redacted match, fingerprint, score trace) and
// never the raw secret value.
package finding

import "solitools/internal/confidence"

// Kind identifies which detector produced a finding.
type Kind string

const (
	// KindSecret is a hardcoded credential candidate.
	KindSecret Kind = "secret"
)

// Finding is one reported candidate.
type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Description string `json:"description,omitempty"`
	Kind        Kind   `json:"kind"`

	// Location is 1-based. Column counts runes, not bytes, from the start of
	// the line.
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`

	// Match is redacted: enough context to recognize the value, never enough
	// to use it. Fingerprint is a truncated hash of the payload, so the same
	// secret can be correlated across files without being revealed.
	Match       string `json:"match"`
	Fingerprint string `json:"fingerprint"`

	Confidence confidence.Score `json:"confidence"`
}
