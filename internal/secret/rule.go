package secret

import (
	"regexp"
	"strings"
	"sync"

	"github.com/soliofski/SoliTools/internal/confidence"
)

// Rule describes one credential detector.
//
// Two kinds of fields exist on purpose:
//
//   - Gates (MinLen, MaxLen, EntropyMin, Require) reject a candidate outright.
//     A malformed candidate is not a weak finding, it is not a finding at all.
//   - Validate only ever adds a confidence signal. It is advisory, so an
//     unverifiable structure can never downgrade a real credential.
//
// Every gate except Require sees the payload: the captured value with the
// vendor prefix removed. Stripping the prefix keeps a low-entropy string such
// as "sk_live_" from depressing the entropy of the part that must be random.
type Rule struct {
	// ID is the stable machine identifier, e.g. "secret.aws-access-key-id".
	ID string
	// Title is the human headline shown in the report, e.g. "AWS Access Key".
	Title string
	// Category groups the rule for reporting: "AWS", "GitHub", "JWT", ...
	Category string
	// Description is the one-line explanation shown in verbose output.
	Description string

	// Base is the starting confidence in [0, 100]. It encodes how strongly the
	// pattern alone identifies this provider's credential format.
	Base float64

	// Pattern is a RE2 expression; lookarounds are unavailable by design.
	Pattern string
	// Group is the capture group holding the secret. Zero means the full match.
	Group int
	// Prefixes are stripped from the captured value, first match wins.
	Prefixes []string

	MinLen     int
	MaxLen     int
	EntropyMin float64

	// Generic marks rules that match a shape rather than a provider. They carry
	// a scoring penalty, so they sort below the display threshold by default.
	Generic bool

	// Require is a hard structural gate. false rejects the candidate.
	Require func(full, payload string) bool
	// Validate is an advisory structural check that can raise confidence.
	Validate func(full, payload string) (confidence.Signal, bool)

	// RedactFullMatch reports the whole match instead of the captured group.
	// It exists for block formats such as PEM, where the header is the only
	// legible evidence and the payload is opaque key material.
	RedactFullMatch bool
	// ShieldGeneric suppresses generic matches that fall inside this rule's
	// span. Base64 key material must never resurface as "high-entropy string",
	// even when the block itself fails its structural gate.
	ShieldGeneric bool

	once sync.Once
	re   *regexp.Regexp
}

// Regexp returns the compiled pattern, compiling it on first use.
//
// New compiles every pattern up front so a malformed rule is reported as an
// error instead of a panic at scan time.
func (r *Rule) Regexp() *regexp.Regexp {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.Pattern)
	})
	return r.re
}

// StripPrefix removes the first matching vendor prefix from value.
func (r *Rule) StripPrefix(value string) string {
	for _, prefix := range r.Prefixes {
		if len(value) > len(prefix) && strings.HasPrefix(value, prefix) {
			return value[len(prefix):]
		}
	}
	return value
}
