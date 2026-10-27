package secret

import (
	"regexp"
	"strings"
	"sync"

	"solitools/internal/confidence"
)

// Rule describes one detector.
//
// Two kinds of fields exist on purpose:
//
//   - Gates (MinLen, MaxLen, EntropyMin, Require) reject a candidate outright.
//     A malformed candidate is not a weak finding, it is not a finding at all.
//   - Validate only ever adds a confidence signal. It is advisory, so an
//     unverifiable structure can never downgrade a real credential.
//
// Every gate except Require sees the payload: the captured value with the
// vendor prefix removed. Striping the prefix keeps a low-entropy string such
// as "sk_live_" from depressing the entropy of the part that must be random.
type Rule struct {
	ID          string
	Name        string
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

	// Generic marks rules that match a shape rather than a provider. They are
	// opt-in and carry a scoring penalty.
	Generic bool

	// Require is a hard structural gate. false rejects the candidate.
	Require func(full, payload string) bool
	// Validate is an advisory structural check that can raise confidence.
	Validate func(full, payload string) (confidence.Signal, bool)

	// RedactFullMatch reports the position and redaction of the whole match
	// instead of the captured group. It exists for block formats such as PEM,
	// where the header is the only legible evidence and the payload is opaque
	// key material.
	RedactFullMatch bool

	once sync.Once
	re   *regexp.Regexp
}

// Regexp returns the compiled pattern, compiling it on first use.
//
// Scanner.New compiles every pattern up front so a malformed rule is reported
// as an error instead of a panic at scan time.
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
