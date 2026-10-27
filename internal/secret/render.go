package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// Fingerprint returns a short, stable hash of a payload.
//
// Whitespace is removed first so the same PEM key wrapped differently, or the
// same token with different quoting, produces the same fingerprint. This is
// what lets the report collapse duplicates and correlate a credential across
// files and responses without storing the value itself.
func Fingerprint(payload string) string {
	sum := sha256.Sum256([]byte(stripSpaces(payload)))
	return hex.EncodeToString(sum[:])[:16]
}

// stripSpaces removes all whitespace, including newlines and tabs.
func stripSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
