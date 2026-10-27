package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// Redact returns a display-safe form of a matched value.
//
// Tokens keep their first four characters so a reader can recognize the
// provider and their last two so two similar findings can be told apart. The
// middle is masked, capped at 32 stars so a long blob cannot flood a report.
// PEM blocks keep only their header. Nothing here reproduces the secret.
func Redact(match string) string {
	if strings.HasPrefix(match, "-----BEGIN ") {
		if labelEnd := strings.Index(match, "-----"); labelEnd >= 0 {
			if close := strings.Index(match[labelEnd+5:], "-----"); close >= 0 {
				return match[:labelEnd+5+close+5] + " [body redacted]"
			}
		}
		return "[redacted PEM block]"
	}

	runes := []rune(match)
	n := len(runes)
	switch {
	case n == 0:
		return ""
	case n <= 8:
		return strings.Repeat("*", n)
	}

	mask := n - 6
	if mask > 32 {
		mask = 32
	}
	return string(runes[:4]) + strings.Repeat("*", mask) + string(runes[n-2:])
}

// Fingerprint returns a short, stable hash of a payload.
//
// Whitespace is removed first so the same PEM key wrapped differently, or the
// same token with different quoting, produces the same fingerprint. This lets
// findings be correlated across files without storing the value itself.
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
