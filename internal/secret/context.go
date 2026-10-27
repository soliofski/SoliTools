package secret

import (
	"strings"
	"unicode"
)

// ContextRadius is how many characters of context accompany a finding. The
// product requirement is at least 30 on each side; 40 leaves room for the
// ellipsis trimming to still show meaningful surroundings.
const ContextRadius = 40

// Context returns a one-line snippet around text[start:end].
//
// Whitespace runs collapse to single spaces so a match inside minified
// JavaScript stays readable, and "...". marks where the snippet was cut.
func Context(text string, start, end, radius int) string {
	return contextWithin(text, start, end, radius, len(text))
}

// contextWithin is Context with a hard right bound. Block formats use it so the
// snippet can never read into key material beyond the header.
func contextWithin(text string, start, end, radius, limit int) string {
	if radius <= 0 {
		radius = ContextRadius
	}
	if limit > len(text) {
		limit = len(text)
	}
	if start < 0 {
		start = 0
	}
	if start > limit {
		start = limit
	}
	if end > limit {
		end = limit
	}
	if end < start {
		end = start
	}

	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > limit {
		to = limit
	}

	snippet := collapseSpace(text[from:to])
	if from > 0 {
		snippet = "..." + snippet
	}
	if to < len(text) {
		snippet += "..."
	}
	return strings.ToValidUTF8(snippet, "?")
}

// collapseSpace replaces every whitespace run with a single space and trims.
func collapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// Mask returns a display-safe form of a credential.
//
// The head identifies the provider, the tail distinguishes two similar
// findings, and the middle is masked (capped so a long blob cannot flood a
// report). PEM blocks keep their header only: the body is opaque key material
// and even a masked prefix of it is useless.
func Mask(value string) string {
	if strings.HasPrefix(value, "-----BEGIN ") {
		if labelEnd := strings.Index(value, "-----"); labelEnd >= 0 {
			if closeAt := strings.Index(value[labelEnd+5:], "-----"); closeAt >= 0 {
				// The header names the algorithm; the body never leaves the scanner.
				return value[:labelEnd+5+closeAt+5]
			}
		}
		return "[redacted PEM block]"
	}

	runes := []rune(value)
	n := len(runes)
	switch {
	case n == 0:
		return ""
	case n <= 8:
		return strings.Repeat("*", n)
	}

	head, tail := 4, 4
	if n < 16 {
		head, tail = 2, 2
	}
	masked := n - head - tail
	if masked > 32 {
		masked = 32
	}
	return string(runes[:head]) + strings.Repeat("*", masked) + string(runes[n-tail:])
}
