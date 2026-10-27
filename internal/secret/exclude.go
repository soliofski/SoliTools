package secret

import (
	"path/filepath"
	"strconv"
	"strings"
)

// placeholderMarkers are substrings that only appear in documentation,
// fixtures or templates.
//
// Matching is case-insensitive and runs against the payload only — that is,
// after the vendor prefix has been stripped — so a prefix can never mask a
// real token, and "example" inside a bare value is enough to reject it. This
// is the filter that removes canonical documentation leaks such as
// AKIAIOSFODNN7EXAMPLE.
var placeholderMarkers = []string{
	"example",
	"sample",
	"dummy",
	"placeholder",
	"changeme",
	"change_me",
	"change-me",
	"your_",
	"your-",
	"insert_",
	"replace_",
	"redacted",
	"not-real",
	"notreal",
	"foobar",
	"lorem",
	"todo",
	"fixme",
	"***",
	"<",
	">",
}

// placeholderReason reports which marker made a payload look like a template.
func placeholderReason(payload string) (string, bool) {
	lower := strings.ToLower(payload)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return "placeholder marker " + strconv.Quote(marker), true
		}
	}
	return "", false
}

// isDegenerate reports payloads that cannot be real credentials: three or
// fewer distinct characters, or a run of eight identical characters.
//
// This catches padding like "aaaaaaaa" that survives a length check while
// keeping random tokens (which always show many distinct symbols) untouched.
func isDegenerate(payload string) bool {
	runes := []rune(payload)
	if len(runes) < 4 {
		return true
	}

	distinct := make(map[rune]struct{}, 4)
	for _, r := range runes {
		distinct[r] = struct{}{}
		if len(distinct) > 3 {
			break
		}
	}
	if len(distinct) <= 3 {
		return true
	}

	run := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			run++
			if run >= 8 {
				return true
			}
			continue
		}
		run = 1
	}
	return false
}

// pathPenalty lowers confidence for files that are expected to contain fake
// credentials. It never suppresses: a fixture can still hold a real key copied
// in by mistake, it just ranks lower.
func pathPenalty(path string) (float64, string) {
	if path == "" {
		return 0, ""
	}
	slashed := filepath.ToSlash(strings.ToLower(path))
	// Normalize so both "examples/x" and "C:/repo/examples/x" match the same
	// slash-delimited markers below.
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	switch {
	case strings.Contains(slashed, "testdata"),
		strings.Contains(slashed, "fixtures"),
		strings.Contains(slashed, "__tests__"),
		strings.Contains(slashed, "/test/"),
		strings.HasSuffix(slashed, "_test.go"),
		strings.HasSuffix(slashed, "_test.py"),
		strings.HasSuffix(slashed, ".test.js"),
		strings.HasSuffix(slashed, ".spec.js"):
		return -20, "path looks like a test fixture"
	case strings.Contains(slashed, "/examples/"),
		strings.Contains(slashed, "/samples/"),
		strings.Contains(slashed, "/docs/"),
		strings.HasSuffix(slashed, ".md"),
		strings.HasSuffix(slashed, ".rst"),
		strings.HasSuffix(slashed, ".txt"),
		strings.Contains(slashed, "readme"):
		return -10, "path looks like documentation or sample data"
	}
	return 0, ""
}
