package secret

import (
	"strconv"
	"strings"
)

// placeholderMarkers are substrings that only appear in documentation,
// fixtures or templates.
//
// Matching is case-insensitive and runs against the payload only — that is,
// after the vendor prefix has been stripped — so a provider name can never mask
// a real token, while "example" inside a bare value is enough to reject it.
// This is the filter that removes canonical documentation leaks such as
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
	"TODO",
	"FIXME",
	"***",
	"<",
	">",
	"test",
	"fake",
	"demo",
	"localhost",
}

// placeholderReason reports which marker made a payload look like a template.
func placeholderReason(payload string) (string, bool) {
	lower := strings.ToLower(payload)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return "placeholder marker " + strconv.Quote(strings.ToLower(marker)), true
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
