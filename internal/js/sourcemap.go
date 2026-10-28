package js

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// sourceMappingURL appears as a trailing line or block comment. The pattern is
// anchored to the comment marker, so a string literal that merely mentions the
// name does not count.
var (
	lineSourceMap  = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s]+)`)
	blockSourceMap = regexp.MustCompile(`/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/`)
)

// queryKeyPattern finds query keys in endpoint literals such as "/api?user=1".
var queryKeyPattern = regexp.MustCompile(`[?&]([A-Za-z_][A-Za-z0-9_]{1,31})=`)

// routeParamPattern finds Express/Koa style path bindings such as "/users/:id".
var routeParamPattern = regexp.MustCompile(`/:([A-Za-z_][A-Za-z0-9_]{1,31})`)

// SourceMap is the subset of the Source Map v3 format the scanner uses.
type SourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// SourceMapURL finds the source map for a fetched script. It prefers the
// SourceMap / X-SourceMap response headers and falls back to a trailing
// sourceMappingURL comment. The result is absolute and same-origin; a map on a
// CDN is someone else's file and is never fetched.
func SourceMapURL(source []byte, scriptURL *url.URL, header http.Header) string {
	if scriptURL == nil {
		return ""
	}

	candidate := ""
	if header != nil {
		for _, name := range []string{"SourceMap", "X-SourceMap"} {
			if value := strings.TrimSpace(header.Get(name)); value != "" {
				candidate = value
				break
			}
		}
	}
	if candidate == "" {
		candidate = sourceMapComment(source)
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}

	resolved, err := scriptURL.Parse(candidate)
	if err != nil {
		return ""
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	if !sameOrigin(resolved, scriptURL) {
		return ""
	}
	resolved.Fragment = ""
	resolved.RawFragment = ""
	return resolved.String()
}

// sourceMapComment returns the last sourceMappingURL comment in the tail of the
// file. Source maps are appended, so scanning the last few kilobytes is enough
// and keeps a huge bundle cheap.
func sourceMapComment(source []byte) string {
	tail := source
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}

	bestIndex := -1
	best := ""
	for _, pattern := range []*regexp.Regexp{lineSourceMap, blockSourceMap} {
		for _, match := range pattern.FindAllSubmatchIndex(tail, -1) {
			if match[0] > bestIndex {
				bestIndex = match[0]
				best = string(tail[match[2]:match[3]])
			}
		}
	}
	return best
}

// sameOrigin requires the exact same scheme, host and port. Source maps are
// code, so a lookalike host is not acceptable.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// ParseSourceMap decodes a v3 map. Only version 3 is accepted: the field
// layout it relies on does not exist in older formats, and guessing would feed
// garbage into endpoint and secret scanning.
func ParseSourceMap(body []byte) (SourceMap, error) {
	var sourceMap SourceMap
	if err := json.Unmarshal(body, &sourceMap); err != nil {
		return SourceMap{}, fmt.Errorf("source map: %w", err)
	}
	if sourceMap.Version != 3 {
		return SourceMap{}, fmt.Errorf("source map: unsupported version %d", sourceMap.Version)
	}
	return sourceMap, nil
}

// EndpointParameters returns a concrete form of an endpoint literal and the
// parameter names it binds. Query keys come from "?name="; route bindings
// ("/:id") become a literal "1" so the endpoint can actually be requested, and
// the binding name is returned for probing.
func EndpointParameters(endpoint string) (string, []string) {
	names := make([]string, 0, 4)
	concrete := routeParamPattern.ReplaceAllStringFunc(endpoint, func(match string) string {
		names = append(names, strings.TrimPrefix(match, "/:"))
		return "/1"
	})
	for _, match := range queryKeyPattern.FindAllStringSubmatch(concrete, -1) {
		names = append(names, match[1])
	}

	seen := make(map[string]struct{}, len(names))
	unique := names[:0]
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		unique = append(unique, name)
	}
	return concrete, unique
}
