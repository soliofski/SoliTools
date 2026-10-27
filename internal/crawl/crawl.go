// Package crawl discovers same-origin pages to scan.
//
// The scope is deliberately narrow: depth one, exact same scheme/host/port, and
// a deny-list for anything that is an asset, a session-ending action or a
// destructive one. A scanner that follows every link becomes a crawler that a
// target can steer; this one only takes pages it can attribute to the seed.
package crawl

import (
	"html"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// anchorTag matches an opening anchor tag. Attribute order and quoting are left
// to the href pattern, so a tag without href simply yields no match.
var anchorTag = regexp.MustCompile(`(?is)<a\b[^>]*>`)

// hrefAttr matches href in double, single or unquoted form.
var hrefAttr = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"\s>]+))`)

// assetExtensions are fetched by the browser as subresources, never as pages.
// Probing them wastes requests and can never reveal an injection point.
var assetExtensions = map[string]struct{}{
	".css": {}, ".js": {}, ".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {},
	".svg": {}, ".ico": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {},
	".pdf": {}, ".zip": {}, ".gz": {}, ".mp4": {},
}

// destructiveMarkers end a session or change state. Following them would make a
// scan indistinguishable from abuse, and any canary they carry would be noise.
var destructiveMarkers = []string{
	"logout", "log-out", "signout", "sign-out",
	"deactivate", "delete-account", "delete_account",
}

// Links returns absolute, same-origin, non-destructive page URLs found in
// document, in first-seen order. limit caps the result; zero means no cap.
//
// base is the URL the document was served from: relative links resolve against
// it, and it defines the origin every candidate must match.
func Links(document []byte, base *url.URL, limit int) []string {
	if base == nil {
		return nil
	}

	seed := normalize(base)
	seen := make(map[string]struct{}, 16)
	links := make([]string, 0, 16)

	for _, tag := range anchorTag.FindAll(document, -1) {
		match := hrefAttr.FindSubmatch(tag)
		if match == nil {
			continue
		}
		raw := string(match[1])
		if raw == "" {
			raw = string(match[2])
		}
		if raw == "" {
			raw = string(match[3])
		}
		href := strings.TrimSpace(html.UnescapeString(raw))
		if href == "" || strings.HasPrefix(href, "#") {
			continue
		}

		parsed, err := base.Parse(href)
		if err != nil || !isHTTP(parsed) || !sameOrigin(parsed, base) {
			continue
		}
		if excluded(parsed) {
			continue
		}

		normalized := normalize(parsed)
		// Re-fetching the seed is pointless; a fragment-only link resolves here.
		if normalized == seed {
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		links = append(links, normalized)
		if limit > 0 && len(links) >= limit {
			break
		}
	}
	return links
}

func isHTTP(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

// sameOrigin requires the exact same scheme, host and port. A redirect from
// http to https is a different origin here on purpose: following it would mean
// scanning a host the user did not name.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
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

func excluded(u *url.URL) bool {
	lowerPath := strings.ToLower(u.Path)
	if _, asset := assetExtensions[path.Ext(lowerPath)]; asset {
		return true
	}
	for _, marker := range destructiveMarkers {
		if strings.Contains(lowerPath, marker) {
			return true
		}
	}
	return false
}

// normalize strips the fragment and redundant trailing slashes so the same page
// is fetched once, however many spellings the markup contains.
func normalize(u *url.URL) string {
	normalized := *u
	normalized.Fragment = ""
	normalized.RawFragment = ""
	if normalized.Path == "" {
		normalized.Path = "/"
	}
	normalized.Path = strings.TrimRight(normalized.Path, "/")
	if normalized.Path == "" {
		normalized.Path = "/"
	}
	return normalized.String()
}
