// Package js analyses JavaScript delivered by a target.
//
// Two goals, both precision-driven: decide which scripts actually belong to the
// target (a CDN copy of jQuery will never contain that target's endpoints), and
// extract only endpoint-shaped strings, so the param and reflect modules are not
// fed asset paths such as "/static/logo.svg".
package js

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// scriptSrcPattern matches <script ... src="..."> in either quote style.
	scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

	// quotedPathPattern matches "/api/v1/users?x=1" style literals. The leading
	// slash is required: without it any quoted word becomes an "endpoint", and a
	// token such as "ghp_..." would be reported as one.
	quotedPathPattern = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./~%?=&+]{2,300})[\"'`]")
	// absoluteURLPattern matches full URLs embedded in bundles.
	absoluteURLPattern = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-./~%?=&+]{0,300}`)
)

// assetExtensions are paths that are never endpoints worth probing.
var assetExtensions = map[string]struct{}{
	".css": {}, ".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {},
	".ico": {}, ".webp": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {},
	".map": {}, ".mp4": {}, ".mp3": {}, ".webm": {}, ".pdf": {}, ".zip": {},
	".js": {}, ".mjs": {}, ".jsx": {}, ".ts": {}, ".tsx": {},
}

// thirdPartyHosts are analytics, tag managers and public CDNs. A script here is
// framework code, not target code, so its endpoints are irrelevant.
var thirdPartyHosts = []string{
	"google-analytics.com", "googletagmanager.com", "gstatic.com", "googleapis.com",
	"doubleclick.net", "googlesyndication.com", "adservice.google.com",
	"cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
	"bootstrapcdn.com", "jquery.com", "code.jquery.com", "fontawesome.com",
	"facebook.net", "connect.facebook.net", "hotjar.com", "segment.com",
	"segment.io", "sentry.io", "sentry-cdn.com", "newrelic.com", "nr-data.net",
	"datadoghq-browser-agent.com", "optimizely.com", "crazyegg.com", "mouseflow.com",
	"zendesk.com", "intercom.io", "intercomcdn.com", "stripe.com", "paypal.com",
	"recaptcha.net", "hcaptcha.com", "akamaihd.net", "amazonaws.com",
}

// twoLevelSuffixes are public suffixes with two labels.
var twoLevelSuffixes = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "com.au": {}, "net.au": {}, "co.jp": {},
	"com.br": {}, "com.cn": {}, "co.in": {}, "co.za": {}, "com.tr": {}, "com.mx": {},
	"co.nz": {}, "com.sg": {}, "com.hk": {}, "com.pl": {},
}

// resolve returns the absolute form of raw against base.
func resolve(raw string, base *url.URL) (string, bool) {
	if base == nil {
		return "", false
	}
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	absolute := base.ResolveReference(reference)
	if absolute.Scheme != "http" && absolute.Scheme != "https" {
		return "", false
	}
	absolute.Fragment = ""
	return absolute.String(), true
}

// ScriptURLs returns the absolute src values found in an HTML document, in
// document order, with duplicates removed.
func ScriptURLs(html []byte, base *url.URL) []string {
	return resolveAll(scriptSrcPattern.FindAllStringSubmatch(string(html), -1), base)
}

func resolveAll(matches [][]string, base *url.URL) []string {
	seen := make(map[string]struct{}, len(matches))
	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		absolute, ok := resolve(match[1], base)
		if !ok {
			continue
		}
		if _, duplicate := seen[absolute]; duplicate {
			continue
		}
		seen[absolute] = struct{}{}
		urls = append(urls, absolute)
	}
	return urls
}

// IsThirdParty reports whether asset belongs to a different site than base.
//
// Same registrable domain is treated as first-party: assets served from a
// static subdomain of the target usually do carry target code.
func IsThirdParty(asset, base *url.URL) bool {
	if asset == nil || base == nil {
		return true
	}
	assetHost := strings.ToLower(asset.Hostname())
	baseHost := strings.ToLower(base.Hostname())
	if assetHost == "" || baseHost == "" {
		return true
	}
	if assetHost == baseHost {
		return false
	}
	if domainOf(assetHost) == domainOf(baseHost) {
		return false
	}
	for _, host := range thirdPartyHosts {
		if assetHost == host || strings.HasSuffix(assetHost, "."+host) {
			return true
		}
	}
	return true
}

// ExtractEndpoints returns normalized, deduplicated first-party endpoints found
// in a script body.
func ExtractEndpoints(source []byte, base *url.URL) []string {
	text := string(source)
	matches := quotedPathPattern.FindAllStringSubmatch(text, -1)

	seen := make(map[string]struct{}, len(matches))
	endpoints := make([]string, 0, len(matches))

	add := func(raw string) {
		absolute, ok := normalizeEndpoint(raw, base)
		if !ok {
			return
		}
		if _, duplicate := seen[absolute]; duplicate {
			return
		}
		seen[absolute] = struct{}{}
		endpoints = append(endpoints, absolute)
	}

	for _, match := range matches {
		add(match[1])
	}
	for _, raw := range absoluteURLPattern.FindAllString(text, -1) {
		add(raw)
	}

	return endpoints
}

// normalizeEndpoint resolves a candidate and rejects anything that is not a
// plausible first-party API path.
func normalizeEndpoint(candidate string, base *url.URL) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || strings.HasPrefix(candidate, "//") {
		return "", false
	}
	// Template placeholders and format strings are not endpoints.
	for _, marker := range []string{"${", "{{", "<%", "%s", "}}"} {
		if strings.Contains(candidate, marker) {
			return "", false
		}
	}

	reference, err := url.Parse(candidate)
	if err != nil {
		return "", false
	}
	if reference.Host == "" {
		if base == nil {
			return "", false
		}
		reference.Scheme = base.Scheme
		reference.Host = base.Host
	}
	absolute := base.ResolveReference(reference)
	if absolute.Scheme != "http" && absolute.Scheme != "https" {
		return "", false
	}
	absolute.Fragment = ""

	pathPart := strings.ToLower(absolute.Path)
	if pathPart == "" || pathPart == "/" {
		return "", false
	}
	if extension := pathExtension(pathPart); extension != "" {
		if _, isAsset := assetExtensions[extension]; isAsset {
			return "", false
		}
	}
	if IsThirdParty(absolute, base) {
		return "", false
	}
	return absolute.String(), true
}

// pathExtension returns the final extension of a path, ignoring any query.
func pathExtension(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 || dot == len(path)-1 {
		return ""
	}
	return path[dot:]
}

// domainOf returns the registrable domain of a host, using a small table for
// common two-label public suffixes. Good enough to separate a target from its
// CDNs without shipping the public suffix list.
func domainOf(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	suffix := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if _, twoLevel := twoLevelSuffixes[suffix]; twoLevel && len(labels) >= 3 {
		return labels[len(labels)-3] + "." + suffix
	}
	return suffix
}
