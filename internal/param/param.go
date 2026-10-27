// Package param classifies URL parameters by how likely they are to be worth
// probing.
//
// The classification is intentionally a curated list rather than a heuristic on
// name length or entropy: a wrong "high interest" verdict costs a request and
// a false finding, while a curated list can be audited and extended.
package param

import (
	"net/url"
	"strings"
)

// Interest is how much attention a parameter deserves.
type Interest int

const (
	// Noise marks tracking parameters: never worth probing.
	Noise Interest = iota
	// Low marks parameters with no obvious sink.
	Low
	// Medium marks parameters that commonly reach a sink.
	Medium
	// High marks parameters that frequently control redirects, file access or
	// template rendering.
	High
)

// String renders the interest level for reports.
func (i Interest) String() string {
	switch i {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "noise"
	}
}

// highInterest parameters typically feed a redirect, a file path or a template.
var highInterest = map[string]struct{}{
	"redirect": {}, "redirect_uri": {}, "redirect_url": {}, "redirecturi": {},
	"url": {}, "uri": {}, "next": {}, "callback": {}, "return": {}, "return_url": {},
	"returnurl": {}, "return_to": {}, "returnto": {}, "file": {}, "filename": {},
	"filepath": {}, "path": {}, "page": {}, "data": {}, "load": {}, "continue": {},
	"dest": {}, "destination": {}, "target": {}, "goto": {}, "out": {}, "view": {},
	"folder": {}, "dir": {}, "document": {}, "download": {}, "link": {}, "ref": {},
	"reference": {}, "host": {}, "domain": {}, "site": {}, "window": {}, "open": {},
	"forward": {}, "proxy": {}, "html": {}, "val": {}, "img": {}, "image": {},
	"src": {}, "source": {}, "template": {}, "layout": {}, "include": {}, "require": {},
}

// mediumInterest parameters frequently hold identifiers, search terms or
// content that reaches a sink after validation.
var mediumInterest = map[string]struct{}{
	"id": {}, "cat": {}, "category": {}, "action": {}, "type": {}, "mode": {},
	"name": {}, "cmd": {}, "command": {}, "exec": {}, "query": {}, "search": {},
	"q": {}, "s": {}, "email": {}, "user": {}, "username": {}, "account": {},
	"login": {}, "pass": {}, "password": {}, "pwd": {}, "token": {}, "key": {},
	"api_key": {}, "apikey": {}, "secret": {}, "hash": {}, "code": {}, "msg": {},
	"message": {}, "text": {}, "content": {}, "title": {}, "body": {}, "comment": {},
	"desc": {}, "description": {}, "sort": {}, "order": {}, "filter": {}, "limit": {},
	"offset": {}, "debug": {}, "admin": {}, "config": {}, "setting": {}, "format": {},
	"output": {}, "jsonp": {}, "ajax": {}, "xml": {}, "lang": {}, "locale": {},
}

// noiseNames are exact tracking parameters.
var noiseNames = map[string]struct{}{
	"fbclid": {}, "gclid": {}, "dclid": {}, "msclkid": {}, "yclid": {}, "twclid": {},
	"gbraid": {}, "wbraid": {}, "igshid": {}, "mc_cid": {}, "mc_eid": {}, "_ga": {},
	"_gl": {}, "spm": {}, "scm": {}, "trk": {}, "trkcampaign": {}, "ref_src": {},
	"ref_url": {}, "vero_id": {}, "vero_conv": {}, "oly_anon_id": {}, "oly_enc_id": {},
	"s_kwcid": {}, "ef_id": {}, "epik": {}, "piwik_campaign": {}, "piwik_kwd": {},
}

// noisePrefixes are tracking namespaces.
var noisePrefixes = []string{"utm_", "hsa_", "pk_", "mtm_", "matomo_"}

// Classify returns the interest level of a parameter name.
func Classify(name string) Interest {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return Noise
	}
	if _, noisy := noiseNames[normalized]; noisy {
		return Noise
	}
	for _, prefix := range noisePrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return Noise
		}
	}
	if _, high := highInterest[normalized]; high {
		return High
	}
	if _, medium := mediumInterest[normalized]; medium {
		return Medium
	}
	return Low
}

// Names returns the query parameter names of a URL in document order, without
// duplicates and without tracking parameters.
func Names(u *url.URL) []string {
	if u == nil || u.RawQuery == "" {
		return nil
	}
	seen := make(map[string]struct{})
	names := make([]string, 0, 4)
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			continue
		}
		if decoded == "" {
			continue
		}
		if _, duplicate := seen[decoded]; duplicate {
			continue
		}
		if Classify(decoded) == Noise {
			continue
		}
		seen[decoded] = struct{}{}
		names = append(names, decoded)
	}
	return names
}
