package js

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}

func TestScriptURLs(t *testing.T) {
	base := mustURL(t, "https://app.example.com/home")
	page := []byte(`
		<html><head>
		<script src="/static/app.js"></script>
		<script src='https://cdn.jsdelivr.net/npm/lib.js'></script>
		<script src="/static/app.js"></script>
		<script>var inline = 1;</script>
		</head></html>`)

	got := ScriptURLs(page, base)
	want := []string{
		"https://app.example.com/static/app.js",
		"https://cdn.jsdelivr.net/npm/lib.js",
	}
	if len(got) != len(want) {
		t.Fatalf("ScriptURLs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ScriptURLs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIsThirdParty(t *testing.T) {
	base := mustURL(t, "https://app.example.com/home")
	cases := []struct {
		asset string
		want  bool
	}{
		{"https://app.example.com/a.js", false},
		{"https://static.example.com/a.js", false}, // same registrable domain
		{"https://cdn.jsdelivr.net/a.js", true},
		{"https://www.googletagmanager.com/gtm.js", true},
		{"https://other.test/a.js", true},
	}
	for _, c := range cases {
		if got := IsThirdParty(mustURL(t, c.asset), base); got != c.want {
			t.Errorf("IsThirdParty(%q) = %v, want %v", c.asset, got, c.want)
		}
	}
}

func TestIsThirdPartyHandlesTwoLevelSuffixes(t *testing.T) {
	base := mustURL(t, "https://shop.example.co.uk/")
	if IsThirdParty(mustURL(t, "https://static.example.co.uk/a.js"), base) {
		t.Error("a subdomain of the same registrable domain must be first-party")
	}
	if !IsThirdParty(mustURL(t, "https://cdn.other.co.uk/a.js"), base) {
		t.Error("a different registrable domain must be third-party")
	}
}

func TestExtractEndpoints(t *testing.T) {
	base := mustURL(t, "https://app.example.com/")
	source := []byte(`
		fetch("/api/v1/users?page=1");
		var logo = "/static/logo.svg";
		var bundle = "/static/app.js";
		var full = "https://app.example.com/api/v2/items";
		var tpl = "/api/{{version}}/x";
		var remote = "https://other.test/api/x";
		fetch("/api/v1/users?page=1");
	`)

	got := ExtractEndpoints(source, base)
	want := map[string]bool{
		"https://app.example.com/api/v1/users?page=1": true,
		"https://app.example.com/api/v2/items":        true,
	}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %v, want %v", got, want)
	}
	for _, endpoint := range got {
		if !want[endpoint] {
			t.Errorf("unexpected endpoint %q", endpoint)
		}
	}
}

func TestExtractEndpointsDeduplicates(t *testing.T) {
	base := mustURL(t, "https://app.example.com/")
	source := []byte(`a("/api/x"); b("/api/x"); c("/api/x?y=1");`)
	if got := ExtractEndpoints(source, base); len(got) != 2 {
		t.Fatalf("endpoints = %v, want 2 distinct values", got)
	}
}

func TestDomainOf(t *testing.T) {
	cases := map[string]string{
		"app.example.com":     "example.com",
		"example.com":         "example.com",
		"a.b.example.co.uk":   "example.co.uk",
		"localhost":           "localhost",
		"static.example.com.": "example.com",
	}
	for host, want := range cases {
		if got := domainOf(host); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", host, got, want)
		}
	}
}
