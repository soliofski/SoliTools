package crawl

import (
	"net/url"
	"testing"
)

func parseBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	base, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("base %q: %v", raw, err)
	}
	return base
}

func TestLinksKeepsOnlySafeSameOriginPages(t *testing.T) {
	document := []byte(`<html><body>
		<a href="/about">about</a>
		<a href="/about#team">about, anchored</a>
		<a href="/about/">about, trailing slash</a>
		<a href="relative/page">relative</a>
		<a href='single/quoted'>single quotes</a>
		<a href=unquoted.html>unquoted</a>
		<a href="/search?q=x&amp;page=2">query</a>
		<a href="/dir/?x=1">directory with query</a>
		<a href="https://target.test/secure">scheme change</a>
		<a href="http://target.test:8080/admin">port change</a>
		<a href="//other.test/x">protocol relative, other host</a>
		<a href="http://other.test/x">other host</a>
		<a href="mailto:security@target.test">mail</a>
		<a href="javascript:void(0)">script</a>
		<a href="tel:+123456">phone</a>
		<a href="/static/app.js">script asset</a>
		<a href="/img/logo.PNG">image asset</a>
		<a href="/docs/manual.pdf">document</a>
		<a href="/logout">logout</a>
		<a href="/account/delete-account">destructive</a>
		<a href="#top">anchor</a>
		<a href="">empty</a>
		<a name="no-href">no href</a>
	</body></html>`)

	base := parseBase(t, "http://target.test/")
	got := Links(document, base, 0)
	want := []string{
		"http://target.test/about",
		"http://target.test/relative/page",
		"http://target.test/single/quoted",
		"http://target.test/unquoted.html",
		"http://target.test/search?q=x&page=2",
		"http://target.test/dir?x=1",
	}
	if len(got) != len(want) {
		t.Fatalf("links = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLinksCapsResults(t *testing.T) {
	document := []byte(`<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>
		<a href="/d">d</a><a href="/e">e</a>`)
	got := Links(document, parseBase(t, "https://target.test/"), 3)
	if len(got) != 3 {
		t.Fatalf("links = %d, want the cap of 3: %#v", len(got), got)
	}
}

func TestLinksTreatsDefaultPortsAsSameOrigin(t *testing.T) {
	base := parseBase(t, "https://target.test/")
	got := Links([]byte(`<a href="https://target.test:443/page">page</a>`), base, 0)
	if len(got) != 1 {
		t.Fatalf("links = %#v, want the explicit default port to match", got)
	}
}

func TestLinksSkipsSeedItself(t *testing.T) {
	base := parseBase(t, "https://target.test/app?tab=1")
	document := []byte(`<a href="/app?tab=1#section">self</a><a href="/other">other</a>`)
	got := Links(document, base, 0)
	if len(got) != 1 || got[0] != "https://target.test/other" {
		t.Fatalf("links = %#v, want only the other page", got)
	}
}

func TestLinksRejectsDestructiveAndAssetPathsCaseInsensitively(t *testing.T) {
	document := []byte(`<a href="/SignOut">out</a><a href="/x/LOGOUT">out</a>
		<a href="/video.MP4">video</a><a href="/font.woff2">font</a>`)
	if got := Links(document, parseBase(t, "https://target.test/"), 0); len(got) != 0 {
		t.Fatalf("links = %#v, want every candidate excluded", got)
	}
}

func TestLinksIgnoresNonAnchorTags(t *testing.T) {
	document := []byte(`<link href="/style.css"><a href="/page">page</a><area href="/map">`)
	got := Links(document, parseBase(t, "https://target.test/"), 0)
	if len(got) != 1 || got[0] != "https://target.test/page" {
		t.Fatalf("links = %#v, want only the anchor", got)
	}
}
