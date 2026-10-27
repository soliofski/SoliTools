package redirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"solitools/internal/httpx"
	"solitools/internal/param"
)

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

func TestProbeDetectsExternalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("next")
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "//") {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.Probe(context.Background(), Target{
		URL:      server.URL + "/?next=/home",
		Name:     "next",
		Interest: param.High,
	})
	if !ok {
		t.Fatal("expected an open redirect finding")
	}
	if finding.Confidence.Value < 90 {
		t.Fatalf("confidence = %v, want critical for a confirmed external redirect", finding.Confidence.Value)
	}
	if finding.Category != "Open Redirect" {
		t.Fatalf("category = %q", finding.Category)
	}
}

func TestProbeDetectsBackslashRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("next")
		// A filter that blocks "//" and "http://" but forgets that a browser
		// treats a leading backslash as a slash.
		if strings.HasPrefix(target, `/\`) || strings.HasPrefix(target, `\\`) || strings.HasPrefix(target, `\/`) {
			// Set the header directly: http.Redirect rewrites relative paths and
			// would blur exactly what this test is about.
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("blocked"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Name: "next"})
	if !ok {
		t.Fatal("a reflected backslash redirect must be detected")
	}
	if finding.Confidence.Value < 90 {
		t.Fatalf("confidence = %v, want critical", finding.Confidence.Value)
	}
	if finding.Context != `/\example.com/solitools-redirect-check` {
		t.Fatalf("reported Location = %q, want the raw header", finding.Context)
	}
}

func TestProbeIgnoresInternalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusFound)
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Name: "next"}); ok {
		t.Fatal("a relative redirect is not an open redirect")
	}
}

func TestProbeIgnoresReflectionWithoutRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("next=" + r.URL.Query().Get("next")))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/?next=x", Name: "next"}); ok {
		t.Fatal("an echoed value is not a redirect")
	}
}

func TestProbeDetectsPostRedirect(t *testing.T) {
	var gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		target := r.PostFormValue("next")
		if strings.HasPrefix(target, "https://example.com/solitools-redirect-check") ||
			strings.HasPrefix(target, "//example.com/solitools-redirect-check") {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.Probe(context.Background(), Target{
		URL:    server.URL + "/go",
		Name:   "next",
		Method: http.MethodPost,
		Fields: url.Values{"csrf": {"t"}},
	})
	if !ok {
		t.Fatal("expected an open redirect submitted through a form")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("server saw %q, want POST", gotMethod)
	}
	if finding.Confidence.Value < 90 {
		t.Fatalf("confidence = %v, want critical", finding.Confidence.Value)
	}
}

func TestIsRedirectParam(t *testing.T) {
	cases := map[string]bool{
		"redirect":   true,
		"return_to":  true,
		"URL":        true,
		"next":       true,
		"path":       false,
		"file":       false,
		"utm_source": false,
		"":           false,
	}
	for name, want := range cases {
		if got := IsRedirectParam(name); got != want {
			t.Errorf("IsRedirectParam(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLeavesSite(t *testing.T) {
	cases := []struct {
		location string
		want     bool
	}{
		{"https://example.com/solitools-redirect-check", true},
		{"//example.com/solitools-redirect-check", true},
		// Browsers normalise a backslash to a slash in the authority position,
		// so these are all "//example.com/..." and all leave the site.
		{`/\example.com/solitools-redirect-check`, true},
		{`\\example.com/solitools-redirect-check`, true},
		{`\/example.com/solitools-redirect-check`, true},
		{`/\notexample.com/solitools-redirect-check`, false},
		// A single slash is a path, not an authority separator.
		{`/example.com/solitools-redirect-check`, false},
		// A UNC-style path is not a URL and must not be reported.
		{`\\server\share\solitools-redirect-check`, false},
		// Userinfo must never be mistaken for the host.
		{`//example.com@evil.test/solitools-redirect-check`, false},
		// Hostnames are case-insensitive.
		{"HTTPS://EXAMPLE.COM/solitools-redirect-check", true},
		{"/home", false},
		{"https://example.com/other", false},
		{"https://notexample.com/solitools-redirect-check", false},
	}
	for _, c := range cases {
		if got := leavesSite(c.location, "https://target.test/"); got != c.want {
			t.Errorf("leavesSite(%q) = %v, want %v", c.location, got, c.want)
		}
	}
}
