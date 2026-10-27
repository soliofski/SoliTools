package redirect

import (
	"context"
	"net/http"
	"net/http/httptest"
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
