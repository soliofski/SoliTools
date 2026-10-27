package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"solitools/internal/finding"
	"solitools/internal/httpx"
)

// testToken is assembled from two literals so this source file never looks like
// a leak while the served document still does.
const testToken = "ghp_Ab3xZ9qLmN2pR7sT4vW8" + "Kf6Yc1Dh5Ju0Ge3N"

func TestRunEndToEnd(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		next := r.URL.Query().Get("next")
		if strings.HasPrefix(next, "https://example.com/solitools-redirect-check") ||
			strings.HasPrefix(next, "//example.com/solitools-redirect-check") {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><p>%s</p>`+
			`<script src="/static/app.js"></script>`+
			`<script>var t = "%s";</script></body></html>`,
			r.URL.Query().Get("q"), testToken)
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `const token = "%s"; fetch("/api/v1/users?page=1");`, testToken)
	})

	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DB_HOST=db.internal\nDB_NAME=app\n")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	result, err := Run(context.Background(), Options{
		Target:       server.URL + "/?q=hello&next=%2Fhome",
		Client:       client,
		MaxPathWords: 5,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byKind := make(map[finding.Kind][]finding.Finding)
	for _, candidate := range result.Findings {
		byKind[candidate.Kind] = append(byKind[candidate.Kind], candidate)
	}

	secrets := byKind[finding.KindSecret]
	if len(secrets) != 1 {
		t.Fatalf("secret findings = %d, want 1 after deduplication: %+v", len(secrets), secrets)
	}
	occurrences := ""
	for _, field := range secrets[0].Fields {
		if field.Name == "Occurrences" {
			occurrences = field.Value
		}
	}
	if occurrences != "2" {
		t.Fatalf("occurrences = %q, want 2 (page and bundle)", occurrences)
	}

	if len(byKind[finding.KindReflect]) == 0 {
		t.Errorf("no reflection finding for q: %+v", result.Findings)
	}
	if len(byKind[finding.KindRedirect]) == 0 {
		t.Errorf("no open redirect finding for next")
	}
	if len(byKind[finding.KindPath]) == 0 {
		t.Errorf("no path finding for /.env")
	}
	if result.Stats.Endpoints == 0 {
		t.Errorf("no endpoints extracted from the bundle")
	}
	if result.Stats.Requests == 0 {
		t.Errorf("request counter was not incremented")
	}
}

func TestRunRejectsInvalidTarget(t *testing.T) {
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	for _, target := range []string{"", "ftp://example.com", "example.com"} {
		if _, err := Run(context.Background(), Options{Target: target, Client: client}); err == nil {
			t.Errorf("target %q should be rejected", target)
		}
	}
}

func TestRunRequiresClient(t *testing.T) {
	if _, err := Run(context.Background(), Options{Target: "https://example.com"}); err == nil {
		t.Fatal("a missing client must be an error")
	}
}
