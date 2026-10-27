package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// formServer serves one page carrying a POST form whose field is reflected by
// the action handler.
func formServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/feedback" method="post">`+
			`<input name="message"><input type="hidden" name="csrf" value="abc">`+
			`</form></body></html>`)
	})
	mux.HandleFunc("/feedback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.PostFormValue("message"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func hasKind(result Result, kind finding.Kind) bool {
	for _, candidate := range result.Findings {
		if candidate.Kind == kind {
			return true
		}
	}
	return false
}

func TestRunProbesFormsOnlyWhenEnabled(t *testing.T) {
	server := formServer(t)
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	// Default: POST forms are never submitted.
	quiet, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasKind(quiet, finding.KindReflect) {
		t.Fatal("a POST form was probed without -forms")
	}
	if quiet.Stats.Forms != 0 {
		t.Fatalf("forms = %d, want 0", quiet.Stats.Forms)
	}

	// Opted in: the field is submitted and reflected.
	enabled, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true, EnableForms: true,
	})
	if err != nil {
		t.Fatalf("Run with forms: %v", err)
	}
	if !hasKind(enabled, finding.KindReflect) {
		t.Fatalf("no reflection from the POST form: %+v", enabled.Findings)
	}
	if enabled.Stats.Forms != 1 {
		t.Fatalf("forms = %d, want 1", enabled.Stats.Forms)
	}
}

func TestRunIgnoresCrossOriginForms(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="https://other.test/collect" method="post">`+
			`<input name="message"></form></body></html>`)
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true, EnableForms: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.Forms != 0 {
		t.Fatalf("forms = %d, want 0 for a cross-origin action", result.Stats.Forms)
	}
	if result.Stats.Requests != 1 {
		t.Fatalf("requests = %d, want only the page fetch", result.Stats.Requests)
	}
}

func TestSameOrigin(t *testing.T) {
	base, err := url.Parse("https://target.test/a")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://target.test/b":      true,
		"http://target.test/b":       true,
		"https://target.test:8443/b": false,
		"https://other.test/b":       false,
	}
	for action, want := range cases {
		if got := sameOrigin(action, base); got != want {
			t.Errorf("sameOrigin(%q) = %v, want %v", action, got, want)
		}
	}
	if sameOrigin("https://target.test/b", nil) {
		t.Error("a nil base must not match")
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

// storedServer keeps the last submitted form value and serves it back from the
// action page, which is exactly what a guestbook does.
func storedServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var saved string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>`+
			`<form action="/guestbook" method="post"><input name="message"></form>`+
			`</body></html>`)
	})
	mux.HandleFunc("/guestbook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			saved = r.PostFormValue("message")
			mu.Unlock()
			w.Write([]byte("<html><body>thanks</body></html>"))
			return
		}
		mu.Lock()
		value := saved
		mu.Unlock()
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", value)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func storedFindings(result Result) []finding.Finding {
	out := make([]finding.Finding, 0, 1)
	for _, candidate := range result.Findings {
		if candidate.RuleID == "reflect.stored" {
			out = append(out, candidate)
		}
	}
	return out
}

func TestRunDetectsStoredReflectionWhenEnabled(t *testing.T) {
	server := storedServer(t)
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	// Off by default: the same submission happens, but nothing is re-fetched.
	off, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true, EnableForms: true,
	})
	if err != nil {
		t.Fatalf("Run without stored: %v", err)
	}
	if len(storedFindings(off)) != 0 {
		t.Fatalf("stored findings without -stored: %+v", off.Findings)
	}
	if off.Stats.StoredPages != 0 {
		t.Fatalf("stored pages = %d, want 0 when the pass is off", off.Stats.StoredPages)
	}

	on, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true,
		EnableForms: true, EnableStored: true,
	})
	if err != nil {
		t.Fatalf("Run with stored: %v", err)
	}
	stored := storedFindings(on)
	if len(stored) != 1 {
		t.Fatalf("stored findings = %d, want 1: %+v", len(stored), on.Findings)
	}
	if stored[0].URL != server.URL+"/guestbook" {
		t.Fatalf("stored URL = %q, want the page that served it", stored[0].URL)
	}
	if stored[0].Confidence.Value < 75 {
		t.Fatalf("confidence = %v, want high", stored[0].Confidence.Value)
	}
	if on.Stats.StoredPages != 1 {
		t.Fatalf("stored pages = %d, want 1", on.Stats.StoredPages)
	}
}

// TestRunSkipsStoredOnContaminatedBaseline refuses to attribute a canary that
// was already in the first response to this scan.
func TestRunSkipsStoredOnContaminatedBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><p>solix1z9q</p><form action="/save" method="post">`+
			`<input name="message"></form></body></html>`)
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true,
		EnableForms: true, EnableStored: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.StoredPages != 0 {
		t.Fatalf("stored pages = %d, want 0 on a contaminated baseline", result.Stats.StoredPages)
	}
	found := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "already contained a canary") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v, want the skip reason", result.Warnings)
	}
}

func TestStoragePage(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		param  string
		method string
		want   string
	}{
		{
			// The probed parameter must not survive, or the re-fetch echoes it.
			name: "get drops the probed parameter",
			url:  "https://target.test/list?page=1&q=hello#top", param: "q", want: "https://target.test/list?page=1",
		},
		{
			name: "post keeps the action query",
			url:  "https://target.test/save?step=2", param: "message", method: http.MethodPost,
			want: "https://target.test/save?step=2",
		},
		{
			name: "plain page",
			url:  "https://target.test/", param: "q", want: "https://target.test/",
		},
	}
	for _, c := range cases {
		if got := storagePage(c.url, c.param, c.method); got != c.want {
			t.Errorf("%s: storagePage = %q, want %q", c.name, got, c.want)
		}
	}
}
