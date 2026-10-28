package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/verify"
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

// crawlServer serves a seed page with safe, excluded and off-site links. Links
// on crawled pages must never be followed at depth one.
func crawlServer(t *testing.T) (*httptest.Server, func(string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := make(map[string]int)
	count := func(path string) {
		mu.Lock()
		hits[path]++
		mu.Unlock()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		count(r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>`+
				`<a href="/about">about</a><a href="/post">post</a>`+
				`<a href="/logout">logout</a><a href="/logo.png">logo</a>`+
				`<a href="https://other.test/x">external</a>`+
				`</body></html>`)
		case "/about":
			fmt.Fprint(w, `<html><body><a href="/deep">deep</a>`+
				`<form action="/search" method="get"><input name="q"></form></body></html>`)
		case "/post":
			if r.Method == http.MethodPost {
				r.ParseForm()
				fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.PostFormValue("message"))
				return
			}
			fmt.Fprint(w, `<html><body><form action="/post" method="post">`+
				`<input name="message"></form></body></html>`)
		case "/search":
			fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.URL.Query().Get("q"))
		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[path]
	}
}

func TestRunCrawlIsDepthOneAndFiltered(t *testing.T) {
	server, hits := crawlServer(t)
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	result, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true,
		EnableCrawl: true, EnableForms: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Stats.Pages != 3 {
		t.Fatalf("pages = %d, want seed + /about + /post", result.Stats.Pages)
	}
	if hits("/logout") != 0 || hits("/logo.png") != 0 {
		t.Fatalf("excluded links were fetched: logout=%d png=%d", hits("/logout"), hits("/logo.png"))
	}
	if hits("/deep") != 0 {
		t.Fatal("a link found on a crawled page was followed; depth must stay one")
	}
	if hits("/about") == 0 || hits("/post") == 0 {
		t.Fatal("same-origin links were not fetched")
	}

	// The GET form on /about and the POST form on /post both reflect.
	reflections := 0
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindReflect {
			reflections++
		}
	}
	if reflections != 2 {
		t.Fatalf("reflections = %d, want one from each crawled form: %+v", reflections, result.Findings)
	}
}

func TestRunCrawlOffByDefault(t *testing.T) {
	server, hits := crawlServer(t)
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.Pages != 1 {
		t.Fatalf("pages = %d, want only the seed", result.Stats.Pages)
	}
	if hits("/about") != 0 {
		t.Fatal("a crawled page was fetched without -crawl")
	}
}

// TestRunCrawlFeedsStoredObservation is the synergy case: the value is stored
// by a form on the seed and served by a crawled listing page.
func TestRunCrawlFeedsStoredObservation(t *testing.T) {
	var mu sync.Mutex
	var saved string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/list">list</a>`+
			`<form action="/guestbook" method="post"><input name="message"></form></body></html>`)
	})
	mux.HandleFunc("/guestbook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			saved = r.PostFormValue("message")
			mu.Unlock()
		}
		w.Write([]byte("<html><body>thanks</body></html>"))
	})
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		value := saved
		mu.Unlock()
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", value)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client, SkipPath: true,
		EnableCrawl: true, EnableForms: true, EnableStored: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var stored []finding.Finding
	for _, candidate := range result.Findings {
		if candidate.RuleID == "reflect.stored" {
			stored = append(stored, candidate)
		}
	}
	if len(stored) != 1 {
		t.Fatalf("stored findings = %d, want the crawled listing: %+v", len(stored), result.Findings)
	}
	if stored[0].URL != server.URL+"/list" {
		t.Fatalf("stored URL = %q, want the crawled page", stored[0].URL)
	}
}

func TestRunUsesCustomWordlist(t *testing.T) {
	var mu sync.Mutex
	hits := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html><body>home</body></html>"))
		case "/.hidden":
			w.Write([]byte("<html><body>a reachable secret file</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/", Client: client,
		Wordlist: []string{".hidden"}, WordlistTruncated: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	paths := 0
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindPath {
			paths++
		}
	}
	if paths != 1 {
		t.Fatalf("path findings = %d, want the one custom entry: %+v", paths, result.Findings)
	}

	mu.Lock()
	defaultHits := hits["/.env"]
	mu.Unlock()
	if defaultHits != 0 {
		t.Fatalf("/.env was probed %d times; the default list must not be merged in", defaultHits)
	}

	truncated := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "truncated") {
			truncated = true
		}
	}
	if !truncated {
		t.Fatalf("warnings = %v, want the wordlist cap warning", result.Warnings)
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

// secretFinding returns the single secret finding in a result.
func secretFinding(t *testing.T, result Result) finding.Finding {
	t.Helper()
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindSecret {
			return candidate
		}
	}
	t.Fatalf("no secret finding: %+v", result.Findings)
	return finding.Finding{}
}

func hasSignal(candidate finding.Finding, name string) bool {
	for _, signal := range candidate.Confidence.Signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}

func hasField(candidate finding.Finding, name, value string) bool {
	for _, field := range candidate.Fields {
		if field.Name == name && field.Value == value {
			return true
		}
	}
	return false
}

// TestRunVerifyIsOptInAndInjectable proves both halves of the contract: without
// Verify the injected verifier is never called, and with it the same finding
// gains the live-validation signal and the provider identity.
func TestRunVerifyIsOptInAndInjectable(t *testing.T) {
	var hits int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ghp_") {
			t.Errorf("authorization header = %q", got)
		}
		w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer provider.Close()

	token := "ghp_Q7mK2xR9tY4bN6vC1wZ8sL0pJ5hG3dA2fX4n"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><script>const token = %q;</script></body></html>", token)
	}))
	defer target.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	verifier := verify.New()
	verifier.BaseURLs["github"] = provider.URL

	off, err := Run(context.Background(), Options{
		Target: target.URL + "/", Client: client, SkipPath: true, Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("Run without verify: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("provider was called %d times without Verify", got)
	}
	if hasSignal(secretFinding(t, off), "live-validation") {
		t.Fatal("an unverified finding must not carry a live-validation signal")
	}

	on, err := Run(context.Background(), Options{
		Target: target.URL + "/", Client: client, SkipPath: true,
		Verify: true, Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("Run with verify: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("provider was called %d times, want exactly one", got)
	}
	verified := secretFinding(t, on)
	if verified.Confidence.Value != 100 {
		t.Fatalf("confidence = %v, want clamped 100", verified.Confidence.Value)
	}
	if !hasSignal(verified, "live-validation") {
		t.Fatalf("signals = %+v, want live-validation", verified.Confidence.Signals)
	}
	if !hasField(verified, "Status", "active (octocat)") {
		t.Fatalf("fields = %+v, want the provider identity", verified.Fields)
	}
}

func warningsText(result Result) string { return strings.Join(result.Warnings, " | ") }

func TestRunDetectsWAFAtSeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		fmt.Fprint(w, "<html><body>application</body></html>")
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.WAF != "Cloudflare" {
		t.Fatalf("WAF = %q, want Cloudflare", result.WAF)
	}
	if !strings.Contains(warningsText(result), "fronted by Cloudflare") {
		t.Fatalf("warnings = %v, want the fronting note", result.Warnings)
	}
}

// TestRunSuppressesReflectionOnWAFBlockPage is the false-positive guard: the
// block page echoes the canary, but that echo is the WAF, not the application.
func TestRunSuppressesReflectionOnWAFBlockPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" && q != "hello" {
			w.Header().Set("cf-ray", "8a1b2c3d-LHR")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "<html><body>Attention Required! | Cloudflare %s</body></html>", q)
			return
		}
		fmt.Fprint(w, "<html><body>hello</body></html>")
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/?q=hello", Client: client, SkipPath: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.Parameters == 0 {
		t.Fatal("the q parameter was not discovered")
	}
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindReflect {
			t.Fatalf("a canary echoed by a WAF block page became a finding: %+v", candidate)
		}
	}
	if !strings.Contains(warningsText(result), "WAF Interception") {
		t.Fatalf("warnings = %v, want an interception warning", result.Warnings)
	}
}

func TestRunWarnsOnConsecutiveBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "" && r.URL.Query().Get("q") != "hello" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "<html><body>hello</body></html>")
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/?q=hello", Client: client, SkipPath: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	warning := warningsText(result)
	if !strings.Contains(warning, "WAF Interception") || !strings.Contains(warning, "Generic Block") {
		t.Fatalf("warnings = %v, want an interception warning naming Generic Block", result.Warnings)
	}
	if !strings.Contains(warning, "Findings may be suppressed or incomplete") {
		t.Fatalf("warnings = %v, want the incompleteness note", result.Warnings)
	}
	if result.WAF != "Generic Block" {
		t.Fatalf("WAF = %q, want Generic Block", result.WAF)
	}
}

// TestRunDoesNotWarnBeforeThreeBlocks pins the threshold at three.
func TestRunDoesNotWarnBeforeThreeBlocks(t *testing.T) {
	var probes int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" && q != "hello" {
			if atomic.AddInt32(&probes, 1) <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}
		fmt.Fprint(w, "<html><body>hello</body></html>")
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/?q=hello", Client: client, SkipPath: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(warningsText(result), "WAF Interception") {
		t.Fatalf("two blocks must not trigger the interception warning: %v", result.Warnings)
	}
}

func TestRunMinesSourceMaps(t *testing.T) {
	token := "ghp_Q7mK2xR9tY4bN6vC1wZ8sL0pJ5hG3dA2fX4n"
	content := `export const api = "/api/internal/secrets?role=admin";` + "\n" +
		`const token = "` + token + `";`
	mapBody, err := json.Marshal(map[string]any{
		"version":        3,
		"sources":        []string{"src/api.ts"},
		"sourcesContent": []string{content},
	})
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "/* bundle */\n//# sourceMappingURL=app.js.map\n")
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mapBody)
	})
	mux.HandleFunc("/api/internal/secrets", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.URL.Query().Get("role"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Stats.SourceMaps != 1 {
		t.Fatalf("source maps = %d, want 1", result.Stats.SourceMaps)
	}
	if result.Stats.Endpoints == 0 {
		t.Fatal("no endpoint was extracted from the source map")
	}

	secretFromMap := false
	reflectFound := false
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindSecret && strings.Contains(candidate.URL, "app.js.map#src/api.ts") {
			secretFromMap = true
		}
		if candidate.Kind == finding.KindReflect && strings.Contains(candidate.URL, "/api/internal/secrets") {
			reflectFound = true
		}
	}
	if !secretFromMap {
		t.Fatalf("no secret was reported from the map source: %+v", result.Findings)
	}
	if !reflectFound {
		t.Fatalf("the map endpoint was not probed: %+v", result.Findings)
	}
}

func TestRunSkipsMalformedSourceMap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "//# sourceMappingURL=/broken.map")
	})
	mux.HandleFunc("/broken.map", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":3,"sources":[`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("a malformed map must not fail the scan: %v", err)
	}
	if result.Stats.SourceMaps != 0 {
		t.Fatalf("source maps = %d, want 0 for a malformed map", result.Stats.SourceMaps)
	}
}

func TestRunMinesJSONPageParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"callback":%q,"id":7}}`, r.URL.Query().Get("callback"))
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.Parameters < 2 {
		t.Fatalf("parameters = %d, want callback and id", result.Stats.Parameters)
	}
	found := false
	for _, candidate := range result.Findings {
		if candidate.Kind == finding.KindReflect {
			found = true
		}
	}
	if !found {
		t.Fatalf("JSON-mined parameters were not probed: %+v", result.Findings)
	}
}

// TestRunMinesJSONFromProbeResponse covers the second pass: keys discovered in
// an API answer are probed even though the parameter snapshot already happened.
func TestRunMinesJSONFromProbeResponse(t *testing.T) {
	var redirectHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				if redirect, ok := payload["redirect"].(string); ok && redirect != "" {
					atomic.AddInt32(&redirectHits, 1)
					fmt.Fprintf(w, `{"redirect":%q}`, redirect)
					return
				}
			}
		}
		if redirect := r.URL.Query().Get("redirect"); redirect != "" {
			atomic.AddInt32(&redirectHits, 1)
			fmt.Fprintf(w, `{"redirect":%q}`, redirect)
			return
		}
		if r.URL.Query().Get("q") == "hello" {
			fmt.Fprint(w, `{"q":"hello"}`)
			return
		}
		fmt.Fprintf(w, `{"redirect":"/somewhere","q":%q}`, r.URL.Query().Get("q"))
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{
		Target: server.URL + "/?q=hello", Client: client, SkipPath: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&redirectHits) == 0 {
		t.Fatalf("the JSON-discovered redirect parameter was never probed: %+v", result.Findings)
	}
}

func TestRunProbesJSONBodiesOnAPIRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><script>fetch("/api/search?q=hello");</script></body></html>`)
		case "/api/search":
			if r.Method == http.MethodPost {
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("decode JSON body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"message":%q}`, fmt.Sprint(payload["q"]))
				return
			}
			fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.URL.Query().Get("q"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	result, err := Run(context.Background(), Options{Target: server.URL + "/", Client: client, SkipPath: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.JSONProbes == 0 {
		t.Fatal("the API parameter was not probed with a JSON body")
	}

	found := false
	for _, candidate := range result.Findings {
		if candidate.RuleID == "reflect.json" && hasField(candidate, "Method", "POST (JSON)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no JSON reflection finding: %+v", result.Findings)
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
