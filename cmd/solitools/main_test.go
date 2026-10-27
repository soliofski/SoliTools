package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, version) {
		t.Fatalf("stdout = %q, want version %q", stdout, version)
	}
}

func TestTUIRefusesWithoutTerminal(t *testing.T) {
	code, _, stderr := runCLI(t, "tui")
	if code != 2 {
		t.Fatalf("exit = %d, want 2 without a terminal", code)
	}
	if !strings.Contains(stderr, "interactive terminal") {
		t.Fatalf("stderr = %q, want an explanatory error", stderr)
	}
}

func TestBareInvocationWithoutTerminalPrintsUsage(t *testing.T) {
	code, _, stderr := runCLI(t)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Fatalf("stderr = %q, want usage text", stderr)
	}
	if !strings.Contains(stderr, "solitools tui") {
		t.Fatalf("stderr = %q, want the tui command documented", stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"scan"},
		{"scan", "https://example.com", "extra"},
		{"scan", "-strict", "-all", "https://example.com"},
		{"scan", "-min-score", "150", "https://example.com"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("args %v: exit = %d, want 2", args, code)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	if got := normalizeTarget("example.com"); got != "https://example.com" {
		t.Errorf("normalizeTarget = %q", got)
	}
	if got := normalizeTarget("http://example.com"); got != "http://example.com" {
		t.Errorf("normalizeTarget changed an absolute URL: %q", got)
	}
}

// leakingServer serves one page containing a credential split across literals
// in this file, so the repository itself stays free of a matching string.
func leakingServer(t *testing.T) *httptest.Server {
	t.Helper()
	token := "ghp_Ab3xZ9qLmN2pR7sT4vW8" + "Kf6Yc1Dh5Ju0Ge3N"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><script>var t = %q;</script></body></html>", token)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestScanReportsFindings(t *testing.T) {
	server := leakingServer(t)
	code, stdout, stderr := runCLI(t, "scan", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "[SECRET]") {
		t.Fatalf("stdout missing a secret finding:\n%s", stdout)
	}
	if !strings.Contains(stdout, "***") {
		t.Fatalf("secret value was not masked:\n%s", stdout)
	}
	if strings.Contains(stdout, "Kf6Yc1Dh5Ju0Ge3N") {
		t.Fatalf("stdout leaks the secret:\n%s", stdout)
	}
}

func TestScanJSON(t *testing.T) {
	server := leakingServer(t)
	code, stdout, stderr := runCLI(t, "scan", "-json", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}

	var payload struct {
		Version   string  `json:"version"`
		Target    string  `json:"target"`
		Threshold float64 `json:"threshold"`
		Findings  []struct {
			Kind       string `json:"kind"`
			RuleID     string `json:"rule_id"`
			Value      string `json:"value"`
			Confidence struct {
				Value float64 `json:"value"`
				Band  string  `json:"band"`
			} `json:"confidence"`
		} `json:"findings"`
		Stats struct {
			Requests int `json:"requests"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if payload.Version != version {
		t.Errorf("version = %q", payload.Version)
	}
	if payload.Threshold != 60 {
		t.Errorf("threshold = %v, want the default 60", payload.Threshold)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(payload.Findings))
	}
	if payload.Findings[0].Kind != "SECRET" || payload.Findings[0].RuleID != "secret.github-token" {
		t.Errorf("unexpected finding %+v", payload.Findings[0])
	}
	if !strings.Contains(payload.Findings[0].Value, "*") {
		t.Errorf("JSON value is not masked: %q", payload.Findings[0].Value)
	}
	if payload.Stats.Requests == 0 {
		t.Errorf("stats.requests = 0, want the real count")
	}
}

func TestScanCleanServerExitsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><p>nothing to see</p></body></html>")
	}))
	defer server.Close()

	code, stdout, _ := runCLI(t, "scan", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "Findings: 0") {
		t.Fatalf("stdout = %s", stdout)
	}
}

func TestColorAlwaysEmitsEscapes(t *testing.T) {
	server := leakingServer(t)
	code, stdout, _ := runCLI(t, "scan", "-color", "always", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stdout, "\x1b[") {
		t.Fatal("-color=always produced no ANSI styling")
	}
	if !strings.Contains(stdout, "┌") {
		t.Fatal("summary box was not drawn")
	}
}

func TestJSONIsNeverStyled(t *testing.T) {
	server := leakingServer(t)
	code, stdout, _ := runCLI(t, "scan", "-json", "-color", "always", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatal("JSON output contains ANSI escapes")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
}

func TestColorModeRejectsGarbage(t *testing.T) {
	if code, _, _ := runCLI(t, "scan", "-color", "rainbow", "https://example.com"); code != 2 {
		t.Fatalf("exit = %d, want 2 for an invalid color mode", code)
	}
}

func TestQuietPrintsASingleLine(t *testing.T) {
	server := leakingServer(t)
	code, stdout, _ := runCLI(t, "scan", "-quiet", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	out := strings.TrimSpace(stdout)
	if strings.Contains(out, "\n") {
		t.Fatalf("quiet printed more than one line: %q", out)
	}
	if !strings.Contains(out, "1 finding") || !strings.Contains(out, "request") {
		t.Fatalf("quiet summary = %q", out)
	}
	if strings.Contains(out, "[SECRET]") || strings.Contains(out, "SoliTools") {
		t.Fatalf("quiet printed detail or banner: %q", out)
	}
}

func TestJSONAndSARIFAreExclusive(t *testing.T) {
	code, _, stderr := runCLI(t, "scan", "-json", "-sarif", "https://example.com")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestSARIFOutput(t *testing.T) {
	server := leakingServer(t)
	code, stdout, stderr := runCLI(t, "scan", "-sarif", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}

	var payload struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if payload.Schema == "" || payload.Version != "2.1.0" {
		t.Fatalf("schema/version = %q/%q", payload.Schema, payload.Version)
	}
	if len(payload.Runs) != 1 || payload.Runs[0].Tool.Driver.Name != "SoliTools" {
		t.Fatalf("tool driver = %+v", payload.Runs)
	}
	if len(payload.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1", len(payload.Runs[0].Results))
	}
	if got := payload.Runs[0].Results[0]; got.RuleID != "secret.github-token" || got.Level != "error" {
		t.Fatalf("result = %+v", got)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatal("SARIF output contains ANSI escapes")
	}
	if strings.Contains(stdout, "Kf6Yc1Dh5Ju0Ge3N") {
		t.Fatal("SARIF output leaks the secret")
	}
}

func TestQuietKeepsJSONParseable(t *testing.T) {
	server := leakingServer(t)
	code, stdout, _ := runCLI(t, "scan", "-quiet", "-json", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("quiet+json is not JSON: %v\n%s", err, stdout)
	}
}

func TestNegativeWidthIsRejected(t *testing.T) {
	if code, _, _ := runCLI(t, "scan", "-width", "-5", "https://example.com"); code != 2 {
		t.Fatalf("exit = %d, want 2 for a negative width", code)
	}
}

func TestMaxPagesMustBePositive(t *testing.T) {
	if code, _, stderr := runCLI(t, "scan", "-max-pages", "0", "https://example.com"); code != 2 {
		t.Fatalf("exit = %d, want 2: %s", code, stderr)
	}
}

func TestMissingWordlistIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	code, _, stderr := runCLI(t, "scan", "-wordlist", path, "https://example.com")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "wordlist") {
		t.Fatalf("stderr = %q, want a wordlist error", stderr)
	}
}

func TestCrawlFlagFetchesLinkedPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><body><a href="/extra">extra</a></body></html>`)
			return
		}
		fmt.Fprint(w, "<html><body>extra page</body></html>")
	}))
	defer server.Close()

	decodePages := func(stdout string) int {
		t.Helper()
		var payload struct {
			Stats struct {
				Pages int `json:"pages"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("JSON: %v\n%s", err, stdout)
		}
		return payload.Stats.Pages
	}

	code, stdout, _ := runCLI(t, "scan", "-json", "-skip-path", "-rate", "500", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 without crawl:\n%s", code, stdout)
	}
	if pages := decodePages(stdout); pages != 1 {
		t.Fatalf("pages = %d, want 1 without -crawl", pages)
	}

	code, stdout, _ = runCLI(t, "scan", "-json", "-skip-path", "-crawl", "-rate", "500", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 with crawl:\n%s", code, stdout)
	}
	if pages := decodePages(stdout); pages != 2 {
		t.Fatalf("pages = %d, want seed plus the linked page", pages)
	}
}

func TestWordlistFlagIsUsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte("# custom\n\n.hidden\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.hidden" {
			w.Write([]byte("<html><body>reachable</body></html>"))
			return
		}
		if r.URL.Path == "/" {
			w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	code, stdout, _ := runCLI(t, "scan", "-json", "-wordlist", path, "-rate", "500", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 for the custom hit:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "/.hidden") {
		t.Fatalf("the custom path is missing from the report:\n%s", stdout)
	}
}

func TestFormsProbingIsOptIn(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/feedback" method="post">`+
			`<input name="message"></form></body></html>`)
	})
	mux.HandleFunc("/feedback", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", r.PostFormValue("message"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	code, stdout, _ := runCLI(t, "scan", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 without -forms:\n%s", code, stdout)
	}

	code, stdout, _ = runCLI(t, "scan", "-forms", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 with -forms:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "[REFLECT]") {
		t.Fatalf("no reflection reported for the POST form:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Method:") {
		t.Fatalf("the finding does not identify the method:\n%s", stdout)
	}
}

func TestStoredProbingIsOptIn(t *testing.T) {
	var mu sync.Mutex
	var saved string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/guestbook" method="post">`+
			`<input name="message"></form></body></html>`)
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
	defer server.Close()

	code, stdout, _ := runCLI(t, "scan", "-forms", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 without -stored:\n%s", code, stdout)
	}

	code, stdout, _ = runCLI(t, "scan", "-forms", "-stored", "-rate", "500", "-skip-path", server.URL+"/")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 with -stored:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "Stored XSS") {
		t.Fatalf("no stored finding reported:\n%s", stdout)
	}
}

func TestScanStrictHidesMediumHigh(t *testing.T) {
	// A JWT scores 65: visible by default, hidden under -strict.
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".abcdefghijklmnopqrstuvwx"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", token)
	}))
	defer server.Close()

	if code, stdout, _ := runCLI(t, "scan", "-rate", "500", "-skip-path", server.URL+"/"); code != 1 {
		t.Fatalf("default run exit = %d, want the JWT to be reported:\n%s", code, stdout)
	}
	if code, stdout, _ := runCLI(t, "scan", "-strict", "-rate", "500", "-skip-path", server.URL+"/"); code != 0 {
		t.Fatalf("strict run exit = %d, want the JWT hidden:\n%s", code, stdout)
	}
}
