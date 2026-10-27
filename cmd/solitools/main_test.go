package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
