package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
		{"scan", "definitely-missing-path"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("args %v: exit = %d, want 2", args, code)
		}
	}
}

// fixture creates a directory holding one credential and returns its path.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// The token is assembled at runtime on purpose: this source file must not
	// read as a leak itself, while the temporary file it writes still does.
	payload := "Ab3xZ9qLmN2pR7sT4vW8" + "Kf6Yc1Dh5Ju0Ge3N"
	content := "token = \"ghp_" + payload + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func TestScanReportsFindings(t *testing.T) {
	dir := fixture(t)
	code, stdout, _ := runCLI(t, "scan", dir)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stdout, "secret.github-token") {
		t.Fatalf("stdout missing rule id:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Findings: 1") {
		t.Fatalf("stdout missing summary:\n%s", stdout)
	}
}

func TestScanCleanDirectoryExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, stdout, _ := runCLI(t, "scan", dir)
	if code != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "Findings: 0") {
		t.Fatalf("stdout = %s", stdout)
	}
}

func TestScanJSON(t *testing.T) {
	dir := fixture(t)
	code, stdout, _ := runCLI(t, "scan", "--json", dir)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}

	var payload struct {
		Version  string `json:"version"`
		Findings []struct {
			RuleID     string `json:"rule_id"`
			Match      string `json:"match"`
			Confidence struct {
				Value float64 `json:"value"`
				Band  string  `json:"band"`
			} `json:"confidence"`
		} `json:"findings"`
		Stats struct {
			FilesScanned int `json:"files_scanned"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if payload.Version != version {
		t.Errorf("version = %q", payload.Version)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(payload.Findings))
	}
	if payload.Findings[0].RuleID != "secret.github-token" {
		t.Errorf("rule = %q", payload.Findings[0].RuleID)
	}
	if payload.Findings[0].Confidence.Value != 90 || payload.Findings[0].Confidence.Band != "very-high" {
		t.Errorf("confidence = %+v", payload.Findings[0].Confidence)
	}
	if strings.Contains(payload.Findings[0].Match, "Ab3xZ9qL") {
		t.Errorf("JSON leaks the secret: %q", payload.Findings[0].Match)
	}
	if payload.Stats.FilesScanned != 1 {
		t.Errorf("files scanned = %d", payload.Stats.FilesScanned)
	}
}

func TestScanMinConfidenceZeroUsesDefault(t *testing.T) {
	dir := t.TempDir()
	// A value that only the generic rules would match.
	content := "password = \"Zx9Qm3Lp7Rn2Ts5Vw8Yb4\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, stdout, _ := runCLI(t, "scan", "--min-confidence", "0", dir)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 without the generic rule set:\n%s", code, stdout)
	}
}
