package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/scan"
	"solitools/internal/term"
)

const sampleSecret = "ghp_ABCDEFGHIJKLMNOP"

func sampleResult() scan.Result {
	item := finding.Finding{
		Kind:        finding.KindSecret,
		Category:    "GitHub",
		RuleID:      "secret.github-token",
		Title:       "GitHub Token",
		URL:         "https://target.test/app.js",
		Value:       sampleSecret,
		Context:     `var t = "` + sampleSecret + `"; fetch("/api");`,
		Fingerprint: "a1b2c3",
		Confidence:  confidence.New(90).Build(),
	}
	item.WithField("Line", "1:9")
	return scan.Result{
		Target:   "https://target.test/",
		Findings: []finding.Finding{item},
		Stats:    scan.Stats{Requests: 3, Pages: 1, Scripts: 1, Endpoints: 1, Parameters: 0},
	}
}

func TestPlainReportHasNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	theme := term.New(&buf, term.ModeNever)

	shown, err := Render(&buf, sampleResult(), Options{
		Threshold: 60, Mask: true, Theme: theme, Version: "test", Elapsed: time.Second,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if shown != 1 {
		t.Fatalf("shown = %d, want 1", shown)
	}

	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("plain report contains escapes:\n%q", out)
	}
	if !strings.Contains(out, "[SECRET]") || !strings.Contains(out, "GitHub Token") {
		t.Fatalf("plain report missing the finding:\n%s", out)
	}
	if !strings.Contains(out, "Findings: 1") {
		t.Fatalf("plain report missing the summary:\n%s", out)
	}
}

func TestColoredReportIsStyled(t *testing.T) {
	var buf bytes.Buffer
	theme := term.New(&buf, term.ModeAlways)

	if _, err := Render(&buf, sampleResult(), Options{
		Threshold: 60, Mask: true, Theme: theme, Version: "test",
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatal("colored report has no escapes")
	}
	if !strings.Contains(out, "38;5;213") {
		t.Fatal("secret badge is not using the secret palette entry")
	}
	if !strings.Contains(out, "┌") {
		t.Fatal("summary box was not drawn")
	}
}

func TestMaskCoversContextToo(t *testing.T) {
	for _, theme := range []*term.Theme{term.New(&bytes.Buffer{}, term.ModeNever), term.New(&bytes.Buffer{}, term.ModeAlways)} {
		var buf bytes.Buffer
		if _, err := Render(&buf, sampleResult(), Options{Threshold: 60, Mask: true, Theme: theme}); err != nil {
			t.Fatalf("Render: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, sampleSecret) {
			t.Fatalf("report leaks the raw secret:\n%s", out)
		}
		if !strings.Contains(out, "ghp_") {
			t.Fatalf("masked value lost its prefix:\n%s", out)
		}
	}
}

func TestRevealShowsTheValue(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Render(&buf, sampleResult(), Options{Threshold: 60, Mask: false, Theme: nil}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), sampleSecret) {
		t.Fatal("-mask=false should reveal the value")
	}
}

func TestThresholdHidesAndCounts(t *testing.T) {
	var buf bytes.Buffer
	shown, err := Render(&buf, sampleResult(), Options{Threshold: 95, Mask: true, Theme: nil})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if shown != 0 {
		t.Fatalf("shown = %d, want 0", shown)
	}
	out := buf.String()
	if !strings.Contains(out, "Below threshold: 1") {
		t.Fatalf("hidden findings were not counted:\n%s", out)
	}
}

func TestWrappingKeepsLinesWithinWidth(t *testing.T) {
	result := sampleResult()
	result.Findings[0].Context = strings.Repeat("segment ", 40)

	var buf bytes.Buffer
	if _, err := Render(&buf, result, Options{Threshold: 60, Mask: true, Width: 70}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if runeLen(line) > 70 {
			t.Fatalf("line is %d columns, limit 70: %q", runeLen(line), line)
		}
	}
	// Continuation lines align under the value column: 2 + label column + 1.
	if !strings.Contains(buf.String(), "\n           segment") {
		t.Fatalf("wrapped context is not hanging-indented:\n%s", buf.String())
	}
}

func TestWrappingHardSplitsLongTokens(t *testing.T) {
	result := sampleResult()
	result.Findings[0].Context = strings.Repeat("A", 120)

	var buf bytes.Buffer
	if _, err := Render(&buf, result, Options{Threshold: 60, Mask: true, Width: 60}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if runeLen(line) > 60 {
			t.Fatalf("line is %d columns, limit 60: %q", runeLen(line), line)
		}
	}
}

func TestNoWrappingWithoutWidth(t *testing.T) {
	long := strings.Repeat("segment ", 40)
	result := sampleResult()
	result.Findings[0].Context = long

	var buf bytes.Buffer
	if _, err := Render(&buf, result, Options{Threshold: 60, Mask: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	// A buffer is not a terminal, so the long value stays on one line.
	if !strings.Contains(buf.String(), strings.TrimSpace(long)) {
		t.Fatalf("context was wrapped without a width:\n%s", buf.String())
	}
}

func TestQuietPrintsOneLine(t *testing.T) {
	var buf bytes.Buffer
	shown, err := Render(&buf, sampleResult(), Options{Threshold: 60, Mask: true, Quiet: true})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if shown != 1 {
		t.Fatalf("shown = %d, want 1", shown)
	}

	out := strings.TrimSpace(buf.String())
	if strings.Contains(out, "\n") {
		t.Fatalf("quiet printed more than one line: %q", out)
	}
	if !strings.Contains(out, "1 finding") || !strings.Contains(out, "3 requests") {
		t.Fatalf("quiet summary = %q", out)
	}
	if strings.Contains(out, "[SECRET]") {
		t.Fatalf("quiet printed finding detail: %q", out)
	}
}

func TestQuietCountsHiddenFindings(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Render(&buf, sampleResult(), Options{Threshold: 95, Quiet: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if out := strings.TrimSpace(buf.String()); !strings.Contains(out, "0 findings") || !strings.Contains(out, "1 hidden") {
		t.Fatalf("quiet summary = %q", out)
	}
}

func TestJSONNeverContainsEscapes(t *testing.T) {
	var buf bytes.Buffer
	theme := term.New(&buf, term.ModeAlways)

	if _, err := Render(&buf, sampleResult(), Options{
		Threshold: 60, Mask: true, JSON: true, Theme: theme, Version: "test",
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatal("JSON output must never carry ANSI escapes")
	}
	if strings.Contains(out, "\\u0026") {
		t.Fatal("JSON output should not HTML-escape URLs")
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("JSON output does not start with an object:\n%s", out)
	}
}
