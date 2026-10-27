package tui

import (
	"os"
	"strings"
	"testing"
	"time"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/scan"
	"solitools/internal/term"
)

// renderToFile captures one frame. A temp file is not a console, so width and
// height fall back to COLUMNS/LINES; that is exactly the code path a redirected
// terminal would take.
func renderToFile(t *testing.T, instance *app) string {
	t.Helper()
	t.Setenv("COLUMNS", "100")
	t.Setenv("LINES", "30")

	file, err := os.CreateTemp(t.TempDir(), "frame-*.txt")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	instance.cfg.Out = file
	instance.cfg.Theme = term.New(file, term.ModeNever)

	instance.render()
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	content, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return string(content)
}

func TestRenderFormShowsEveryControl(t *testing.T) {
	instance := &app{
		cfg:   Config{Version: "test"},
		form:  NewForm(),
		bands: map[string]int{},
	}
	instance.form.Target = "https://target.test/"
	// Move focus off the URL row so the render shows the field without the
	// insertion cursor.
	instance.form.Focus = rowCrawl

	frame := renderToFile(t, instance)
	for _, want := range []string{
		"SoliTools test",
		"Target URL: https://target.test/",
		"Crawl same-origin pages",
		"Probe POST form parameters",
		"Detect stored/blind reflection",
		"Skip sensitive path scan",
		"Mask secrets in output",
		"(•) Default (>= 60)",
		"Rate limit (req/s): 10",
		"Max pages (crawl): 10",
		"Start Scan",
		"Exit",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame is missing %q:\n%s", want, frame)
		}
	}
}

func TestRenderScanningShowsMetrics(t *testing.T) {
	instance := &app{
		cfg:          Config{Version: "test"},
		form:         NewForm(),
		screen:       screenScanning,
		stage:        "probing parameters",
		bands:        map[string]int{"critical": 1, "high": 2, "medium-high": 3},
		started:      time.Now(),
		lastRequests: 42,
		rate:         12.5,
		spinner:      1,
	}
	frame := renderToFile(t, instance)
	for _, want := range []string{
		"scanning",
		"probing parameters",
		"Requests: 42",
		"Rate: 12.5 req/s",
		"critical 1",
		"high 2",
		"medium-high 3",
		"ctrl+c cancels",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame is missing %q:\n%s", want, frame)
		}
	}
}

func TestRenderResultsShowsListAndDetail(t *testing.T) {
	secretValue := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	result := scan.Result{Findings: []finding.Finding{
		{
			Kind:        finding.KindSecret,
			Category:    "GitHub",
			RuleID:      "secret.github-token",
			Title:       "GitHub Token",
			URL:         "https://target.test/app.js",
			Value:       secretValue,
			Context:     "var t = \"" + secretValue + "\";",
			Fingerprint: "abc",
			Confidence: confidence.Score{
				Base:  90,
				Value: 95,
				Band:  confidence.BandOf(95),
				Signals: []confidence.Signal{
					{Name: "entropy", Delta: 5, Reason: "high entropy payload"},
				},
			},
		},
	}}
	instance := &app{
		cfg:    Config{Version: "test"},
		form:   NewForm(),
		screen: screenResults,
		result: result,
		view:   NewResultView(result, 60, true),
	}
	instance.view.Result = result

	frame := renderToFile(t, instance)
	for _, want := range []string{
		"findings 1/1",
		"[CRITICAL]",
		"[SECRET]",
		"GitHub Token",
		"URL: https://target.test/app.js",
		"Rule: secret.github-token",
		"Score: 95.0 (critical)",
		"+5.0 entropy",
		"MASKED",
		"q quit",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("frame is missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, secretValue) {
		t.Fatal("the results frame leaked the raw secret while masked")
	}

	instance.view.ToggleMask(instance.view.Findings[0])
	frame = renderToFile(t, instance)
	if strings.Contains(frame, secretValue) == false {
		t.Fatal("revealing the secret must show the raw value")
	}
	if !strings.Contains(frame, "REVEALED") {
		t.Fatalf("frame is missing the reveal badge:\n%s", frame)
	}
}

func TestFitIgnoresAnsiSequences(t *testing.T) {
	colored := "\x1b[38;5;203m[CRITICAL]\x1b[0m title"
	if got := visibleLen(colored); got != len("[CRITICAL] title") {
		t.Fatalf("visibleLen = %d, want %d", got, len("[CRITICAL] title"))
	}
	if got := fit(colored, 100); got != colored {
		t.Fatal("a string that fits must be returned unchanged")
	}
	truncated := fit(colored, 10)
	if get := visibleLen(truncated); get != 10 {
		t.Fatalf("truncated width = %d, want 10", get)
	}
	if !strings.HasSuffix(truncated, "\x1b[0m") {
		t.Fatalf("truncated output lost the reset: %q", truncated)
	}
}
