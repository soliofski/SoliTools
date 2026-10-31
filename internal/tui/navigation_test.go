package tui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/scan"
)

func resultsApp(result scan.Result) *app {
	form := NewForm()
	return &app{
		cfg:      Config{Version: "test"},
		form:     form,
		screen:   screenResults,
		result:   result,
		bands:    map[string]int{},
		baseCtx:  context.Background(),
		view:     NewResultView(result, form.ThresholdValue(), form.Mask),
		history:  nil,
		savePath: "",
	}
}

func TestRescanKeyPushesHistoryAndRetargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>rescanned</body></html>")
	}))
	defer server.Close()

	for _, key := range []rune{'r', 'd'} {
		t.Run(string(key), func(t *testing.T) {
			findingWithURL := testFinding("reflect.rule", finding.KindReflect, 90, "soli<x3z>yq")
			findingWithURL.URL = server.URL + "/page"

			previous := scan.Result{
				Target:   "https://old.test/",
				Findings: []finding.Finding{findingWithURL},
				WAF:      "Cloudflare",
			}
			instance := resultsApp(previous)

			instance.handleResults(Event{Key: KeyRune, Rune: key})

			if len(instance.history) != 1 {
				t.Fatalf("history = %d, want 1", len(instance.history))
			}
			if instance.history[0].result.Target != previous.Target {
				t.Fatalf("history target = %q, want %q", instance.history[0].result.Target, previous.Target)
			}
			if instance.form.Target != findingWithURL.URL {
				t.Fatalf("form target = %q, want the finding URL %q", instance.form.Target, findingWithURL.URL)
			}
			if instance.screen != screenScanning {
				t.Fatalf("screen = %v, want scanning", instance.screen)
			}

			// Let the scan goroutine finish so the test does not leak it.
			if instance.cancel != nil {
				instance.cancel()
			}
			select {
			case <-instance.done:
			case <-time.After(3 * time.Second):
				t.Fatal("rescan did not finish")
			}
		})
	}
}

func TestRescanIgnoresMissingURL(t *testing.T) {
	findingWithoutURL := testFinding("reflect.rule", finding.KindReflect, 90, "x")
	findingWithoutURL.URL = ""
	instance := resultsApp(scan.Result{Findings: []finding.Finding{findingWithoutURL}})

	instance.handleResults(Event{Key: KeyRune, Rune: 'r'})

	if len(instance.history) != 0 {
		t.Fatalf("history = %d, want 0 for a finding without a URL", len(instance.history))
	}
	if instance.screen != screenResults {
		t.Fatalf("screen = %v, want to stay on the results view", instance.screen)
	}
}

func TestBackRestoresPreviousOutcome(t *testing.T) {
	previous := scan.Result{
		Target:   "https://previous.test/",
		Findings: []finding.Finding{testFinding("previous.rule", finding.KindSecret, 95, "ghp_previous")},
		WAF:      "Cloudflare",
	}
	current := scan.Result{
		Target:   "https://current.test/",
		Findings: []finding.Finding{testFinding("current.rule", finding.KindPath, 80, "/.env")},
	}
	previousErr := errors.New("previous scan error")

	instance := resultsApp(current)
	instance.runErr = nil
	instance.history = []scanOutcome{{result: previous, err: previousErr}}

	instance.handleResults(Event{Key: KeyRune, Rune: 'b'})

	if len(instance.history) != 0 {
		t.Fatalf("history = %d, want empty after pop", len(instance.history))
	}
	if instance.result.Target != previous.Target {
		t.Fatalf("target = %q, want %q", instance.result.Target, previous.Target)
	}
	if instance.runErr != previousErr {
		t.Fatalf("runErr = %v, want the restored error", instance.runErr)
	}
	if instance.waf != previous.WAF {
		t.Fatalf("waf = %q, want %q", instance.waf, previous.WAF)
	}
	if instance.screen != screenResults {
		t.Fatalf("screen = %v, want results", instance.screen)
	}
	if instance.view == nil || instance.view.Len() != 1 {
		t.Fatalf("view not rebuilt from the previous result: %+v", instance.view)
	}
	if selected, ok := instance.view.SelectedFinding(); !ok || selected.RuleID != "previous.rule" {
		t.Fatalf("selected = %+v, want the previous finding", selected)
	}
}

func TestBackWithoutHistoryReturnsToForm(t *testing.T) {
	instance := resultsApp(scan.Result{
		Findings: []finding.Finding{testFinding("a", finding.KindReflect, 90, "x")},
	})

	instance.handleResults(Event{Key: KeyRune, Rune: 'b'})

	if instance.screen != screenForm {
		t.Fatalf("screen = %v, want the form", instance.screen)
	}
}

func TestResultsFooterShowsRescanAndBack(t *testing.T) {
	instance := resultsApp(scan.Result{
		Findings: []finding.Finding{testFinding("a", finding.KindReflect, 90, "x")},
	})
	frame := renderToFile(t, instance)
	if !strings.Contains(frame, "r rescan") || !strings.Contains(frame, "b back") {
		t.Fatalf("footer is missing the navigation hints:\n%s", frame)
	}
}
