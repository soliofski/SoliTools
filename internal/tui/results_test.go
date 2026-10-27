package tui

import (
	"strings"
	"testing"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/scan"
)

func testFinding(rule string, kind finding.Kind, score float64, value string) finding.Finding {
	band := confidence.BandOf(score)
	return finding.Finding{
		Kind:        kind,
		Category:    "Test",
		RuleID:      rule,
		Title:       rule,
		URL:         "https://target.test/" + rule,
		Value:       value,
		Context:     "context " + value + " tail",
		Fingerprint: rule,
		Confidence:  confidence.Score{Base: score, Value: score, Band: band},
	}
}

func TestResultViewFiltersByThreshold(t *testing.T) {
	result := scan.Result{Findings: []finding.Finding{
		testFinding("a", finding.KindSecret, 95, "ghp_secretvalue123456"),
		testFinding("b", finding.KindReflect, 80, "soli<x3z>yq"),
		testFinding("c", finding.KindRedirect, 65, "https://example.com/x"),
		testFinding("d", finding.KindPath, 50, "/.env"),
		testFinding("e", finding.KindPath, 20, "/admin"),
	}}

	if view := NewResultView(result, 60, true); view.Len() != 3 {
		t.Fatalf("threshold 60 shows %d, want 3", view.Len())
	}
	if view := NewResultView(result, 75, true); view.Len() != 2 {
		t.Fatalf("threshold 75 shows %d, want 2", view.Len())
	}
	if view := NewResultView(result, 0, true); view.Len() != 5 {
		t.Fatalf("threshold 0 shows %d, want 5", view.Len())
	}
}

func TestResultViewNavigationClamps(t *testing.T) {
	result := scan.Result{Findings: []finding.Finding{
		testFinding("a", finding.KindSecret, 95, "x"),
		testFinding("b", finding.KindSecret, 90, "y"),
		testFinding("c", finding.KindSecret, 85, "z"),
	}}
	view := NewResultView(result, 60, true)

	view.Move(-1)
	if view.Selected != 0 {
		t.Fatalf("selected = %d, want clamped at 0", view.Selected)
	}
	view.Move(99)
	if view.Selected != 2 {
		t.Fatalf("selected = %d, want clamped at last", view.Selected)
	}
	view.MoveTo(-3)
	if view.Selected != 0 {
		t.Fatalf("selected = %d after MoveTo(-3)", view.Selected)
	}
	view.Page(1, 2)
	if view.Selected != 2 {
		t.Fatalf("selected = %d after a page down", view.Selected)
	}
}

func TestResultViewScrollWindow(t *testing.T) {
	findings := make([]finding.Finding, 0, 10)
	for i := 0; i < 10; i++ {
		findings = append(findings, testFinding(string(rune('a'+i)), finding.KindPath, 80, "x"))
	}
	view := NewResultView(scan.Result{Findings: findings}, 0, true)
	view.MoveTo(5)
	visible := view.Visible(3)
	if len(visible) != 3 {
		t.Fatalf("visible = %d, want 3", len(visible))
	}
	if view.Offset != 3 {
		t.Fatalf("offset = %d, want 3 so the selection stays visible", view.Offset)
	}
	if view.Selected != 5 || view.Findings[5].RuleID != visible[2].RuleID {
		t.Fatal("the selected finding is not in the window")
	}

	view.MoveTo(0)
	view.Visible(3)
	if view.Offset != 0 {
		t.Fatalf("offset = %d, want 0 after moving home", view.Offset)
	}
}

func TestResultViewMasking(t *testing.T) {
	raw := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	result := scan.Result{Findings: []finding.Finding{
		testFinding("secret.rule", finding.KindSecret, 95, raw),
		testFinding("reflect.rule", finding.KindReflect, 85, "soli<x3z>yq"),
	}}
	view := NewResultView(result, 60, true)

	secretFinding := view.Findings[0]
	masked := view.DisplayValue(secretFinding)
	if masked == raw || masked == "" {
		t.Fatalf("masked value = %q, want a masked form", masked)
	}
	if !strings.Contains(view.DisplayValue(secretFinding), "*") {
		t.Fatalf("masked value = %q, want masking characters", view.DisplayValue(secretFinding))
	}
	if strings.Contains(view.DisplayContext(secretFinding), raw) {
		t.Fatal("the context leaks the raw secret while masked")
	}
	if view.MaskLabel(secretFinding) != "MASKED" {
		t.Fatalf("label = %q", view.MaskLabel(secretFinding))
	}

	view.ToggleMask(secretFinding)
	if view.DisplayValue(secretFinding) != raw {
		t.Fatal("toggling must reveal the raw value")
	}
	if !strings.Contains(view.DisplayContext(secretFinding), raw) {
		t.Fatal("toggling must also reveal the context")
	}
	if view.MaskLabel(secretFinding) != "REVEALED" {
		t.Fatalf("label = %q", view.MaskLabel(secretFinding))
	}

	view.ToggleMask(secretFinding)
	if view.DisplayValue(secretFinding) == raw {
		t.Fatal("toggling twice must mask again")
	}

	// Non-secret findings are never masked.
	reflectFinding := view.Findings[1]
	if view.DisplayValue(reflectFinding) != "soli<x3z>yq" {
		t.Fatal("a non-secret value must not be masked")
	}
	if view.MaskLabel(reflectFinding) != "" {
		t.Fatal("non-secret findings carry no mask badge")
	}
}

func TestResultViewEmpty(t *testing.T) {
	view := NewResultView(scan.Result{}, 60, true)
	view.Move(1)
	if _, ok := view.SelectedFinding(); ok {
		t.Fatal("an empty view has no selection")
	}
	if visible := view.Visible(5); visible != nil {
		t.Fatalf("visible = %v, want none", visible)
	}
}
