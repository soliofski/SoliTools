package term

import (
	"bytes"
	"strings"
	"testing"
)

func TestAutoOnNonTerminalIsPlain(t *testing.T) {
	var buf bytes.Buffer
	if New(&buf, ModeAuto).Enabled() {
		t.Fatal("a buffer is not a terminal: color must stay off")
	}
}

func TestExplicitAlwaysForcesColor(t *testing.T) {
	var buf bytes.Buffer
	theme := New(&buf, ModeAlways)
	if !theme.Enabled() {
		t.Fatal("-color=always must enable styling")
	}
	out := theme.Color("critical", "x")
	if !strings.HasPrefix(out, "\x1b[") || !strings.HasSuffix(out, "\x1b[0m") {
		t.Fatalf("styled text = %q, want a reset-terminated ANSI sequence", out)
	}
}

func TestExplicitModeBeatsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if !New(&buf, ModeAlways).Enabled() {
		t.Fatal("an explicit mode must win over the environment")
	}
	if New(&buf, ModeAuto).Enabled() {
		t.Fatal("NO_COLOR must disable auto color")
	}
}

func TestNeverDisablesEvenOnAlways(t *testing.T) {
	var buf bytes.Buffer
	if New(&buf, ModeNever).Enabled() {
		t.Fatal("-color=never must disable styling")
	}
}

func TestWidthUsesColumns(t *testing.T) {
	t.Setenv("COLUMNS", "132")
	var buf bytes.Buffer
	if got := Width(&buf); got != 132 {
		t.Fatalf("Width = %d, want 132", got)
	}
}

func TestWidthRejectsUnusableColumns(t *testing.T) {
	for _, raw := range []string{"", "abc", "0", "-5", "5000"} {
		t.Setenv("COLUMNS", raw)
		var buf bytes.Buffer
		if got := Width(&buf); got != DefaultWidth {
			t.Errorf("COLUMNS=%q: Width = %d, want %d", raw, got, DefaultWidth)
		}
	}
}

func TestNilThemeRendersPlain(t *testing.T) {
	var theme *Theme
	if theme.Enabled() {
		t.Fatal("nil theme must report disabled")
	}
	if got := theme.Bold("x"); got != "x" {
		t.Fatalf("nil theme Bold = %q", got)
	}
	if got := theme.Color("critical", "x"); got != "x" {
		t.Fatalf("nil theme Color = %q", got)
	}
	if got := theme.Dim(""); got != "" {
		t.Fatalf("empty text must stay empty, got %q", got)
	}
}

func TestParseMode(t *testing.T) {
	valid := map[string]Mode{"": ModeAuto, "auto": ModeAuto, "ALWAYS": ModeAlways, "never": ModeNever}
	for raw, want := range valid {
		got, err := ParseMode(raw)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := ParseMode("rainbow"); err == nil {
		t.Error("invalid mode must be rejected")
	}
}

func TestUnknownPaletteNameRendersPlain(t *testing.T) {
	var buf bytes.Buffer
	theme := New(&buf, ModeAlways)
	if got := theme.Color("nonexistent", "x"); got != "x" {
		t.Fatalf("unknown color = %q, want plain", got)
	}
}

func TestBandColor(t *testing.T) {
	cases := map[string]string{
		"critical":    "critical",
		"high":        "high",
		"medium-high": "medium-high",
		"medium":      "medium",
		"low":         "low",
		"unknown":     "low",
	}
	for band, want := range cases {
		if got := BandColor(band); got != want {
			t.Errorf("BandColor(%q) = %q, want %q", band, got, want)
		}
	}
}

func TestKindColor(t *testing.T) {
	cases := map[string]string{
		"SECRET":   "secret",
		"REFLECT":  "reflect",
		"REDIRECT": "redirect",
		"PATH":     "path",
		"OTHER":    "muted",
	}
	for kind, want := range cases {
		if got := KindColor(kind); got != want {
			t.Errorf("KindColor(%q) = %q, want %q", kind, got, want)
		}
	}
}
