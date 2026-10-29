// Package term renders colored terminal output.
//
// Styling is opt-in by evidence: color is used only when the destination is a
// real terminal and the environment has not asked for plain text. That keeps
// piped output, CI logs and `NO_COLOR` users byte-for-byte parseable while the
// interactive experience stays readable.
package term

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Mode selects color behaviour.
type Mode string

const (
	// ModeAuto enables color only for an interactive terminal.
	ModeAuto Mode = "auto"
	// ModeAlways forces color, even into a pipe or file.
	ModeAlways Mode = "always"
	// ModeNever disables color.
	ModeNever Mode = "never"
)

// ParseMode validates a -color value.
func ParseMode(raw string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(raw))) {
	case ModeAuto, "":
		return ModeAuto, nil
	case ModeAlways:
		return ModeAlways, nil
	case ModeNever:
		return ModeNever, nil
	}
	return ModeAuto, fmt.Errorf("invalid color mode %q (want auto, always or never)", raw)
}

// Theme applies ANSI styling. A nil Theme is valid and renders plain text, so
// callers never need to branch on nil.
type Theme struct {
	enabled bool
}

// New decides whether w should be colorized.
//
// Precedence: an explicit mode wins over the environment; otherwise NO_COLOR,
// TERM=dumb and CLICOLOR=0 all force plain output.
func New(w io.Writer, mode Mode) *Theme {
	switch mode {
	case ModeNever:
		return &Theme{}
	case ModeAlways:
		return &Theme{enabled: true}
	}

	if os.Getenv("NO_COLOR") != "" || os.Getenv("CLICOLOR") == "0" {
		return &Theme{}
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return &Theme{}
	}

	file, ok := w.(*os.File)
	if !ok || !IsTerminal(w) {
		return &Theme{}
	}
	if !enableVirtualTerminal(file) {
		// A Windows console that refuses VT processing would print raw escape
		// codes, which is worse than no color at all.
		return &Theme{}
	}
	return &Theme{enabled: true}
}

// Enabled reports whether styling is active. Safe on a nil Theme.
func (t *Theme) Enabled() bool { return t != nil && t.enabled }

func (t *Theme) paint(code, text string) string {
	if !t.Enabled() || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// Bold renders text in bold.
func (t *Theme) Bold(text string) string { return t.paint("1", text) }

// Dim renders text in a muted grey.
func (t *Theme) Dim(text string) string { return t.paint(palette["muted"], text) }

// Accent renders text in the product accent color.
func (t *Theme) Accent(text string) string { return t.paint("1;38;5;45", text) }

// Color paints text with a named palette entry; unknown names render plain.
func (t *Theme) Color(name, text string) string {
	code, ok := palette[name]
	if !ok {
		return text
	}
	return t.paint(code, text)
}

// BandColor maps a confidence band to a palette entry.
func BandColor(band string) string {
	switch band {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium-high":
		return "medium-high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// KindColor maps a finding kind to a palette entry.
func KindColor(kind string) string {
	switch kind {
	case "SECRET":
		return "secret"
	case "REFLECT":
		return "reflect"
	case "REDIRECT":
		return "redirect"
	case "PATH":
		return "path"
	case "CORS":
		return "warning"
	case "CRLF":
		return "critical"
	case "SSRF":
		return "critical"
	case "PROTOTYPE":
		return "high"
	default:
		return "muted"
	}
}

// palette holds 256-color codes, which Windows Terminal, VS Code, iTerm and
// every modern Linux terminal support.
var palette = map[string]string{
	"critical":    "1;38;5;203", // bright red, bold
	"high":        "38;5;215",   // orange
	"medium-high": "38;5;221",   // amber
	"medium":      "38;5;111",   // blue
	"low":         "38;5;245",   // grey
	"secret":      "1;38;5;213", // magenta
	"reflect":     "38;5;81",    // cyan
	"redirect":    "38;5;220",   // yellow
	"path":        "38;5;111",   // blue
	"muted":       "38;5;244",   // grey
	"success":     "38;5;114",   // green
	"warning":     "38;5;214",   // orange
	"url":         "38;5;250",   // near-white
}

// IsTerminal reports whether w is an interactive terminal. Pipes, files and
// buffers are not, which is what keeps animation and escape codes out of
// redirected output.
func IsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
