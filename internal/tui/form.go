// Package tui is the interactive front end: a configuration form, a live scan
// monitor and a findings explorer, rendered with ANSI escapes only.
//
// The package has no external dependencies and keeps every decision that can be
// tested — form state, list navigation, key decoding — separate from the two
// places that touch hardware: raw console mode and the byte stream itself.
package tui

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/scan"
)

// Numeric bounds. They are deliberately narrow: the TUI is for a focused scan,
// not for turning the tool into a flooder.
const (
	DefaultRate     = 10
	DefaultMaxPages = 10
	MinRate         = 1
	MaxRate         = 1000
	MinPages        = 1
	MaxPages        = 100
)

// Row indexes on the configuration form, top to bottom.
const (
	rowTarget = iota
	rowCrawl
	rowForms
	rowStored
	rowVerify
	rowSkipPath
	rowMask
	rowThresholdDefault
	rowThresholdStrict
	rowThresholdAll
	rowRate
	rowMaxPages
	rowStart
	rowExit
	rowCount
)

// Form is the configuration screen's state. It is pure data: every method is a
// small transition the UI can call and a test can assert.
type Form struct {
	Target string
	// Cursor is a byte offset into Target, kept on a rune boundary.
	Cursor    int
	Crawl     bool
	Forms     bool
	Stored    bool
	Verify    bool
	SkipPath  bool
	Mask      bool
	Threshold int // 0 default, 1 strict, 2 all
	Rate      int
	MaxPages  int
	Focus     int
}

// NewForm returns the documented defaults: crawl, forms and stored detection
// on, path scanning on, masking on, default threshold.
func NewForm() Form {
	return Form{
		Crawl:     true,
		Forms:     true,
		Stored:    true,
		SkipPath:  false,
		Mask:      true,
		Threshold: 0,
		Rate:      DefaultRate,
		MaxPages:  DefaultMaxPages,
	}
}

// MoveFocus moves the row cursor, clamped to the form.
func (f *Form) MoveFocus(delta int) {
	f.Focus += delta
	if f.Focus < 0 {
		f.Focus = 0
	}
	if f.Focus >= rowCount {
		f.Focus = rowCount - 1
	}
}

// Checkbox reports whether row is a checkbox row.
func isCheckbox(row int) bool {
	switch row {
	case rowCrawl, rowForms, rowStored, rowVerify, rowSkipPath, rowMask:
		return true
	}
	return false
}

// Toggle handles Space on the focused row.
func (f *Form) Toggle() {
	switch f.Focus {
	case rowCrawl:
		f.Crawl = !f.Crawl
	case rowForms:
		f.Forms = !f.Forms
	case rowStored:
		f.Stored = !f.Stored
	case rowVerify:
		f.Verify = !f.Verify
	case rowSkipPath:
		f.SkipPath = !f.SkipPath
	case rowMask:
		f.Mask = !f.Mask
	case rowThresholdDefault:
		f.Threshold = 0
	case rowThresholdStrict:
		f.Threshold = 1
	case rowThresholdAll:
		f.Threshold = 2
	}
}

// Adjust handles Left/Right. Numeric rows clamp; radio rows move the selection.
func (f *Form) Adjust(delta int) {
	switch f.Focus {
	case rowRate:
		f.Rate = clamp(f.Rate+delta, MinRate, MaxRate)
	case rowMaxPages:
		f.MaxPages = clamp(f.MaxPages+delta, MinPages, MaxPages)
	case rowThresholdDefault, rowThresholdStrict, rowThresholdAll:
		f.Threshold = clamp(f.Threshold+delta, 0, 2)
	}
}

// Digit appends a decimal digit to a numeric row, ignoring other rows.
func (f *Form) Digit(d int) {
	if d < 0 || d > 9 {
		return
	}
	switch f.Focus {
	case rowRate:
		f.Rate = clamp(f.Rate*10+d, MinRate, MaxRate)
	case rowMaxPages:
		f.MaxPages = clamp(f.MaxPages*10+d, MinPages, MaxPages)
	}
}

// DeleteDigit removes the last digit of a numeric row.
func (f *Form) DeleteDigit() {
	switch f.Focus {
	case rowRate:
		f.Rate /= 10
		if f.Rate < MinRate {
			f.Rate = MinRate
		}
	case rowMaxPages:
		f.MaxPages /= 10
		if f.MaxPages < MinPages {
			f.MaxPages = MinPages
		}
	}
}

// Insert appends a rune at the target cursor.
func (f *Form) Insert(r rune) {
	if f.Focus != rowTarget || r == 0 {
		return
	}
	f.Cursor = clamp(f.Cursor, 0, len(f.Target))
	head := f.Target[:f.Cursor]
	tail := f.Target[f.Cursor:]
	f.Target = head + string(r) + tail
	f.Cursor += utf8.RuneLen(r)
}

// Backspace removes the rune before the target cursor.
func (f *Form) Backspace() {
	if f.Focus != rowTarget || f.Cursor <= 0 || len(f.Target) == 0 {
		return
	}
	_, size := utf8.DecodeLastRuneInString(f.Target[:f.Cursor])
	f.Target = f.Target[:f.Cursor-size] + f.Target[f.Cursor:]
	f.Cursor -= size
}

// MoveCursor shifts the text cursor by one rune within the target field.
func (f *Form) MoveCursor(delta int) {
	if f.Focus != rowTarget {
		return
	}
	if delta < 0 {
		if f.Cursor > 0 {
			_, size := utf8.DecodeLastRuneInString(f.Target[:f.Cursor])
			f.Cursor -= size
		}
		return
	}
	if f.Cursor < len(f.Target) {
		_, size := utf8.DecodeRuneInString(f.Target[f.Cursor:])
		f.Cursor += size
	}
}

// ThresholdValue maps the radio selection to a confidence floor.
func (f Form) ThresholdValue() float64 {
	switch f.Threshold {
	case 1:
		return 75
	case 2:
		return 0
	default:
		return 60
	}
}

// ThresholdLabel is the human label for the selected radio.
func (f Form) ThresholdLabel() string {
	switch f.Threshold {
	case 1:
		return "strict"
	case 2:
		return "all"
	default:
		return "default"
	}
}

// NormalizeTarget accepts a bare host and returns an absolute http(s) URL.
func NormalizeTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("target URL is required")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("target must be an http(s) URL")
	}
	return parsed.String(), nil
}

// ScanOptions turns the form into the orchestrator's options.
func (f Form) ScanOptions(client *httpx.Client, progress func(string), notify func(finding.Finding)) scan.Options {
	target, _ := NormalizeTarget(f.Target)
	return scan.Options{
		Target:       target,
		Client:       client,
		EnableCrawl:  f.Crawl,
		MaxPages:     f.MaxPages,
		EnableForms:  f.Forms,
		EnableStored: f.Stored,
		Verify:       f.Verify,
		SkipPath:     f.SkipPath,
		MaxParams:    scan.DefaultMaxParams,
		Progress:     progress,
		Notify:       notify,
	}
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}
