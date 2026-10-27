// Package report renders scan results.
//
// Three invariants: a filtered finding is always counted and never silently
// dropped; a secret is masked at render time unless the caller explicitly asked
// to reveal it, including inside the context snippet; and machine output (JSON,
// piped text) never carries ANSI escapes.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/scan"
	"solitools/internal/secret"
	"solitools/internal/term"
)

// Options controls rendering.
type Options struct {
	// Threshold is the minimum confidence to display.
	Threshold float64
	// Mask replaces secret values with a masked form.
	Mask bool
	// Verbose adds the score derivation for every finding.
	Verbose bool
	// JSON renders a machine-readable report instead of text.
	JSON bool
	// Elapsed is the wall time of the scan.
	Elapsed time.Duration
	// Version is stamped into JSON output.
	Version string
	// Theme styles terminal output. Nil renders plain text.
	Theme *term.Theme
}

// row is one aligned detail line under a finding.
type row struct {
	label string
	value string
}

// Render writes the report and returns how many findings were displayed.
func Render(w io.Writer, result scan.Result, opts Options) (int, error) {
	shown := make([]finding.Finding, 0, len(result.Findings))
	for _, candidate := range result.Findings {
		if candidate.Confidence.Value < opts.Threshold {
			continue
		}
		if opts.Mask && candidate.Kind == finding.KindSecret {
			masked := secret.Mask(candidate.Value)
			// The context is copied from the response and therefore still holds
			// the raw credential: masking only the Value line would defeat the
			// purpose of the flag.
			if candidate.Value != "" {
				candidate.Context = strings.ReplaceAll(candidate.Context, candidate.Value, masked)
			}
			candidate.Value = masked
		}
		shown = append(shown, candidate)
	}

	if opts.JSON {
		return len(shown), writeJSON(w, result, shown, opts)
	}
	writeText(w, result, shown, opts)
	return len(shown), nil
}

func writeText(w io.Writer, result scan.Result, shown []finding.Finding, opts Options) {
	for _, candidate := range shown {
		writeFinding(w, candidate, opts)
	}
	writeSummary(w, result, shown, opts)
}

func writeFinding(w io.Writer, item finding.Finding, opts Options) {
	theme := opts.Theme

	kind := theme.Color(term.KindColor(string(item.Kind)), "["+string(item.Kind)+"]")
	score := theme.Color(term.BandColor(string(item.Confidence.Band)),
		fmt.Sprintf("[%d]", int(item.Confidence.Value+0.5)))
	fmt.Fprintf(w, "%s %s %s\n", kind, score, theme.Bold(item.Title))

	rows := make([]row, 0, 8)
	rows = append(rows, row{"URL", item.URL})
	if item.Value != "" {
		rows = append(rows, row{"Value", item.Value})
	}
	if item.Context != "" {
		rows = append(rows, row{"Context", item.Context})
	}
	for _, field := range item.Fields {
		rows = append(rows, row{field.Name, field.Value})
	}
	if opts.Verbose {
		rows = append(rows, row{"Base", fmt.Sprintf("%.1f", item.Confidence.Base)})
		if trace := signalTrace(item.Confidence.Signals); trace != "" {
			rows = append(rows, row{"Signals", trace})
		}
	}

	width := 0
	for _, line := range rows {
		if len(line.label)+1 > width {
			width = len(line.label) + 1
		}
	}

	for _, line := range rows {
		label := theme.Dim(fmt.Sprintf("%-*s", width, line.label+":"))
		value := line.value
		switch line.label {
		case "Value":
			value = theme.Color("warning", value)
		case "URL":
			value = theme.Color("url", value)
		}
		fmt.Fprintf(w, "  %s %s\n", label, value)
	}
	fmt.Fprintln(w)
}

func writeSummary(w io.Writer, result scan.Result, shown []finding.Finding, opts Options) {
	theme := opts.Theme
	hidden := len(result.Findings) - len(shown)

	if !theme.Enabled() {
		writePlainSummary(w, result, shown, hidden)
		return
	}

	rows := [][2]string{
		{"Findings", fmt.Sprintf("%d", len(shown))},
		{"Bands", plainBands(shown)},
		{"Traffic", fmt.Sprintf("%s · %s · %s · %s · %s",
			plural(result.Stats.Requests, "request", "requests"),
			plural(result.Stats.Pages, "page", "pages"),
			plural(result.Stats.Scripts, "script", "scripts"),
			plural(result.Stats.Endpoints, "endpoint", "endpoints"),
			plural(result.Stats.Parameters, "param", "params"))},
	}
	if hidden > 0 {
		rows = append(rows, [2]string{"Hidden", fmt.Sprintf("%d below threshold (use --all)", hidden)})
	}
	if result.Stats.Gated > 0 {
		rows = append(rows, [2]string{"Filtered", fmt.Sprintf("%d at detection (%s)", result.Stats.Gated, reasonSummary(result.Stats.ByReason))})
	}
	if len(result.Warnings) > 0 {
		rows = append(rows, [2]string{"Warnings", fmt.Sprintf("%d", len(result.Warnings))})
	}
	writeBox(w, theme, "SoliTools", rows)

	for _, warning := range result.Warnings {
		fmt.Fprintf(w, "%s %s\n", theme.Color("warning", "!"), warning)
	}
}

func writePlainSummary(w io.Writer, result scan.Result, shown []finding.Finding, hidden int) {
	fmt.Fprintf(w, "Requests: %d  Pages: %d  Scripts: %d  Endpoints: %d  Parameters: %d\n",
		result.Stats.Requests, result.Stats.Pages, result.Stats.Scripts,
		result.Stats.Endpoints, result.Stats.Parameters)
	fmt.Fprintf(w, "Findings: %d", len(shown))
	if bands := plainBands(shown); bands != "" {
		fmt.Fprintf(w, " (%s)", bands)
	}
	fmt.Fprintln(w)
	if hidden > 0 {
		fmt.Fprintf(w, "Below threshold: %d (use --all to display)\n", hidden)
	}
	if result.Stats.Gated > 0 {
		fmt.Fprintf(w, "Filtered at detection: %d (%s)\n", result.Stats.Gated, reasonSummary(result.Stats.ByReason))
	}
	if len(result.Warnings) > 0 {
		fmt.Fprintf(w, "Warnings: %d\n", len(result.Warnings))
		for _, warning := range result.Warnings {
			fmt.Fprintf(w, "  %s\n", warning)
		}
	}
}

// writeBox draws a rounded panel sized to its widest row.
func writeBox(w io.Writer, theme *term.Theme, title string, rows [][2]string) {
	const labelWidth = 10
	const maxWidth = 78

	width := len(title) + 8
	for _, line := range rows {
		if candidate := labelWidth + runeLen(line[1]) + 4; candidate > width {
			width = candidate
		}
	}
	if width > maxWidth {
		width = maxWidth
	}
	if width < 44 {
		width = 44
	}

	dashes := width - len(title) - 5
	if dashes < 1 {
		dashes = 1
	}
	fmt.Fprintf(w, "┌─ %s %s┐\n", theme.Accent(title), strings.Repeat("─", dashes))

	for _, line := range rows {
		value := line[1]
		room := width - labelWidth - 4
		if runeLen(value) > room {
			value = truncate(value, room)
		}
		padding := width - labelWidth - runeLen(value) - 4
		fmt.Fprintf(w, "│ %s%s%s │\n", theme.Dim(fmt.Sprintf("%-*s", labelWidth, line[0])), value, strings.Repeat(" ", padding))
	}
	fmt.Fprintf(w, "└%s┘\n", strings.Repeat("─", width-2))
}

// truncate shortens s to limit runes, keeping the result readable.
func truncate(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit || limit <= 1 {
		return s
	}
	return string(runes[:limit-1]) + "…"
}

// runeLen returns the display width of s in runes, which is what the box
// geometry needs: multi-byte characters such as "·" occupy one column.
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// plural renders "1 page" and "2 pages".
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// plainBands summarizes the displayed findings per band, highest first.
func plainBands(shown []finding.Finding) string {
	counts := make(map[string]int, 3)
	for _, candidate := range shown {
		counts[string(candidate.Confidence.Band)]++
	}
	order := []string{"critical", "high", "medium-high", "medium", "low"}
	parts := make([]string, 0, len(counts))
	for _, band := range order {
		if counts[band] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[band], band))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func reasonSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func signalTrace(signals []confidence.Signal) string {
	parts := make([]string, 0, len(signals))
	for _, signal := range signals {
		parts = append(parts, fmt.Sprintf("%s %+.1f (%s)", signal.Name, signal.Delta, signal.Reason))
	}
	return strings.Join(parts, "; ")
}

func writeJSON(w io.Writer, result scan.Result, shown []finding.Finding, opts Options) error {
	payload := struct {
		Version   string            `json:"version"`
		Target    string            `json:"target"`
		Elapsed   string            `json:"elapsed"`
		Threshold float64           `json:"threshold"`
		Findings  []finding.Finding `json:"findings"`
		Stats     scan.Stats        `json:"stats"`
		Warnings  []string          `json:"warnings,omitempty"`
	}{
		Version:   opts.Version,
		Target:    result.Target,
		Elapsed:   opts.Elapsed.Round(time.Millisecond).String(),
		Threshold: opts.Threshold,
		Findings:  shown,
		Stats:     result.Stats,
		Warnings:  result.Warnings,
	}
	if payload.Findings == nil {
		payload.Findings = []finding.Finding{}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// URLs are full of '&'; HTML escaping would turn every query separator into
	// \u0026 and make the report unreadable.
	encoder.SetEscapeHTML(false)
	return encoder.Encode(payload)
}
