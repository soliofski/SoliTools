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
	// SARIF renders a SARIF 2.1.0 log for code-scanning integrations.
	SARIF bool
	// Elapsed is the wall time of the scan.
	Elapsed time.Duration
	// Version is stamped into JSON output.
	Version string
	// Theme styles terminal output. Nil renders plain text.
	Theme *term.Theme
	// Width caps the rendered line length. Zero means "detect for a terminal";
	// a non-terminal writer is left unwrapped so redirected text stays intact.
	Width int
	// Quiet prints a single summary line and nothing else.
	Quiet bool
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
	if opts.SARIF {
		return len(shown), writeSARIF(w, result, shown, opts)
	}
	if opts.Quiet {
		writeQuiet(w, result, shown)
		return len(shown), nil
	}

	width := opts.Width
	if width <= 0 && term.IsTerminal(w) {
		width = term.Width(w)
	}
	writeText(w, result, shown, opts, width)
	return len(shown), nil
}

// writeQuiet prints the CI summary: counts, bands and warnings, one line.
func writeQuiet(w io.Writer, result scan.Result, shown []finding.Finding) {
	parts := []string{
		plural(len(shown), "finding", "findings"),
		plural(result.Stats.Requests, "request", "requests"),
	}
	if bands := plainBands(shown); len(shown) > 0 {
		parts = append(parts, bands)
	}
	if hidden := len(result.Findings) - len(shown); hidden > 0 {
		parts = append(parts, fmt.Sprintf("%d hidden", hidden))
	}
	if len(result.Warnings) > 0 {
		parts = append(parts, plural(len(result.Warnings), "warning", "warnings"))
	}
	if badge := wafBadge(result); badge != "" {
		parts = append(parts, "WAF "+badge)
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
}

func writeText(w io.Writer, result scan.Result, shown []finding.Finding, opts Options, width int) {
	for _, candidate := range shown {
		writeFinding(w, candidate, opts, width)
	}
	writeSummary(w, result, shown, opts, width)
}

func writeFinding(w io.Writer, item finding.Finding, opts Options, width int) {
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

	labelCol := 0
	for _, line := range rows {
		if len(line.label)+1 > labelCol {
			labelCol = len(line.label) + 1
		}
	}

	// Zero means "no wrapping": pipes and files keep one line per field.
	valueWidth := 0
	if width > 0 {
		valueWidth = width - 2 - labelCol - 1
		if valueWidth < 24 {
			valueWidth = 24
		}
	}
	indent := strings.Repeat(" ", 2+labelCol+1)

	for _, line := range rows {
		label := theme.Dim(fmt.Sprintf("%-*s", labelCol, line.label+":"))
		lineWidth := valueWidth
		if line.label == "URL" {
			// A URL must stay on one line: splitting it makes the one thing a
			// reader wants to copy unusable.
			lineWidth = 0
		}
		parts := wrapText(line.value, lineWidth)
		for i, part := range parts {
			switch line.label {
			case "Value":
				part = theme.Color("warning", part)
			case "URL":
				part = theme.Color("url", part)
			}
			if i == 0 {
				fmt.Fprintf(w, "  %s %s\n", label, part)
				continue
			}
			fmt.Fprintf(w, "%s%s\n", indent, part)
		}
	}
	fmt.Fprintln(w)
}

func writeSummary(w io.Writer, result scan.Result, shown []finding.Finding, opts Options, width int) {
	theme := opts.Theme
	hidden := len(result.Findings) - len(shown)

	if !theme.Enabled() {
		writePlainSummary(w, result, shown, hidden, width)
		return
	}

	rows := [][2]string{
		{"Findings", fmt.Sprintf("%d", len(shown))},
		{"Bands", plainBands(shown)},
		{"Traffic", trafficSummary(result.Stats)},
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
	if badge := wafBadge(result); badge != "" {
		rows = append(rows, [2]string{"WAF", badge})
	}
	writeBox(w, theme, "SoliTools", rows, width)

	for _, warning := range result.Warnings {
		fmt.Fprintf(w, "%s %s\n", theme.Color("warning", "!"), warning)
	}
}

func writePlainSummary(w io.Writer, result scan.Result, shown []finding.Finding, hidden int, width int) {
	requests := fmt.Sprintf("Requests: %d  Pages: %d  Scripts: %d  Endpoints: %d  Parameters: %d",
		result.Stats.Requests, result.Stats.Pages, result.Stats.Scripts,
		result.Stats.Endpoints, result.Stats.Parameters)
	if result.Stats.Forms > 0 {
		requests += fmt.Sprintf("  Forms: %d", result.Stats.Forms)
	}
	lines := []string{requests}

	summary := fmt.Sprintf("Findings: %d", len(shown))
	if bands := plainBands(shown); bands != "" {
		summary += " (" + bands + ")"
	}
	lines = append(lines, summary)

	if hidden > 0 {
		lines = append(lines, fmt.Sprintf("Below threshold: %d (use --all to display)", hidden))
	}
	if result.Stats.Gated > 0 {
		lines = append(lines, fmt.Sprintf("Filtered at detection: %d (%s)", result.Stats.Gated, reasonSummary(result.Stats.ByReason)))
	}
	if len(result.Warnings) > 0 {
		lines = append(lines, fmt.Sprintf("Warnings: %d", len(result.Warnings)))
		lines = append(lines, result.Warnings...)
	}
	if badge := wafBadge(result); badge != "" {
		lines = append(lines, "WAF: "+badge)
	}

	for _, line := range lines {
		writeWrapped(w, line, width, "  ")
	}
}

// writeWrapped prints text wrapped to width, indenting continuation lines.
func writeWrapped(w io.Writer, text string, width int, indent string) {
	for i, part := range wrapText(text, width) {
		if i == 0 {
			fmt.Fprintln(w, part)
			continue
		}
		fmt.Fprintf(w, "%s%s\n", indent, part)
	}
}

// writeBox draws a rounded panel sized to its widest row, capped to the
// terminal so a narrow window never gets a border wider than itself.
func writeBox(w io.Writer, theme *term.Theme, title string, rows [][2]string, terminalWidth int) {
	const labelWidth = 10

	limit := 78
	if terminalWidth > 0 {
		limit = terminalWidth - 2
		if limit > 78 {
			limit = 78
		}
		if limit < 36 {
			limit = 36
		}
	}

	width := len(title) + 8
	for _, line := range rows {
		if candidate := labelWidth + runeLen(line[1]) + 4; candidate > width {
			width = candidate
		}
	}
	if width > limit {
		width = limit
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

// wrapText breaks text into lines of at most width runes.
//
// Words are preserved where possible; a token longer than the limit (a URL with
// a long query string, a base64 blob) is hard-split instead of overflowing.
// A width of zero disables wrapping.
func wrapText(text string, width int) []string {
	if width <= 0 || runeLen(text) <= width {
		return []string{text}
	}

	var (
		lines   []string
		current []rune
	)
	flush := func() {
		if len(current) > 0 {
			lines = append(lines, string(current))
			current = current[:0]
		}
	}

	for _, word := range strings.Fields(text) {
		runes := []rune(word)
		if len(current) > 0 && len(current)+1+len(runes) <= width {
			current = append(current, ' ')
			current = append(current, runes...)
			continue
		}
		flush()
		for len(runes) > width {
			head, rest := splitToken(runes, width)
			lines = append(lines, string(head))
			runes = rest
		}
		current = append(current, runes...)
	}
	flush()

	if len(lines) == 0 {
		return []string{text}
	}
	return lines
}

// splitToken cuts an over-long token, preferring a natural boundary such as a
// path separator so a URL breaks at a readable point instead of mid-word.
func splitToken(runes []rune, width int) ([]rune, []rune) {
	if len(runes) <= width {
		return runes, nil
	}
	for i := width; i > width/2; i-- {
		previous := runes[i-1]
		if previous == '<' {
			// Break before a tag rather than inside it.
			return runes[:i-1], runes[i-1:]
		}
		if previous == '/' && i >= 2 && runes[i-2] == '<' {
			// A closing tag: keep "</body>" together.
			return runes[:i-2], runes[i-2:]
		}
		switch previous {
		case '/', '?', '&', '=', '-', '_', '.', ',', ';', ':', '@', '>':
			return runes[:i], runes[i:]
		}
	}
	return runes[:width], runes[width:]
}

// wafBadge names the detected WAF and whether probing was actively blocked.
// Empty means "nothing to say": no provider and no interception warning.
func wafBadge(result scan.Result) string {
	intercepted := false
	for _, warning := range result.Warnings {
		if strings.HasPrefix(warning, "WAF Interception:") {
			intercepted = true
			break
		}
	}
	if result.WAF == "" && !intercepted {
		return ""
	}
	provider := result.WAF
	if provider == "" {
		return "interception detected"
	}
	if intercepted {
		return provider + " (interception detected)"
	}
	return provider
}

// trafficSummary renders the counters shared by the box and the summary.
func trafficSummary(stats scan.Stats) string {
	parts := []string{
		plural(stats.Requests, "request", "requests"),
		plural(stats.Pages, "page", "pages"),
		plural(stats.Scripts, "script", "scripts"),
		plural(stats.Endpoints, "endpoint", "endpoints"),
		plural(stats.Parameters, "param", "params"),
	}
	if stats.Forms > 0 {
		parts = append(parts, plural(stats.Forms, "form", "forms"))
	}
	return strings.Join(parts, " · ")
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
