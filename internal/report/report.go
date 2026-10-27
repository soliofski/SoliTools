// Package report renders scan results.
//
// Two invariants: a filtered finding is always counted, never silently dropped,
// and a secret is masked at render time unless the caller explicitly asked to
// reveal it. Masking happens here rather than in the detectors so the JSON and
// text outputs can never disagree.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/scan"
	"solitools/internal/secret"
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
		fmt.Fprintln(w, candidate.Header())
		fmt.Fprintf(w, "URL: %s\n", candidate.URL)
		if candidate.Value != "" {
			fmt.Fprintf(w, "Value: %s\n", candidate.Value)
		}
		if candidate.Context != "" {
			fmt.Fprintf(w, "Context: %s\n", candidate.Context)
		}
		for _, field := range candidate.Fields {
			fmt.Fprintf(w, "%s: %s\n", field.Name, field.Value)
		}
		if opts.Verbose {
			fmt.Fprintf(w, "Score: %s  base %.1f", candidate.Confidence.String(), candidate.Confidence.Base)
			if trace := signalTrace(candidate.Confidence.Signals); trace != "" {
				fmt.Fprintf(w, "  %s", trace)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	hidden := len(result.Findings) - len(shown)
	fmt.Fprintf(w, "Target: %s\n", result.Target)
	fmt.Fprintf(w, "Requests: %d  Pages: %d  Scripts: %d  Endpoints: %d  Parameters: %d\n",
		result.Stats.Requests, result.Stats.Pages, result.Stats.Scripts,
		result.Stats.Endpoints, result.Stats.Parameters)
	fmt.Fprintf(w, "Findings: %d", len(shown))
	if byBand := bandSummary(shown); byBand != "" {
		fmt.Fprintf(w, " (%s)", byBand)
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

// bandSummary counts displayed findings per band, highest first.
func bandSummary(shown []finding.Finding) string {
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
