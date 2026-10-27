// Command solitools scans files for hardcoded credentials and reports them
// with an explainable confidence score.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"solitools/internal/confidence"
	"solitools/internal/finding"
	"solitools/internal/secret"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "solitools %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "solitools: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `solitools - high-accuracy secret detection

Usage:
  solitools scan [flags] <path>...
  solitools version

Flags for scan:
  -min-confidence float   drop findings below this score (0 uses default 40)
  -generic                add the low-precision generic rules
  -json                   emit a JSON report

Exit codes:
  0  no findings
  1  findings reported
  2  usage or runtime error
`)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	minConfidence := flags.Float64("min-confidence", secret.DefaultMinConfidence,
		"drop findings below this confidence (0 uses the default)")
	includeGeneric := flags.Bool("generic", false,
		"also run the low-precision generic rule set")
	asJSON := flags.Bool("json", false,
		"emit a JSON report instead of text")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	paths := flags.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "solitools scan: at least one path is required")
		return 2
	}

	scanner, err := secret.New(secret.Options{
		MinConfidence:  *minConfidence,
		IncludeGeneric: *includeGeneric,
	})
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}

	start := time.Now()
	report, err := scanner.ScanPaths(context.Background(), paths)
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}
	elapsed := time.Since(start)

	if *asJSON {
		return writeJSON(stdout, report, elapsed)
	}
	return writeText(stdout, report, elapsed)
}

func writeJSON(w io.Writer, report secret.Report, elapsed time.Duration) int {
	findings := report.Findings
	if findings == nil {
		findings = []finding.Finding{}
	}

	payload := struct {
		Version  string            `json:"version"`
		Elapsed  string            `json:"elapsed"`
		Findings []finding.Finding `json:"findings"`
		Stats    secret.Stats      `json:"stats"`
		Warnings []string          `json:"warnings,omitempty"`
	}{
		Version:  version,
		Elapsed:  elapsed.Round(time.Millisecond).String(),
		Findings: findings,
		Stats:    report.Stats,
		Warnings: report.Warnings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return 2
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}

func writeText(w io.Writer, report secret.Report, elapsed time.Duration) int {
	for _, f := range report.Findings {
		fmt.Fprintf(w, "%s:%d:%d  %s  confidence %.1f (%s)\n",
			f.File, f.Line, f.Column, f.RuleID, f.Confidence.Value, f.Confidence.Band)
		fmt.Fprintf(w, "    %s\n", f.RuleName)
		fmt.Fprintf(w, "    match %s  fp %s\n", f.Match, f.Fingerprint)
		if len(f.Confidence.Signals) > 0 {
			fmt.Fprintf(w, "    score %.1f -> %.1f  %s\n",
				f.Confidence.Base, f.Confidence.Value, trace(f.Confidence.Signals))
		}
		fmt.Fprintln(w)
	}

	high := 0
	for _, f := range report.Findings {
		if f.Confidence.Band == confidence.BandHigh || f.Confidence.Band == confidence.BandVeryHigh {
			high++
		}
	}

	fmt.Fprintf(w, "Scanned %d files (%s) in %s\n",
		report.Stats.FilesScanned, humanBytes(report.Stats.BytesRead), elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "Findings: %d (%d high or very-high)\n", len(report.Findings), high)
	if report.Stats.Suppressed > 0 {
		fmt.Fprintf(w, "Suppressed: %d (%s)\n", report.Stats.Suppressed, reasonSummary(report.Stats.ByReason))
	}
	if len(report.Warnings) > 0 {
		fmt.Fprintf(w, "Warnings: %d\n", len(report.Warnings))
		for _, warning := range report.Warnings {
			fmt.Fprintf(w, "  %s\n", warning)
		}
	}

	if len(report.Findings) > 0 {
		return 1
	}
	return 0
}

// trace renders a score's derivation for human output.
func trace(signals []confidence.Signal) string {
	parts := make([]string, 0, len(signals))
	for _, signal := range signals {
		parts = append(parts, fmt.Sprintf("%s %+.1f (%s)", signal.Name, signal.Delta, signal.Reason))
	}
	return strings.Join(parts, "; ")
}

// reasonSummary renders suppression counts in a stable order.
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

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
