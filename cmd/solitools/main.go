// Command solitools scans a web target for secrets, reflections, open
// redirects and reachable sensitive paths, and reports only what clears a
// confidence threshold.
//
// Use it exclusively against systems you are authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"solitools/internal/confidence"
	"solitools/internal/httpx"
	"solitools/internal/progress"
	"solitools/internal/report"
	"solitools/internal/scan"
	"solitools/internal/term"
)

const version = "0.8.0"

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
	fmt.Fprint(w, `solitools - high-accuracy web security scanning

Usage:
  solitools scan [flags] <url>
  solitools version

Flags for scan:
  -strict                 only show findings with confidence >= 75
  -all                    show every finding, including low confidence
  -min-score float        custom minimum score (overrides -strict/-all)
  -mask                   mask secret values in the output (default true;
                          pass -mask=false to reveal them)
  -rate float             maximum requests per second (default 10)
  -proxy string           HTTP/HTTPS proxy URL
  -header "Name: value"   extra request header (repeatable)
  -cookie string          Cookie header value
  -timeout duration       per-request timeout (default 15s)
  -max-params int         maximum parameters to probe (default 10)
  -skip-path              skip the sensitive-path wordlist
  -forms                  submit POST forms (may change state; same-origin only)
  -stored                 re-fetch known pages to detect stored/blind XSS
  -verbose                show the score derivation
  -quiet                  print only a one-line summary (CI mode)
  -width int              wrap output to this many columns (0 = detect)
  -json                   emit a JSON report
  -sarif                  emit a SARIF 2.1.0 log (code scanning)
  -color auto|always|never
                          color output (default auto: only on a terminal)

Exit codes:
  0  no findings at the selected threshold
  1  findings reported
  2  usage or runtime error

Only scan systems you are authorized to test.
`)
}

// headerList collects repeatable -header flags.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func runScan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	strict := flags.Bool("strict", false, "only show findings with confidence >= 75")
	all := flags.Bool("all", false, "show every finding, including low confidence")
	minScore := flags.Float64("min-score", 0, "custom minimum score")
	mask := flags.Bool("mask", true, "mask secret values in the output")
	rate := flags.Float64("rate", httpx.DefaultRate, "maximum requests per second")
	proxy := flags.String("proxy", "", "HTTP/HTTPS proxy URL")
	timeout := flags.Duration("timeout", httpx.DefaultTimeout, "per-request timeout")
	cookie := flags.String("cookie", "", "Cookie header value")
	maxParams := flags.Int("max-params", scan.DefaultMaxParams, "maximum parameters to probe")
	skipPath := flags.Bool("skip-path", false, "skip the sensitive-path wordlist")
	submitForms := flags.Bool("forms", false, "submit POST forms (may change state; same-origin only)")
	stored := flags.Bool("stored", false, "re-fetch known pages to detect stored/blind reflection")
	verbose := flags.Bool("verbose", false, "show the score derivation")
	quiet := flags.Bool("quiet", false, "print only a one-line summary")
	width := flags.Int("width", 0, "wrap output to this many columns (0 = detect)")
	asJSON := flags.Bool("json", false, "emit a JSON report")
	asSARIF := flags.Bool("sarif", false, "emit a SARIF 2.1.0 log")
	colorMode := flags.String("color", "auto", "color output: auto, always or never")

	var headers headerList
	flags.Var(&headers, "header", "extra request header, \"Name: value\" (repeatable)")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	targets := flags.Args()
	if len(targets) != 1 {
		fmt.Fprintln(stderr, "solitools scan: exactly one target URL is required")
		return 2
	}
	target := normalizeTarget(targets[0])

	if *asJSON && *asSARIF {
		fmt.Fprintln(stderr, "solitools scan: -json and -sarif are mutually exclusive")
		return 2
	}

	shade, err := term.ParseMode(*colorMode)
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}
	theme := term.New(stdout, shade)
	if *quiet {
		// CI output stays plain and deterministic even on a color terminal.
		theme = term.New(stdout, term.ModeNever)
	}
	if *width < 0 {
		fmt.Fprintf(stderr, "solitools scan: -width must be zero or positive, got %d\n", *width)
		return 2
	}

	threshold, err := resolveThreshold(flags, *minScore, *strict, *all)
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}

	client, err := httpx.New(httpx.Options{
		Rate:    *rate,
		Timeout: *timeout,
		Proxy:   *proxy,
		Headers: headers,
		Cookie:  *cookie,
	})
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}

	// Machine formats must stay parseable: no banner and no live status block.
	machine := *asJSON || *asSARIF
	if !machine && !*quiet {
		writeBanner(stdout, theme, target, threshold, *rate)
	}
	live := progress.New(stdout, theme, client)
	if !machine && !*quiet {
		live.Start()
	}

	start := time.Now()
	result, err := scan.Run(context.Background(), scan.Options{
		Target:    target,
		Client:    client,
		MaxParams: *maxParams,
		SkipPath:  *skipPath,
		// Opt-in: a form submission can create records or send mail.
		EnableForms: *submitForms,
		// Opt-in: extra requests, and the answer may be state a POST wrote.
		EnableStored: *stored,
		Progress:     live.Stage,
	})
	live.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "solitools scan: %v\n", err)
		return 2
	}

	shown, err := report.Render(stdout, result, report.Options{
		Threshold: threshold,
		Mask:      *mask,
		Verbose:   *verbose,
		Quiet:     *quiet,
		Width:     *width,
		JSON:      *asJSON,
		SARIF:     *asSARIF,
		Elapsed:   time.Since(start),
		Version:   version,
		Theme:     theme,
	})
	if err != nil {
		fmt.Fprintf(stderr, "solitools: %v\n", err)
		return 2
	}
	if shown > 0 {
		return 1
	}
	return 0
}

// writeBanner prints the product header before a scan starts.
func writeBanner(w io.Writer, theme *term.Theme, target string, threshold, rate float64) {
	fmt.Fprintf(w, "%s %s\n", theme.Accent("SoliTools"), theme.Dim(version))
	fmt.Fprintf(w, "  %s %s\n", theme.Dim("target  "), theme.Color("url", target))
	fmt.Fprintf(w, "  %s %s\n\n", theme.Dim("settings"), describeThreshold(threshold, rate))
}

func describeThreshold(threshold, rate float64) string {
	if threshold <= 0 {
		return fmt.Sprintf("showing all findings · %.0f req/s", rate)
	}
	return fmt.Sprintf("confidence >= %.0f (%s) · %.0f req/s", threshold, confidence.BandOf(threshold), rate)
}

// resolveThreshold picks the display threshold. An explicit -min-score always
// wins; -strict and -all are mutually exclusive so a typo cannot silently
// produce the wrong report.
func resolveThreshold(flags *flag.FlagSet, minScore float64, strict, all bool) (float64, error) {
	explicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "min-score" {
			explicit = true
		}
	})

	switch {
	case explicit:
		if minScore < 0 || minScore > 100 {
			return 0, fmt.Errorf("min-score %v outside [0, 100]", minScore)
		}
		return minScore, nil
	case strict && all:
		return 0, errors.New("-strict and -all are mutually exclusive")
	case strict:
		return confidence.ThresholdStrict, nil
	case all:
		return confidence.ThresholdAll, nil
	default:
		return confidence.ThresholdDefault, nil
	}
}

// normalizeTarget adds https:// to a bare host so "example.com" works.
func normalizeTarget(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "https://" + raw
}
