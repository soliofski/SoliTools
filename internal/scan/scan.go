// Package scan orchestrates the detection modules against a single target.
//
// The pipeline is deliberately one-directional: the page body feeds the secret
// scanner, its scripts feed endpoint and secret extraction, endpoints feed
// parameter discovery, and only classified parameters are actively probed. No
// module invents work for another one without evidence.
package scan

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"sync"

	"solitools/internal/errgroup"
	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/js"
	"solitools/internal/param"
	"solitools/internal/pathscan"
	"solitools/internal/redirect"
	"solitools/internal/reflect"
	"solitools/internal/secret"
)

// Defaults for Options.
const (
	DefaultMaxParams    = 10
	DefaultMaxScripts   = 10
	DefaultMaxPathWords = 20
)

// Options configures a scan.
type Options struct {
	// Target is an absolute http(s) URL.
	Target string
	// Client performs every request.
	Client *httpx.Client
	// MaxParams caps how many parameters are actively probed.
	MaxParams int
	// MaxScripts caps how many first-party scripts are fetched.
	MaxScripts int
	// MaxPathWords caps how many wordlist entries are probed.
	MaxPathWords int
	// SkipPath disables the path module.
	SkipPath bool
}

func (o Options) normalized() Options {
	if o.MaxParams <= 0 {
		o.MaxParams = DefaultMaxParams
	}
	if o.MaxScripts <= 0 {
		o.MaxScripts = DefaultMaxScripts
	}
	if o.MaxPathWords <= 0 {
		o.MaxPathWords = DefaultMaxPathWords
	}
	return o
}

// Stats summarizes what a run looked at.
type Stats struct {
	Requests          int            `json:"requests"`
	Pages             int            `json:"pages"`
	Scripts           int            `json:"scripts"`
	ThirdPartyScripts int            `json:"third_party_scripts"`
	Endpoints         int            `json:"endpoints"`
	Parameters        int            `json:"parameters"`
	Gated             int            `json:"gated"`
	ByReason          map[string]int `json:"gated_by_reason,omitempty"`
}

// Result is the outcome of a scan. Findings are deduplicated and sorted; the
// caller decides which confidence threshold to display.
type Result struct {
	Target   string            `json:"target"`
	Findings []finding.Finding `json:"findings"`
	Stats    Stats             `json:"stats"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Run executes the pipeline.
func Run(ctx context.Context, opts Options) (Result, error) {
	options := opts.normalized()

	target, err := url.Parse(options.Target)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return Result{}, fmt.Errorf("scan: %q is not an absolute http(s) URL", options.Target)
	}
	if options.Client == nil {
		return Result{}, fmt.Errorf("scan: an HTTP client is required")
	}

	scanner, err := secret.New()
	if err != nil {
		return Result{}, err
	}

	result := Result{Target: target.String(), Stats: Stats{ByReason: make(map[string]int)}}
	page, err := options.Client.Fetch(ctx, target.String())
	if err != nil {
		return result, err
	}
	result.Stats.Pages = 1
	result.Target = page.URL

	collected := &collector{byReason: make(map[string]int)}
	// The page body already contains every inline script, so scanning it once
	// covers them; scanning them separately would double-count the same secret.
	collected.addSecret(scanner.Scan(secret.Document{Source: page.URL, Body: page.Body}))

	base, err := url.Parse(page.URL)
	if err != nil {
		return result, fmt.Errorf("scan: %w", err)
	}

	scripts := js.ScriptURLs(page.Body, base)
	firstParty := firstPartyScripts(scripts, base)
	result.Stats.ThirdPartyScripts = len(scripts) - len(firstParty)
	if len(firstParty) > options.MaxScripts {
		firstParty = firstParty[:options.MaxScripts]
	}
	result.Stats.Scripts = len(firstParty)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for _, scriptURL := range firstParty {
		scriptURL := scriptURL
		group.Go(func() error {
			response, err := options.Client.Get(groupCtx, scriptURL)
			if err != nil || response.Status != 200 {
				return nil
			}
			collected.addSecret(scanner.Scan(secret.Document{Source: scriptURL, Body: response.Body}))
			collected.addEndpoints(js.ExtractEndpoints(response.Body, base))

			// Endpoints discovered inside a bundle may themselves carry
			// parameters, but only those on the script's own origin are useful.
			if parsed, err := url.Parse(scriptURL); err == nil {
				collected.addParams(parsed)
			}
			return nil
		})
	}
	_ = group.Wait()

	collected.addEndpoints(js.ExtractEndpoints(page.Body, base))
	collected.addParams(target)
	collected.addParams(base)

	endpoints, params := collected.snapshot()
	result.Stats.Endpoints = len(endpoints)
	result.Stats.Parameters = len(params)

	// Probe parameters, highest interest first.
	sort.SliceStable(params, func(i, j int) bool {
		if params[i].Interest != params[j].Interest {
			return params[i].Interest > params[j].Interest
		}
		return params[i].Name < params[j].Name
	})
	probes := params
	if len(probes) > options.MaxParams {
		probes = probes[:options.MaxParams]
	}

	reflectAnalyzer := reflect.New(options.Client)
	redirectAnalyzer := redirect.New(options.Client)

	probeGroup, probeCtx := errgroup.WithContext(ctx)
	probeGroup.SetLimit(4)
	for _, probe := range probes {
		probe := probe
		probeGroup.Go(func() error {
			candidate, ok := reflectAnalyzer.Probe(probeCtx, reflect.Target{URL: probe.URL, Name: probe.Name, Interest: probe.Interest})
			if ok {
				collected.addFinding(candidate)
			}
			if redirect.IsRedirectParam(probe.Name) {
				redirected, ok := redirectAnalyzer.Probe(probeCtx, redirect.Target{URL: probe.URL, Name: probe.Name, Interest: probe.Interest})
				if ok {
					collected.addFinding(redirected)
				}
			}
			return nil
		})
	}
	_ = probeGroup.Wait()

	if !options.SkipPath {
		words := pathscan.Wordlist()
		if len(words) > options.MaxPathWords {
			words = words[:options.MaxPathWords]
		}
		origin := target.Scheme + "://" + target.Host
		paths, warnings := pathscan.New(options.Client, words, 6).Probe(ctx, origin)
		for _, candidate := range paths {
			collected.addFinding(candidate)
		}
		result.Warnings = append(result.Warnings, warnings...)
	}

	result.Findings = dedupe(collected.findings)
	result.Stats.Gated = collected.gated
	result.Stats.ByReason = collected.byReason
	result.Stats.Requests = int(options.Client.Requests())
	return result, nil
}

// IsRedirectParam is re-exported for callers that need the same rule.
func IsRedirectParam(name string) bool { return redirect.IsRedirectParam(name) }

// firstPartyScripts keeps scripts belonging to the target site.
func firstPartyScripts(scripts []string, base *url.URL) []string {
	out := make([]string, 0, len(scripts))
	for _, script := range scripts {
		parsed, err := url.Parse(script)
		if err != nil {
			continue
		}
		if js.IsThirdParty(parsed, base) {
			continue
		}
		out = append(out, script)
	}
	return out
}

// collector gathers findings from concurrent goroutines.
type collector struct {
	mu        sync.Mutex
	findings  []finding.Finding
	endpoints []string
	params    []probeTarget
	gated     int
	byReason  map[string]int
}

// probeTarget is one parameter to probe, with the page that carries it.
type probeTarget struct {
	URL      string
	Name     string
	Interest param.Interest
}

func (c *collector) addSecret(result secret.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, result.Findings...)
	c.gated += result.Suppressed
	for reason, count := range result.ByReason {
		c.byReason[reason] += count
	}
}

func (c *collector) addFinding(candidate finding.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, candidate)
}

func (c *collector) addEndpoints(endpoints []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints = append(c.endpoints, endpoints...)
}

func (c *collector) addParams(u *url.URL) {
	if u == nil {
		return
	}
	names := param.Names(u)
	if len(names) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range names {
		c.params = append(c.params, probeTarget{URL: u.String(), Name: name, Interest: param.Classify(name)})
	}
}

func (c *collector) snapshot() ([]string, []probeTarget) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seenEndpoints := make(map[string]struct{}, len(c.endpoints))
	endpoints := make([]string, 0, len(c.endpoints))
	for _, endpoint := range c.endpoints {
		if _, duplicate := seenEndpoints[endpoint]; duplicate {
			continue
		}
		seenEndpoints[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}

	seenParams := make(map[string]struct{}, len(c.params))
	params := make([]probeTarget, 0, len(c.params))
	for _, target := range c.params {
		key := target.URL + "|" + target.Name
		if _, duplicate := seenParams[key]; duplicate {
			continue
		}
		seenParams[key] = struct{}{}
		params = append(params, target)
	}

	return endpoints, params
}

// dedupe collapses repeated evidence and records how often it was seen.
func dedupe(findings []finding.Finding) []finding.Finding {
	byKey := make(map[string]int, len(findings))
	out := make([]finding.Finding, 0, len(findings))
	counts := make(map[string]int, len(findings))

	for _, candidate := range findings {
		key := candidate.DedupeKey()
		counts[key]++
		if index, seen := byKey[key]; seen {
			if candidate.Confidence.Value > out[index].Confidence.Value {
				out[index] = candidate
			}
			continue
		}
		byKey[key] = len(out)
		out = append(out, candidate)
	}

	for i := range out {
		if count := counts[out[i].DedupeKey()]; count > 1 {
			out[i].WithField("Occurrences", strconv.Itoa(count))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence.Value != out[j].Confidence.Value {
			return out[i].Confidence.Value > out[j].Confidence.Value
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].URL < out[j].URL
	})
	return out
}
