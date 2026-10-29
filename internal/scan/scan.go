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
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/soliofski/SoliTools/internal/cors"
	"github.com/soliofski/SoliTools/internal/crawl"
	"github.com/soliofski/SoliTools/internal/crlf"
	"github.com/soliofski/SoliTools/internal/errgroup"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/form"
	"github.com/soliofski/SoliTools/internal/httpx"
	"github.com/soliofski/SoliTools/internal/js"
	"github.com/soliofski/SoliTools/internal/param"
	"github.com/soliofski/SoliTools/internal/parammine"
	"github.com/soliofski/SoliTools/internal/pathscan"
	"github.com/soliofski/SoliTools/internal/prototype"
	"github.com/soliofski/SoliTools/internal/redirect"
	"github.com/soliofski/SoliTools/internal/reflect"
	"github.com/soliofski/SoliTools/internal/secret"
	"github.com/soliofski/SoliTools/internal/ssrf"
	"github.com/soliofski/SoliTools/internal/verify"
	"github.com/soliofski/SoliTools/internal/waf"
)

// Defaults for Options.
const (
	DefaultMaxParams    = 10
	DefaultMaxScripts   = 10
	DefaultMaxPathWords = 20
	// DefaultMaxForms caps POST form probing, which is opt-in.
	DefaultMaxForms = 3
	// DefaultMaxStoredPages caps stored-reflection re-fetches, which are opt-in.
	DefaultMaxStoredPages = 5
	// DefaultMaxPages caps a crawl, seed page included.
	DefaultMaxPages = 10
	// maxSourceMapBytes bounds one source map. Maps are bigger than pages, but
	// still bounded: five of them at 10 MiB is the worst case per run.
	maxSourceMapBytes = 10 << 20
	// maxJSONParams bounds the second probe pass for names mined from JSON
	// responses. Without a cap, an API that echoes its schema could steer the
	// scan indefinitely.
	maxJSONParams = 5
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
	// EnableForms submits POST forms. Off by default: a form submission can
	// change state, so it is opt-in and restricted to same-origin forms.
	EnableForms bool
	// MaxForms caps how many POST forms are probed.
	MaxForms int
	// EnableStored re-fetches known pages after probing to find values the
	// server kept. Off by default: it costs extra requests and reports state a
	// POST may have written.
	EnableStored bool
	// MaxStoredPages caps how many pages the stored pass re-fetches.
	MaxStoredPages int
	// EnableCrawl follows same-origin links on the seed page (depth one).
	EnableCrawl bool
	// MaxPages caps how many pages a crawl fetches, seed included.
	MaxPages int
	// EnableMine runs hidden-parameter mining against the seed. Off by default:
	// it costs a burst of requests and is noisy on dynamic pages.
	EnableMine bool
	// Wordlist replaces the built-in sensitive-path list. It is already capped
	// by pathscan.LoadWordlist.
	Wordlist []string
	// WordlistTruncated reports that a custom list was capped while loading.
	WordlistTruncated bool
	// Verify actively validates supported credentials against provider identity
	// APIs. Off by default: it is the only path that contacts a third party.
	Verify bool
	// Verifier overrides the default verifier. Tests inject one with local base
	// URLs so no provider is ever contacted.
	Verifier *verify.Verifier
	// Progress is called at each pipeline stage with a short human label. It is
	// always invoked from the goroutine that called Run, never concurrently.
	Progress func(stage string)
	// Notify is called for every finding as it is produced, before dedupe. The
	// TUI uses it for live counters; it may be called concurrently and must be
	// cheap and safe for concurrent use.
	Notify func(finding.Finding)
	// OnWAF reports a detected provider as soon as it is known: at the seed for
	// passive fronting, or when probes start getting blocked.
	OnWAF func(provider string)
}

// reportProgress publishes a stage label if a listener is attached.
func (o Options) reportProgress(stage string) {
	if o.Progress != nil {
		o.Progress(stage)
	}
}

// reportWAF publishes a detected provider if a listener is attached.
func (o Options) reportWAF(provider string) {
	if o.OnWAF != nil {
		o.OnWAF(provider)
	}
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
	if o.MaxForms <= 0 {
		o.MaxForms = DefaultMaxForms
	}
	if o.MaxStoredPages <= 0 {
		o.MaxStoredPages = DefaultMaxStoredPages
	}
	if o.MaxPages <= 0 {
		o.MaxPages = DefaultMaxPages
	}
	return o
}

// Stats summarizes what a run looked at.
type Stats struct {
	Requests          int            `json:"requests"`
	Pages             int            `json:"pages"`
	Scripts           int            `json:"scripts"`
	SourceMaps        int            `json:"source_maps,omitempty"`
	JSONProbes        int            `json:"json_probes,omitempty"`
	MinedParams       int            `json:"mined_params,omitempty"`
	ThirdPartyScripts int            `json:"third_party_scripts"`
	Endpoints         int            `json:"endpoints"`
	Parameters        int            `json:"parameters"`
	Forms             int            `json:"forms"`
	StoredPages       int            `json:"stored_pages,omitempty"`
	Gated             int            `json:"gated"`
	ByReason          map[string]int `json:"gated_by_reason,omitempty"`
}

// Result is the outcome of a scan. Findings are deduplicated and sorted; the
// caller decides which confidence threshold to display.
type Result struct {
	Target   string            `json:"target"`
	WAF      string            `json:"waf,omitempty"`
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
	options.reportProgress("crawling target")
	page, err := options.Client.Fetch(ctx, target.String())
	if err != nil {
		return result, err
	}
	result.Stats.Pages = 1
	result.Target = page.URL

	// A WAF can front a perfectly healthy site; record it, but do not call the
	// page a block. Only IsBlockPage suppresses findings.
	if provider, ok := waf.Detect(page); ok {
		result.WAF = string(provider)
		result.Warnings = append(result.Warnings, "Target is fronted by "+string(provider))
		options.reportWAF(string(provider))
	}

	base, err := url.Parse(page.URL)
	if err != nil {
		return result, fmt.Errorf("scan: %w", err)
	}

	fetched := []fetchedPage{{URL: page.URL, Body: page.Body, ContentType: page.ContentType()}}
	if options.EnableCrawl {
		options.reportProgress("crawling links")
		fetched = append(fetched, crawlPages(ctx, options, base, fetched[0], options.MaxPages-1)...)
	}
	result.Stats.Pages = len(fetched)

	collected := &collector{byReason: make(map[string]int), stored: make(map[string][]reflect.Submission), notify: options.Notify}

	// CORS is evaluated once, on the seed, before any state-changing work: it
	// costs four Origin variants and can expose a cross-origin read of whatever
	// the page already returns.
	options.reportProgress("checking CORS")
	if candidate, ok := cors.New(options.Client).Probe(ctx, cors.Target{
		URL:     page.URL,
		IsAPI:   looksLikeAPI(base.Path),
		HasAuth: page.Header.Get("Set-Cookie") != "",
	}); ok {
		collected.addFinding(*candidate)
	}
	// The page body already contains every inline script, so scanning it once
	// covers them; scanning them separately would double-count the same secret.
	for _, current := range fetched {
		collected.addSecret(scanner.Scan(secret.Document{Source: current.URL, Body: current.Body}))
	}

	scripts := make([]string, 0, 8)
	seenScripts := make(map[string]struct{}, 8)
	seenThirdParty := make(map[string]struct{}, 8)
	usedForms := 0

	for _, current := range fetched {
		currentBase, err := url.Parse(current.URL)
		if err != nil {
			continue
		}
		for _, endpoint := range js.ExtractEndpoints(current.Body, currentBase) {
			collected.addEndpoints([]string{endpoint})
			if endpointURL, err := url.Parse(endpoint); err == nil {
				collected.addParams(endpointURL)
			}
		}
		collected.addParams(currentBase)
		if param.LooksJSON(current.ContentType, current.Body) {
			for _, field := range param.FromJSONFields(current.Body, 3) {
				collected.addJSONField(current.URL, field.Path)
			}
		}

		for _, scriptURL := range js.ScriptURLs(current.Body, currentBase) {
			parsed, err := url.Parse(scriptURL)
			if err != nil {
				continue
			}
			if js.IsThirdParty(parsed, currentBase) {
				if _, counted := seenThirdParty[scriptURL]; !counted {
					seenThirdParty[scriptURL] = struct{}{}
					result.Stats.ThirdPartyScripts++
				}
				continue
			}
			if _, duplicate := seenScripts[scriptURL]; duplicate {
				continue
			}
			seenScripts[scriptURL] = struct{}{}
			scripts = append(scripts, scriptURL)
		}

		// MaxForms is a run-wide budget, so each page receives what is left.
		usedForms += collected.addForms(current.Body, currentBase, options.EnableForms, options.MaxForms-usedForms)
	}

	firstParty := scripts
	if len(firstParty) > options.MaxScripts {
		firstParty = firstParty[:options.MaxScripts]
	}
	result.Stats.Scripts = len(firstParty)

	// Source maps named by first-party scripts are a second, richer source of
	// endpoints and of code that never shipped minified.
	var (
		mapMu      sync.Mutex
		seenMaps   = make(map[string]struct{}, 4)
		sourceMaps = make([]sourceMapRef, 0, 4)
	)

	options.reportProgress("analysing scripts")
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
			if candidate, ok := prototype.AnalyzeScript(prototype.ScriptAnalysis{
				URL: scriptURL, Content: string(response.Body),
			}); ok {
				collected.addFinding(*candidate)
			}

			// Endpoints discovered inside a bundle may themselves carry
			// parameters, but only those on the script's own origin are useful.
			if parsed, err := url.Parse(scriptURL); err == nil {
				for _, endpoint := range js.ExtractEndpoints(response.Body, parsed) {
					collected.addEndpoints([]string{endpoint})
					if endpointURL, err := url.Parse(endpoint); err == nil {
						collected.addParams(endpointURL)
					}
				}
				collected.addParams(parsed)

				if mapURL := js.SourceMapURL(response.Body, parsed, response.Header); mapURL != "" {
					mapMu.Lock()
					if _, duplicate := seenMaps[mapURL]; !duplicate && len(sourceMaps) < 5 {
						seenMaps[mapURL] = struct{}{}
						sourceMaps = append(sourceMaps, sourceMapRef{URL: mapURL, Script: parsed})
					}
					mapMu.Unlock()
				}
			}
			return nil
		})
	}
	_ = group.Wait()

	// Source maps are fetched with the same client, at most five, four at a
	// time, and a 10 MiB ceiling per map. A malformed or truncated map is
	// simply skipped: it is extra surface, not a reason to fail a scan.
	if len(sourceMaps) > 0 {
		options.reportProgress("analysing source maps")
		mapGroup, mapCtx := errgroup.WithContext(ctx)
		mapGroup.SetLimit(4)
		var statsMu sync.Mutex
		for _, ref := range sourceMaps {
			ref := ref
			mapGroup.Go(func() error {
				response, err := options.Client.GetLimited(mapCtx, ref.URL, maxSourceMapBytes)
				if err != nil || response.Status != http.StatusOK {
					return nil
				}
				parsed, err := js.ParseSourceMap(response.Body)
				if err != nil {
					return nil
				}
				statsMu.Lock()
				result.Stats.SourceMaps++
				statsMu.Unlock()

				for index, content := range parsed.SourcesContent {
					if strings.TrimSpace(content) == "" {
						continue
					}
					source := ref.URL
					if index < len(parsed.Sources) && parsed.Sources[index] != "" {
						source += "#" + parsed.Sources[index]
					}
					body := []byte(content)
					collected.addSecret(scanner.Scan(secret.Document{Source: source, Body: body}))

					for _, endpoint := range js.ExtractEndpoints(body, ref.Script) {
						concrete, names := js.EndpointParameters(endpoint)
						parsedEndpoint, err := url.Parse(concrete)
						if err != nil {
							continue
						}
						collected.addEndpoints([]string{parsedEndpoint.String()})
						collected.addParams(parsedEndpoint)
						collected.addParamNames(parsedEndpoint, names, true)
					}
				}
				return nil
			})
		}
		_ = mapGroup.Wait()
	}

	// Hidden-parameter mining is opt-in: it spends a burst of requests to learn
	// names the page never linked, and a dynamic page makes it useless. An
	// unstable baseline is a warning, not a failed scan.
	if options.EnableMine {
		options.reportProgress("mining hidden parameters")
		discovered, mineErr := parammine.New(options.Client).Mine(ctx, page.URL, param.Names(target))
		switch {
		case mineErr != nil:
			result.Warnings = append(result.Warnings, "parameter mining skipped: "+mineErr.Error())
		case len(discovered) > 0:
			collected.addParamNames(base, discovered, false)
			result.Stats.MinedParams = len(discovered)
		}
	}

	collected.addParams(target)
	result.Stats.Forms = usedForms

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
	crlfAnalyzer := crlf.New(options.Client)
	ssrfAnalyzer := ssrf.New(options.Client)
	options.reportProgress("probing parameters")

	// Watch probe responses for block pages. The observer is scoped to this
	// stage: path scanning later must not count toward the probe streak.
	watcher := &blockWatcher{}
	options.Client.SetObserver(watcher.observe)

	probeGroup, probeCtx := errgroup.WithContext(ctx)
	probeGroup.SetLimit(4)
	var jsonProbes int64
	var crlfProbes, ssrfProbes int32
	const maxCRLFParams = 3
	const maxSSRFParams = 3
	for _, probe := range probes {
		probe := probe
		probeGroup.Go(func() error {
			submission := reflectAnalyzer.Submit(probeCtx, reflect.Target{
				URL: probe.URL, Name: probe.Name, Interest: probe.Interest,
				Method: probe.Method, Fields: probe.Fields,
			})
			if candidate, ok := reflect.Analyze(submission); ok {
				collected.addFinding(candidate)
			}
			// The submission is kept only if a response arrived: a value that was
			// never accepted cannot have been stored.
			if options.EnableStored && submission.Status != 0 {
				collected.addSubmission(storagePage(probe.URL, probe.Name, probe.Method), submission)
			}
			// A JSON API answer can name parameters the page markup never showed.
			if submission.JSONBody != "" && !strings.EqualFold(probe.Method, http.MethodPost) {
				for _, field := range param.FromJSONFields([]byte(submission.JSONBody), 3) {
					collected.addJSONParam(probe.URL, field.Path)
				}
			}
			if redirect.IsRedirectParam(probe.Name) {
				redirected, ok := redirectAnalyzer.Probe(probeCtx, redirect.Target{
					URL: probe.URL, Name: probe.Name, Interest: probe.Interest,
					Method: probe.Method, Fields: probe.Fields,
				})
				if ok {
					collected.addFinding(redirected)
				}
			}
			// JSON body probing runs alongside the query probe, not instead of
			// it: the same parameter can be read from either channel.
			if probe.JSON && !strings.EqualFold(probe.Method, http.MethodPost) {
				jsonSubmission := reflectAnalyzer.SubmitJSON(probeCtx, reflect.JSONTarget{
					URL: probe.URL, Name: probe.Name, Path: probe.JSONPath, Interest: probe.Interest,
				})
				if candidate, ok := reflect.Analyze(jsonSubmission); ok {
					collected.addFinding(candidate)
				}
				atomic.AddInt64(&jsonProbes, 1)
				if redirect.IsRedirectParam(probe.Name) {
					if redirected, ok := redirectAnalyzer.ProbeJSON(probeCtx, redirect.JSONTarget{
						URL: probe.URL, Name: probe.Name,
					}); ok {
						collected.addFinding(redirected)
					}
				}
			}
			// CRLF and SSRF are expensive per parameter (5 and 3 requests), so
			// they run only for the first few eligible targets, in interest order.
			if !strings.EqualFold(probe.Method, http.MethodPost) {
				if crlfEligible(probe) && atomic.AddInt32(&crlfProbes, 1) <= maxCRLFParams {
					if candidate, ok := crlfAnalyzer.Probe(probeCtx, crlf.Target{URL: probe.URL, Param: probe.Name}); ok {
						collected.addFinding(*candidate)
					}
					if candidate, ok := crlf.ProbeRaw(probeCtx, options.Client, probe.URL, probe.Name); ok {
						collected.addFinding(*candidate)
					}
				}
				if ssrf.IsSSRFParam(probe.Name) && atomic.AddInt32(&ssrfProbes, 1) <= maxSSRFParams {
					if candidate, ok := ssrfAnalyzer.Probe(probeCtx, ssrf.Target{
						BaseURL: probe.URL, Param: probe.Name, Method: probe.Method,
					}); ok {
						collected.addFinding(*candidate)
					}
				}
			}
			return nil
		})
	}
	_ = probeGroup.Wait()

	// Names mined from JSON probe responses were not in the snapshot, so they
	// get one bounded second pass. No further mining runs here: one level of
	// discovery, never a loop.
	probed := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		probed[probeTargetKey(probe)] = struct{}{}
	}
	if extras := collected.takeJSONTargets(maxJSONParams, probed); len(extras) > 0 {
		extraGroup, extraCtx := errgroup.WithContext(ctx)
		extraGroup.SetLimit(4)
		for _, target := range extras {
			target := target
			extraGroup.Go(func() error {
				submission := reflectAnalyzer.SubmitJSON(extraCtx, reflect.JSONTarget{
					URL: target.URL, Name: target.Name, Path: target.JSONPath, Interest: target.Interest,
				})
				if candidate, ok := reflect.Analyze(submission); ok {
					collected.addFinding(candidate)
				}
				atomic.AddInt64(&jsonProbes, 1)
				if redirect.IsRedirectParam(target.Name) {
					if redirected, ok := redirectAnalyzer.ProbeJSON(extraCtx, redirect.JSONTarget{
						URL: target.URL, Name: target.Name,
					}); ok {
						collected.addFinding(redirected)
					}
				}
				return nil
			})
		}
		_ = extraGroup.Wait()
	}

	result.Stats.JSONProbes = int(atomic.LoadInt64(&jsonProbes))
	options.Client.SetObserver(nil)

	if provider, blocked := watcher.interception(); blocked {
		result.Warnings = append(result.Warnings, interceptionWarning(provider))
		if result.WAF == "" {
			result.WAF = string(provider)
		}
		options.reportWAF(string(provider))
	}

	// Stored reflection is a second-pass question about the same submissions:
	// known pages are fetched again later in the run, and only canaries that
	// were absent from the immediate response can qualify.
	if options.EnableStored {
		options.reportProgress("checking stored reflections")
		if containsCanary(page.Body) {
			// A canary already in the first response means an earlier run (or
			// the page itself) contaminated the baseline; every hit would be a
			// false attribution to this scan.
			result.Warnings = append(result.Warnings, "stored check skipped: the target body already contained a canary")
		} else {
			limit := options.MaxStoredPages
			targets := collected.storedPages()
			if options.EnableCrawl {
				// A crawled page can be the listing that serves a value stored
				// elsewhere, so the crawled set becomes observation targets too.
				limit = options.MaxPages
				targets = append(targets, page.URL)
				for _, current := range fetched[1:] {
					targets = append(targets, current.URL)
				}
			}
			targets = uniquePages(targets, limit)

			submissions := collected.allSubmissions()
			known := make(map[string][]byte, len(fetched))
			for _, current := range fetched {
				known[current.URL] = current.Body
			}

			storedGroup, storedCtx := errgroup.WithContext(ctx)
			storedGroup.SetLimit(2)
			checked := 0
			for _, pageURL := range targets {
				pageURL := pageURL
				if body, ok := known[pageURL]; ok && containsCanary(body) {
					continue
				}
				checked++
				storedGroup.Go(func() error {
					for _, candidate := range reflectAnalyzer.Stored(storedCtx, pageURL, submissions) {
						collected.addFinding(candidate)
					}
					return nil
				})
			}
			_ = storedGroup.Wait()
			result.Stats.StoredPages = checked
		}
	}

	if !options.SkipPath {
		options.reportProgress("scanning sensitive paths")
		// A custom list is already capped at MaxCustomWords while loading, so
		// applying the default 20-entry budget to it would silently ignore most
		// of what the user asked for.
		words := options.Wordlist
		if len(words) == 0 {
			words = pathscan.DefaultWordlist()
			if len(words) > options.MaxPathWords {
				words = words[:options.MaxPathWords]
			}
		}
		origin := target.Scheme + "://" + target.Host
		paths, warnings := pathscan.New(options.Client, words, 6).Probe(ctx, origin)
		for _, candidate := range paths {
			collected.addFinding(candidate)
		}
		result.Warnings = append(result.Warnings, warnings...)
		if options.WordlistTruncated {
			result.Warnings = append(result.Warnings, fmt.Sprintf("wordlist truncated to %d entries", pathscan.MaxCustomWords))
		}
	}

	result.Findings = dedupe(collected.findings)

	// Live validation is the only stage that leaves the target's origin, so it
	// runs last, once dedupe has collapsed a credential to one finding. Skipped
	// checks leave the structural score untouched.
	if options.Verify {
		options.reportProgress("verifying credentials")
		verifier := options.Verifier
		if verifier == nil {
			verifier = verify.New()
		}
		result.Findings = verifier.Apply(ctx, result.Findings)
	}
	result.Stats.Gated = collected.gated
	result.Stats.ByReason = collected.byReason
	result.Stats.Requests = int(options.Client.Requests())
	return result, nil
}

// IsRedirectParam is re-exported for callers that need the same rule.
func IsRedirectParam(name string) bool { return redirect.IsRedirectParam(name) }

// fetchedPage is one page the pipeline analyses: the seed or a crawled link.
type fetchedPage struct {
	URL         string
	Body        []byte
	ContentType string
}

// sourceMapRef is a discovered same-origin map and the script that named it.
type sourceMapRef struct {
	URL    string
	Script *url.URL
}

// crawlPages fetches the depth-one links of the seed, four at a time, and
// returns the successful ones in URL order so a run is reproducible.
func crawlPages(ctx context.Context, options Options, base *url.URL, seed fetchedPage, budget int) []fetchedPage {
	if budget <= 0 {
		return nil
	}
	links := crawl.Links(seed.Body, base, budget)
	if len(links) == 0 {
		return nil
	}

	var (
		mu    sync.Mutex
		pages []fetchedPage
	)
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for _, link := range links {
		link := link
		group.Go(func() error {
			response, err := options.Client.Get(groupCtx, link)
			if err != nil || response.Status != 200 {
				return nil
			}
			mu.Lock()
			pages = append(pages, fetchedPage{URL: link, Body: response.Body, ContentType: response.ContentType()})
			mu.Unlock()
			return nil
		})
	}
	_ = group.Wait()

	sort.SliceStable(pages, func(i, j int) bool { return pages[i].URL < pages[j].URL })
	return pages
}

// uniquePages deduplicates while preserving priority order, then caps.
func uniquePages(pages []string, limit int) []string {
	seen := make(map[string]struct{}, len(pages))
	out := make([]string, 0, len(pages))
	for _, page := range pages {
		if page == "" {
			continue
		}
		if _, duplicate := seen[page]; duplicate {
			continue
		}
		seen[page] = struct{}{}
		out = append(out, page)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// collector gathers findings from concurrent goroutines.
type collector struct {
	mu        sync.Mutex
	findings  []finding.Finding
	endpoints []string
	params    []probeTarget
	// stored maps a page to the submissions whose values could have been
	// persisted there; the stored pass re-fetches each page once.
	stored     map[string][]reflect.Submission
	jsonParams []probeTarget
	notify     func(finding.Finding)
	gated      int
	byReason   map[string]int
}

// probeTarget is one parameter to probe, with the page that carries it.
type probeTarget struct {
	URL      string
	Name     string
	Interest param.Interest
	// Method is "" or "GET" for a query parameter, "POST" for a form field.
	Method string
	// Fields carries form defaults for a POST target.
	Fields url.Values
	// JSON marks a target worth a JSON body probe: an /api/ endpoint, or a
	// parameter mined from JSON or a source map.
	JSON bool
	// JSONPath is the mined object path, including the name, used to build a
	// nested request body.
	JSONPath []string
}

func (c *collector) addSecret(result secret.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, result.Findings...)
	c.gated += result.Suppressed
	for reason, count := range result.ByReason {
		c.byReason[reason] += count
	}
	for _, candidate := range result.Findings {
		c.notifyFinding(candidate)
	}
}

func (c *collector) addFinding(candidate finding.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, candidate)
	c.notifyFinding(candidate)
}

// notifyFinding runs the optional observer. The caller already holds the lock,
// so the callback must not touch the collector.
func (c *collector) notifyFinding(candidate finding.Finding) {
	if c.notify != nil {
		c.notify(candidate)
	}
}

func (c *collector) addSubmission(page string, submission reflect.Submission) {
	if page == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stored[page] = append(c.stored[page], submission)
}

// storedPages returns every page that received a submission, sorted.
func (c *collector) storedPages() []string {
	c.mu.Lock()
	pages := make([]string, 0, len(c.stored))
	for page := range c.stored {
		pages = append(pages, page)
	}
	c.mu.Unlock()

	sort.Strings(pages)
	return pages
}

// allSubmissions returns every recorded submission in page order. The stored
// pass checks each observation page against all of them: a value submitted on
// one page and served on another is exactly the bug it looks for.
func (c *collector) allSubmissions() []reflect.Submission {
	c.mu.Lock()
	defer c.mu.Unlock()

	pages := make([]string, 0, len(c.stored))
	for page := range c.stored {
		pages = append(pages, page)
	}
	sort.Strings(pages)

	submissions := make([]reflect.Submission, 0, len(c.stored))
	for _, page := range pages {
		submissions = append(submissions, c.stored[page]...)
	}
	return submissions
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
		c.params = append(c.params, probeTarget{
			URL:      u.String(),
			Name:     name,
			Interest: param.Classify(name),
			JSON:     looksLikeAPI(u.Path),
		})
	}
}

// addJSONField attaches a JSON-mined field, with the path that leads to it, to
// the page it was found on. These are available before the parameter snapshot.
func (c *collector) addJSONField(rawURL string, path []string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || len(path) == 0 {
		return
	}
	name := path[len(path)-1]
	interest := param.Classify(name)
	if interest == param.Noise {
		return
	}
	c.mu.Lock()
	c.params = append(c.params, probeTarget{
		URL:      parsed.String(),
		Name:     name,
		Interest: interest,
		JSON:     true,
		JSONPath: path,
	})
	c.mu.Unlock()
}

// addJSONParam records a field mined from a probe response. These arrive after
// the parameter snapshot, so they are probed in a bounded second pass rather
// than being silently dropped.
func (c *collector) addJSONParam(rawURL string, path []string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || len(path) == 0 {
		return
	}
	name := path[len(path)-1]
	interest := param.Classify(name)
	if interest == param.Noise {
		return
	}
	c.mu.Lock()
	c.jsonParams = append(c.jsonParams, probeTarget{
		URL:      parsed.String(),
		Name:     name,
		Interest: interest,
		JSON:     true,
		JSONPath: path,
	})
	c.mu.Unlock()
}

// takeJSONTargets deduplicates and caps the second-pass targets, skipping any
// name already probed on that URL.
func (c *collector) takeJSONTargets(limit int, already map[string]struct{}) []probeTarget {
	c.mu.Lock()
	defer c.mu.Unlock()

	seen := make(map[string]struct{}, len(c.jsonParams))
	targets := make([]probeTarget, 0, len(c.jsonParams))
	for _, target := range c.jsonParams {
		key := probeTargetKey(target)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if _, done := already[key]; done {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
		if limit > 0 && len(targets) >= limit {
			break
		}
	}
	return targets
}

func probeTargetKey(target probeTarget) string {
	return target.Method + "|" + target.URL + "|" + target.Name
}

// crlfEligible limits header-injection probing to parameters whose value is
// likely to reach a response header: high-interest names, redirect sinks and
// JSON-mined fields.
func crlfEligible(target probeTarget) bool {
	if target.JSON {
		return true
	}
	return param.Classify(target.Name) == param.High || redirect.IsRedirectParam(target.Name)
}

// looksLikeAPI decides whether a path is conventionally an API route. It is
// deliberately narrow: a JSON body on an arbitrary page is a guess, while /api
// is the convention the specification names.
func looksLikeAPI(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasPrefix(lower, "/api") || strings.Contains(lower, "/api/")
}

// addParamNames attaches names that have no query string of their own — JSON
// keys and route bindings — to an existing endpoint. jsonCandidate marks a
// target that should also be probed with a JSON body.
func (c *collector) addParamNames(base *url.URL, names []string, jsonCandidate bool) {
	if base == nil || len(names) == 0 {
		return
	}
	targets := make([]probeTarget, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		interest := param.Classify(name)
		if interest == param.Noise {
			continue
		}
		targets = append(targets, probeTarget{
			URL:      base.String(),
			Name:     name,
			Interest: interest,
			JSON:     jsonCandidate,
		})
	}
	if len(targets) == 0 {
		return
	}
	c.mu.Lock()
	c.params = append(c.params, targets...)
	c.mu.Unlock()
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
		key := target.Method + "|" + target.URL + "|" + target.Name
		if _, duplicate := seenParams[key]; duplicate {
			continue
		}
		seenParams[key] = struct{}{}
		params = append(params, target)
	}

	return endpoints, params
}

// addForms registers parameters that only exist inside HTML forms.
//
// A GET form is just a URL, so it joins the query-parameter path with no
// submission and no side effects. A POST form becomes a probe target only when
// the caller opted in, the action stays on the same origin, and the form does
// not look destructive.
func (c *collector) addForms(document []byte, base *url.URL, allowPost bool, limit int) int {
	pending := make([]probeTarget, 0, 8)
	posts := 0

	for _, candidate := range form.Parse(document, base) {
		if candidate.HasFile || !sameOrigin(candidate.Action, base) {
			continue
		}

		if candidate.Method == http.MethodPost {
			if !allowPost || candidate.LooksDestructive() || posts >= limit {
				continue
			}
			posts++
			values := candidate.Values()
			for _, field := range candidate.ProbeFields() {
				pending = append(pending, probeTarget{
					URL:      candidate.Action,
					Name:     field.Name,
					Interest: param.Classify(field.Name),
					Method:   http.MethodPost,
					Fields:   values,
				})
			}
			continue
		}

		parsed, err := url.Parse(candidate.Action)
		if err != nil {
			continue
		}
		query := parsed.Query()
		for _, field := range candidate.ProbeFields() {
			if _, exists := query[field.Name]; !exists {
				query.Set(field.Name, field.Value)
			}
		}
		parsed.RawQuery = query.Encode()
		c.addParams(parsed)
	}

	if len(pending) > 0 {
		c.mu.Lock()
		c.params = append(c.params, pending...)
		c.mu.Unlock()
	}
	return posts
}

// sameOrigin reports whether the action stays on the target host. A POST to a
// third party would be an attack on someone else's system, so it never happens.
func sameOrigin(action string, base *url.URL) bool {
	if base == nil {
		return false
	}
	parsed, err := url.Parse(action)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Host, base.Host)
}

// storagePage is where a submitted value would reappear: the page that received
// it, with the probed parameter removed. Leaving the canary in the query string
// would make the re-fetch echo it and fabricate a stored finding of its own.
func storagePage(rawURL, name, method string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parsed.Fragment = ""
	if !strings.EqualFold(method, http.MethodPost) {
		query := parsed.Query()
		query.Del(name)
		parsed.RawQuery = query.Encode()
		parsed.ForceQuery = false
	}
	return parsed.String()
}

// containsCanary reports whether a body already carries a probe canary, which
// makes it unusable as a stored-detection baseline.
func containsCanary(body []byte) bool {
	text := string(body)
	for _, canary := range reflect.Payloads() {
		if strings.Contains(text, canary) {
			return true
		}
	}
	return false
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
