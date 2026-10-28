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

	"solitools/internal/crawl"
	"solitools/internal/errgroup"
	"solitools/internal/finding"
	"solitools/internal/form"
	"solitools/internal/httpx"
	"solitools/internal/js"
	"solitools/internal/param"
	"solitools/internal/pathscan"
	"solitools/internal/redirect"
	"solitools/internal/reflect"
	"solitools/internal/secret"
	"solitools/internal/verify"
	"solitools/internal/waf"
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

	fetched := []fetchedPage{{URL: page.URL, Body: page.Body}}
	if options.EnableCrawl {
		options.reportProgress("crawling links")
		fetched = append(fetched, crawlPages(ctx, options, base, fetched[0], options.MaxPages-1)...)
	}
	result.Stats.Pages = len(fetched)

	collected := &collector{byReason: make(map[string]int), stored: make(map[string][]reflect.Submission), notify: options.Notify}
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
		collected.addEndpoints(js.ExtractEndpoints(current.Body, currentBase))
		collected.addParams(currentBase)

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

			// Endpoints discovered inside a bundle may themselves carry
			// parameters, but only those on the script's own origin are useful.
			if parsed, err := url.Parse(scriptURL); err == nil {
				collected.addEndpoints(js.ExtractEndpoints(response.Body, parsed))
				collected.addParams(parsed)
			}
			return nil
		})
	}
	_ = group.Wait()

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
	options.reportProgress("probing parameters")

	// Watch probe responses for block pages. The observer is scoped to this
	// stage: path scanning later must not count toward the probe streak.
	watcher := &blockWatcher{}
	options.Client.SetObserver(watcher.observe)

	probeGroup, probeCtx := errgroup.WithContext(ctx)
	probeGroup.SetLimit(4)
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
			if redirect.IsRedirectParam(probe.Name) {
				redirected, ok := redirectAnalyzer.Probe(probeCtx, redirect.Target{
					URL: probe.URL, Name: probe.Name, Interest: probe.Interest,
					Method: probe.Method, Fields: probe.Fields,
				})
				if ok {
					collected.addFinding(redirected)
				}
			}
			return nil
		})
	}
	_ = probeGroup.Wait()
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
	URL  string
	Body []byte
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
			pages = append(pages, fetchedPage{URL: link, Body: response.Body})
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
	stored   map[string][]reflect.Submission
	notify   func(finding.Finding)
	gated    int
	byReason map[string]int
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
