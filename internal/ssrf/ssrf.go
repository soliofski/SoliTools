// Package ssrf detects server-side request forgery from the outside, in band.
//
// The usual SSRF test needs an out-of-band listener: point a parameter at a host
// you control and wait for the callback. SoliTools forbids that — every request
// must go to the target and nowhere else — so this module looks for the traces a
// server leaves when it does fetch, without asking a third party to observe
// anything:
//
//   - a leaked backend network error ("cURL error 7", "ECONNREFUSED") in the
//     response body;
//   - a gateway status shift (502/504) the baseline did not have;
//   - a wall-clock differential against an RFC 5737 address, where a dropped SYN
//     ends in the OS connect timeout;
//   - a Location header that sends the client back to the probe host.
//
// The loopback payload targets 127.0.0.1:65530, a high unassigned port, so the
// kernel refuses the connection immediately and no service is touched. The
// latency payload targets 192.0.2.1 (TEST-NET-1), reserved for documentation, so
// routers discard it instead of delivering it. Neither payload is dialled by this
// tool: they are values handed to the target, which is what the tool is testing.
//
// Probe volume is fixed at three requests per parameter — baseline, loopback,
// SYN — so the module can run against a production endpoint without becoming a
// load test.
package ssrf

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

const (
	// KindSSRF labels every finding this module returns. internal/finding has no
	// SSRF constant and a detector must not edit the shared model package, so the
	// label is declared here with the same underlying type. Its value is what the
	// report, JSON and SARIF outputs show.
	KindSSRF finding.Kind = "SSRF"

	// categoryName is the vulnerability class shared by both rule IDs.
	categoryName = "Server-Side Request Forgery"

	// RuleDifferential is a scored differential heuristic result.
	RuleDifferential = "ssrf.differential.heuristic"
	// RuleAsync is an informative result: the target accepted the payload for
	// later processing, which a response differential cannot prove.
	RuleAsync = "ssrf.async-sink"
)

const (
	// LoopbackPayload targets a high unassigned port on the loopback interface.
	// A refused connection is immediate, so a difference between this and the
	// baseline cannot be explained by network latency.
	LoopbackPayload = "http://127.0.0.1:65530/soli-probe"

	// SYNPayload targets TEST-NET-1 (RFC 5737), reserved for documentation:
	// packets are discarded, so a server-side connect attempt ends in its own SYN
	// timeout. A slow answer here is the time-based signature.
	SYNPayload = "http://192.0.2.1/soli-probe"

	// DefaultLatencyThreshold is the wall-clock delta that counts as a SYN
	// timeout signature. OS connect timeouts land between 3s and 10s.
	DefaultLatencyThreshold = 3 * time.Second

	// synProbeTimeout bounds the latency probe. A target that swallows the
	// connection could otherwise stall a scan for the client's whole timeout; the
	// measurement is wall-clock, so the cut-off still yields a usable delta.
	synProbeTimeout = 6 * time.Second

	// baseConfidence is the score of "this endpoint has a URL-shaped parameter".
	baseConfidence = 40.0

	// asyncMaxScore caps the informative asynchronous finding. 202 Accepted means
	// the fetch left the request path — a sink, not proof — so the result must stay
	// below the default threshold whatever else is true of it.
	asyncMaxScore = 55.0
)

// Signal identifiers, spelled exactly as the roadmap derives them so a score can
// be reconstructed from the report.
const (
	signalNetworkErrorLeak = "signal.backend-network-error-leak"
	signalLatencyDelta     = "signal.time-differential-syn-timeout"
	signalStatusShift      = "signal.gateway-status-shift"
	signalHighInterest     = "signal.high-interest-exact-name"
	signalReflection       = "signal.header-reflection-redirect"
	signalWAFBlock         = "signal.generic-waf-block"
	signalErraticLatency   = "signal.erratic-baseline-latency"
	signalNotFound         = "signal.status-404-not-found"
	signalAsyncAccepted    = "signal.async-accepted"
)

var (
	// rxNetworkErrors matches the network error strings that backend stacks and
	// HTTP libraries leak into response bodies. Every alternative is a phrase a
	// developer would recognise in a log, which is what makes a match evidence: a
	// generic "error" would match every page ever rendered.
	rxNetworkErrors = regexp.MustCompile(`(?i)(` + strings.Join([]string{
		`cURL error (?:7|28|6)`,
		`Failed to connect to`,
		`Connection refused`,
		`ECONNREFUSED`,
		`java\.net\.ConnectException`,
		`java\.net\.SocketTimeoutException`,
		`getaddrinfo ENOTFOUND`,
		`getaddrinfo EAI_AGAIN`,
		`No route to host`,
		`Network is unreachable`,
		`urllib\.error\.URLError`,
		`requests\.exceptions\.ConnectionError`,
		`dial tcp (?:127\.0\.0\.1|192\.0\.2\.1)`,
	}, "|") + `)`)

	// ssrfParams is the hard gate. These names contractually carry a URL or a
	// host, the only places where a differential is worth three requests. Anything
	// else returns before a packet is sent, which also keeps noise parameters
	// (utm_*, fbclid) from costing the target anything.
	ssrfParams = map[string]struct{}{
		"url": {}, "uri": {}, "dest": {}, "destination": {}, "target": {},
		"webhook": {}, "callback": {}, "callback_url": {}, "feed": {}, "feed_url": {},
		"api": {}, "proxy": {}, "fetch": {}, "load": {}, "document": {}, "link": {},
		"endpoint": {}, "next": {}, "return": {}, "return_url": {},
	}

	// highInterest are the names that receive a fully qualified URL by
	// convention, so their verdict is worth more than a generic "url". The
	// roadmap also lists proxy_url here; the taxonomy above does not contain it,
	// so that entry only matters if the gate is ever widened.
	highInterest = map[string]struct{}{
		"webhook": {}, "callback_url": {}, "proxy_url": {}, "feed_url": {},
	}

	// wafStatuses are the edge statuses worth inspecting for a block page.
	wafStatuses = map[int]struct{}{
		http.StatusForbidden:          {},
		http.StatusNotAcceptable:      {},
		http.StatusTooManyRequests:    {},
		http.StatusServiceUnavailable: {},
	}

	// wafBodySignatures are vendor or product strings that identify an edge block
	// page. Status alone never counts: a 403 from the application means the
	// parameter was rejected, which says nothing about the network.
	wafBodySignatures = []string{
		"cloudflare",
		"cf-error-details",
		"attention required",
		"akamai",
		"reference #",
		"the requested url was rejected",
		"incapsula",
		"sucuri website firewall",
		"mod_security",
		"modsecurity",
		"web application firewall",
		"request blocked",
	}

	// wafServers are edge vendors recognised by header when the body is opaque.
	wafServers = []string{"cloudflare", "akamai", "incapsula", "sucuri", "big-ip", "barracuda"}

	// loopbackHost and synHost are the hosts a reflected Location header would
	// have to mention to prove the server redirected to our own probe.
	loopbackHost = hostOf(LoopbackPayload)
	synHost      = hostOf(SYNPayload)
)

// Target is one parameter to test.
//
// BaseURL is the endpoint with its original parameters; Method is empty or GET
// for a query parameter and POST for a form field. A POST target keeps its other
// parameters in the query: the probed field moves to the form body, everything
// else stays where the caller put it.
type Target struct {
	BaseURL string
	Param   string
	Method  string
}

// Analyzer probes SSRF-shaped parameters through a shared client.
//
// It is safe for concurrent use: it holds no state between probes.
type Analyzer struct {
	client *httpx.Client

	// LatencyThreshold is the wall-clock gap between the baseline and the SYN
	// probe that counts as a server-side connect timeout. Zero selects
	// DefaultLatencyThreshold; tests lower it so they do not have to wait
	// seconds to exercise the signal.
	LatencyThreshold time.Duration
}

// New builds an Analyzer. A nil client makes Probe a no-op.
func New(client *httpx.Client) *Analyzer {
	return &Analyzer{client: client, LatencyThreshold: DefaultLatencyThreshold}
}

// IsSSRFParam reports whether name is in the SSRF parameter taxonomy.
//
// It is exported because the scan pipeline ranks parameters before it builds a
// Target, and asking the module is cheaper than duplicating the list.
func IsSSRFParam(name string) bool {
	_, ok := ssrfParams[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// Probe measures one parameter.
//
// It issues exactly three requests — the original URL, the loopback payload and
// the RFC 5737 payload — and preserves every other query parameter on all three,
// so the probed value is the only variable.
//
// Only the two hard gates suppress a result outright: a parameter outside the
// taxonomy, and a loopback response identical to the baseline. The second yields
// to a 202 Accepted probe, which becomes an informative asynchronous sink because
// a queued fetch leaves nothing to compare. Everything else is returned with an
// honest score even below confidence.ThresholdDefault: the report applies the
// threshold, and --all needs the weak evidence together with its signal trace.
func (a *Analyzer) Probe(ctx context.Context, target Target) (*finding.Finding, bool) {
	if a == nil || a.client == nil || !IsSSRFParam(target.Param) {
		return nil, false
	}
	baseURL := strings.TrimSpace(target.BaseURL)
	param := strings.TrimSpace(target.Param)
	if baseURL == "" || param == "" {
		return nil, false
	}
	name := strings.ToLower(param)

	// 1. Baseline: the request as given, byte for byte.
	baselineRequest, err := requestFor(baseURL, target.Method, param, "", false)
	if err != nil {
		return nil, false
	}
	started := time.Now()
	baseline, err := a.send(ctx, baselineRequest)
	baselineLatency := time.Since(started)
	if err != nil || baseline == nil {
		// A target that will not answer its own URL cannot be probed for a
		// difference: there is no reference point.
		return nil, false
	}

	// 2. Loopback: an immediate RST, so any divergence is the target reacting to
	// the value rather than to time. A transport error here leaves nothing to
	// read, and the next probe may still carry a signal.
	loopbackRequest, err := requestFor(baseURL, target.Method, param, LoopbackPayload, true)
	if err != nil {
		return nil, false
	}
	started = time.Now()
	loopback, _ := a.send(ctx, loopbackRequest)
	loopbackLatency := time.Since(started)

	// 3. SYN: bounded on its own so a target that holds the connection open
	// cannot stall the scan. The deadline cuts the wait, and the wall clock still
	// records how long the target kept us.
	synRequest, err := requestFor(baseURL, target.Method, param, SYNPayload, true)
	if err != nil {
		return nil, false
	}
	synCtx, cancel := context.WithTimeout(ctx, synProbeTimeout)
	defer cancel()
	started = time.Now()
	syn, _ := a.send(synCtx, synRequest)
	synLatency := time.Since(started)

	builder := confidence.New(baseConfidence)

	leaked := firstLeak(loopback, syn)
	if leaked != "" {
		builder.Add(signalNetworkErrorLeak, 35,
			fmt.Sprintf("the response body leaked a backend network error: %s", leaked))
	}

	from, to, shifted := gatewayShift(baseline, loopback, syn)
	if shifted {
		builder.Add(signalStatusShift, 15,
			fmt.Sprintf("status shifted from %d to %d, the shape of a gateway failing to reach an upstream", from, to))
	}

	if _, ok := highInterest[name]; ok {
		builder.Add(signalHighInterest, 10,
			fmt.Sprintf("%q is a name that conventionally carries a fully qualified URL", param))
	}

	location, reflected := probeReflection(loopback, syn)
	if reflected {
		builder.Add(signalReflection, 15,
			fmt.Sprintf("the Location header points at the probe host: %s", location))
	}

	threshold := a.LatencyThreshold
	if threshold <= 0 {
		threshold = DefaultLatencyThreshold
	}
	latencyDelta := synLatency - baselineLatency
	slowProbe := latencyDelta > threshold
	if slowProbe {
		builder.Add(signalLatencyDelta, 25,
			fmt.Sprintf("the SYN probe was %s slower than the baseline (threshold %s), the signature of a server-side connect timeout",
				roundMs(latencyDelta), threshold))
		// A loopback value cannot make the target wait for the network, so a
		// loopback that is equally slow means the server's own timing wanders and
		// the SYN delta is not attributable to the payload. This is the measurable
		// stand-in for the roadmap's erratic-baseline penalty: true variance needs
		// a fourth request and the budget is three.
		if loopbackDelta := loopbackLatency - baselineLatency; loopbackDelta > threshold {
			builder.Add(signalErraticLatency, -25,
				fmt.Sprintf("the loopback probe was also %s slower than the baseline, so latency is unstable and the SYN delta is not attributable to the payload",
					roundMs(loopbackDelta)))
		}
	}

	wafVendor := wafBlock(loopback, syn, baseline)
	if wafVendor != "" {
		builder.Add(signalWAFBlock, -20,
			fmt.Sprintf("the probe was answered by a %s block page, not by backend fetch logic", wafVendor))
	}

	if notFoundOnly(baseline, loopback, syn) {
		builder.Add(signalNotFound, -15,
			"the probe returned 404 without a structural change or a network diagnostic")
	}

	// 202 Accepted takes the fetch out of the request path, where no differential
	// can see it. When nothing stronger was observed, say so rather than return
	// nothing and imply the parameter is safe.
	networkEvidence := leaked != "" || shifted || reflected || slowProbe
	if !networkEvidence && wafVendor == "" && asyncAccepted(loopback, syn) {
		return asyncFinding(baseURL, param, baseline, loopback, syn, baselineLatency, synLatency), true
	}

	// Hard gate: the loopback value produced the baseline's exact status and
	// body, so the parameter never reached fetch logic. The comparison is
	// deliberately bit-for-bit — a handler that echoes the value changes the body
	// and is not identical.
	//
	// The asynchronous branch runs first on purpose: a target that queues every job
	// answers 202 with the same body for the baseline and for the probe, and that
	// identical pair is exactly the false negative the 202 path exists to report.
	// What it emits is capped below the default threshold, so the gate still keeps
	// inert parameters out of the default report.
	if loopback != nil && loopback.Status == baseline.Status && bytes.Equal(loopback.Body, baseline.Body) {
		return nil, false
	}

	score := builder.Build()
	candidate := finding.Finding{
		Kind:       KindSSRF,
		Category:   categoryName,
		RuleID:     RuleDifferential,
		Title:      fmt.Sprintf("SSRF Parameter Differential (%s)", score.Band),
		URL:        baseURL,
		Value:      param,
		Context:    strongestEvidence(score),
		Confidence: score,
	}
	candidate.WithField("Parameter", param)
	candidate.WithField("Baseline Latency", roundMs(baselineLatency))
	candidate.WithField("SYN Probe Latency", roundMs(synLatency))
	candidate.WithField("Status", statusSummary(baseline, loopback, syn))
	return &candidate, true
}

// probeRequest is one of the three requests. A non-nil form selects a form POST;
// a nil form selects a GET with the parameter in the query.
type probeRequest struct {
	url  string
	form url.Values
}

// send issues the request. It is the only place that picks a verb.
func (a *Analyzer) send(ctx context.Context, request probeRequest) (*httpx.Response, error) {
	if request.form != nil {
		return a.client.PostForm(ctx, request.url, request.form)
	}
	return a.client.Get(ctx, request.url)
}

// requestFor builds a probe request, preserving every other parameter.
//
// override=false reproduces the target's own request unchanged, which is what
// makes the baseline a real reference. override=true replaces only the probed
// value: in the query for a GET, in the form body for a POST, where a form field
// actually travels.
func requestFor(baseURL, method, param, value string, override bool) (probeRequest, error) {
	if !strings.EqualFold(strings.TrimSpace(method), http.MethodPost) {
		if !override {
			return probeRequest{url: baseURL}, nil
		}
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return probeRequest{}, err
		}
		query := parsed.Query()
		query.Set(param, value)
		parsed.RawQuery = query.Encode()
		return probeRequest{url: parsed.String()}, nil
	}

	// A POST parameter is a form field, so it moves to the body and the parameter
	// is removed from the query: exactly one value is in play, and the endpoint
	// reads it where it expects it. Every other query parameter stays put.
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return probeRequest{}, err
	}
	query := parsed.Query()
	original := query.Get(param)
	if query.Has(param) {
		query.Del(param)
		parsed.RawQuery = query.Encode()
	}
	form := make(url.Values, 1)
	switch {
	case override:
		form.Set(param, value)
	case original != "":
		form.Set(param, original)
	}
	return probeRequest{url: parsed.String(), form: form}, nil
}

// asyncFinding builds the informative result for a 202 Accepted probe.
//
// The score is capped at asyncMaxScore by construction — a high-interest name
// plus two accepted probes is 55 — and the clamp below makes that a guarantee
// rather than an arithmetic coincidence.
func asyncFinding(baseURL, param string, baseline, loopback, syn *httpx.Response, baselineLatency, synLatency time.Duration) *finding.Finding {
	builder := confidence.New(baseConfidence)
	if _, ok := highInterest[strings.ToLower(param)]; ok {
		builder.Add(signalHighInterest, 10,
			fmt.Sprintf("%q is a name that conventionally carries a fully qualified URL", param))
	}
	if loopback != nil && syn != nil && loopback.Status == http.StatusAccepted && syn.Status == http.StatusAccepted {
		builder.Add(signalAsyncAccepted, 5,
			"both probe payloads were accepted with 202, so the parameter is consistently treated as a job")
	}
	score := builder.Build()
	if score.Value > asyncMaxScore {
		score.Value = asyncMaxScore
		score.Band = confidence.BandOf(score.Value)
	}

	candidate := finding.Finding{
		Kind:     KindSSRF,
		Category: categoryName,
		RuleID:   RuleAsync,
		Title:    fmt.Sprintf("Potential Asynchronous SSRF Sink (%s; probe accepted with 202 and queued)", score.Band),
		URL:      baseURL,
		Value:    param,
		Context: fmt.Sprintf("parameter %q answered 202 Accepted to a probe URL: the fetch may happen after the response, "+
			"in a queue or a background job, where a response differential cannot observe it", param),
		Confidence: score,
	}
	candidate.WithField("Parameter", param)
	candidate.WithField("Baseline Latency", roundMs(baselineLatency))
	candidate.WithField("SYN Probe Latency", roundMs(synLatency))
	candidate.WithField("Status", statusSummary(baseline, loopback, syn))
	return &candidate
}

// firstLeak returns the first backend network error visible in a probe body.
func firstLeak(responses ...*httpx.Response) string {
	for _, response := range responses {
		if response == nil {
			continue
		}
		if match := rxNetworkErrors.FindString(response.BodyString()); match != "" {
			return match
		}
	}
	return ""
}

// gatewayShift reports the first probe answered like a gateway giving up, and the
// status it moved away from.
func gatewayShift(baseline *httpx.Response, responses ...*httpx.Response) (int, int, bool) {
	for _, response := range responses {
		if response == nil || response.Status == baseline.Status {
			continue
		}
		if response.Status == http.StatusBadGateway || response.Status == http.StatusGatewayTimeout {
			return baseline.Status, response.Status, true
		}
	}
	return 0, 0, false
}

// probeReflection reports a Location header that points back at a probe host.
//
// This is the observable half of gateway header ingestion: a proxy or router that
// echoes the forwarded host into its own redirect is telling us the value reached
// URL-building logic. A payload echoed in the body is not counted — that is the
// reflection false positive this module must not repeat.
func probeReflection(responses ...*httpx.Response) (string, bool) {
	for _, response := range responses {
		if response == nil {
			continue
		}
		location := strings.TrimSpace(response.Location())
		if location == "" {
			continue
		}
		lower := strings.ToLower(location)
		if (loopbackHost != "" && strings.Contains(lower, loopbackHost)) ||
			(synHost != "" && strings.Contains(lower, synHost)) {
			return location, true
		}
	}
	return "", false
}

// wafBlock reports the vendor signature when a response is an edge block page.
//
// A 403 from the application and a 403 from the edge mean opposite things for
// this module, so status alone is never enough: a body signature or a known edge
// vendor in the Server header has to agree with it.
func wafBlock(responses ...*httpx.Response) string {
	for _, response := range responses {
		if response == nil {
			continue
		}
		if _, ok := wafStatuses[response.Status]; !ok {
			continue
		}
		body := strings.ToLower(response.BodyString())
		for _, signature := range wafBodySignatures {
			if strings.Contains(body, signature) {
				return signature
			}
		}
		server := strings.ToLower(response.Header.Get("Server") + " " + response.Header.Get("X-Powered-By"))
		for _, signature := range wafServers {
			if strings.Contains(server, signature) {
				return signature
			}
		}
	}
	return ""
}

// asyncAccepted reports whether a probe answered 202.
func asyncAccepted(responses ...*httpx.Response) bool {
	for _, response := range responses {
		if response != nil && response.Status == http.StatusAccepted {
			return true
		}
	}
	return false
}

// notFoundOnly reports a probe that 404s where the baseline did not.
func notFoundOnly(baseline *httpx.Response, responses ...*httpx.Response) bool {
	if baseline.Status == http.StatusNotFound {
		return false
	}
	for _, response := range responses {
		if response != nil && response.Status == http.StatusNotFound {
			return true
		}
	}
	return false
}

// strongestEvidence names the largest positive signal, so the finding's context
// line says why it exists and not merely that it does.
func strongestEvidence(score confidence.Score) string {
	reason := ""
	strongest := 0.0
	for _, signal := range score.Signals {
		if signal.Delta > strongest {
			reason, strongest = signal.Reason, signal.Delta
		}
	}
	if reason == "" {
		return "the probe response diverged from the baseline without a network diagnostic"
	}
	return reason
}

// statusSummary renders the three statuses. A request that never completed is
// reported as such rather than as a zero, because "failed" is not a status.
func statusSummary(baseline, loopback, syn *httpx.Response) string {
	return fmt.Sprintf("baseline %s, loopback %s, SYN %s",
		statusText(baseline), statusText(loopback), statusText(syn))
}

func statusText(response *httpx.Response) string {
	if response == nil {
		return "no response"
	}
	return fmt.Sprintf("%d", response.Status)
}

// roundMs formats a duration at millisecond resolution: microsecond noise is an
// artefact of the client, not a property of the target.
func roundMs(d time.Duration) string { return d.Round(time.Millisecond).String() }

// hostOf returns the host:port of an absolute URL, or "" when it does not parse.
func hostOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
}
