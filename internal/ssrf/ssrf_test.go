package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 1000, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

func newTestAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	return New(newTestClient(t))
}

func hasSignal(score confidence.Score, name string) bool {
	for _, signal := range score.Signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}

// mustField returns a detail line, failing when the field is missing: every
// finding has to carry enough evidence to be re-checked by hand.
func mustField(t *testing.T, candidate *finding.Finding, name string) string {
	t.Helper()
	for _, field := range candidate.Fields {
		if field.Name == name {
			return field.Value
		}
	}
	t.Fatalf("finding has no %q field: %+v", name, candidate.Fields)
	return ""
}

func TestIsSSRFParamTaxonomy(t *testing.T) {
	for _, name := range []string{
		"url", "uri", "dest", "destination", "target", "webhook", "callback",
		"callback_url", "feed", "feed_url", "api", "proxy", "fetch", "load",
		"document", "link", "endpoint", "next", "return", "return_url",
	} {
		if !IsSSRFParam(name) {
			t.Errorf("%q belongs to the SSRF taxonomy", name)
		}
	}
	for _, name := range []string{"utm_source", "fbclid", "q", "id", "page", "proxy_url", "PROXY_URL"} {
		if IsSSRFParam(name) {
			t.Errorf("%q is not a URL-shaped parameter", name)
		}
	}
	if !IsSSRFParam("  URL ") {
		t.Error("names must be trimmed and case-folded")
	}
}

// TestProbeDetectsNetworkErrorLeak covers the strongest in-band evidence: the
// backend tried to connect and the failure reached the page.
func TestProbeDetectsNetworkErrorLeak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("webhook")
		if strings.Contains(value, "127.0.0.1:65530") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"error":"cURL error 7: Failed to connect to 127.0.0.1 port 65530: Connection refused"}`)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"endpoint":%q}`, value)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/fetch?webhook=https%3A%2F%2Fexample.org%2Fhook",
		Param:   "webhook",
		Method:  http.MethodGet,
	})
	if !ok || candidate == nil {
		t.Fatal("a leaked backend network error produced no finding")
	}
	if candidate.Kind != KindSSRF {
		t.Errorf("Kind = %q, want %q", candidate.Kind, KindSSRF)
	}
	if candidate.RuleID != RuleDifferential {
		t.Errorf("RuleID = %q, want %q", candidate.RuleID, RuleDifferential)
	}
	if candidate.Confidence.Value < 75 {
		t.Fatalf("score = %.1f, want >= 75 (40 base + 35 leak + 10 exact name)", candidate.Confidence.Value)
	}
	if !hasSignal(candidate.Confidence, signalNetworkErrorLeak) {
		t.Errorf("missing %s in the trace: %+v", signalNetworkErrorLeak, candidate.Confidence.Signals)
	}
	for _, name := range []string{"Parameter", "Baseline Latency", "SYN Probe Latency", "Status"} {
		if mustField(t, candidate, name) == "" {
			t.Errorf("field %q is empty", name)
		}
	}
}

// TestProbeGatewayStatusShiftScoresMedium pins the calibration the roadmap calls
// out: a status shift with nothing else behind it is medium, not a finding to
// wake someone for.
func TestProbeGatewayStatusShiftScoresMedium(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "127.0.0.1:65530") {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "<html>502 Bad Gateway</html>")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/proxy?url=https%3A%2F%2Fexample.org%2F&page=2",
		Param:   "url",
	})
	if !ok || candidate == nil {
		t.Fatal("a status shift alone was dropped; it must be returned for --all")
	}
	if candidate.Confidence.Value != 55 {
		t.Fatalf("score = %.1f, want 55 (40 + 15)", candidate.Confidence.Value)
	}
	if candidate.Confidence.Band != confidence.BandMedium {
		t.Errorf("band = %q, want %q", candidate.Confidence.Band, confidence.BandMedium)
	}
	if !hasSignal(candidate.Confidence, signalStatusShift) {
		t.Errorf("missing %s in the trace: %+v", signalStatusShift, candidate.Confidence.Signals)
	}
	if status := mustField(t, candidate, "Status"); !strings.Contains(status, "502") {
		t.Errorf("Status = %q, want the shift towards 502", status)
	}
}

// TestProbeDropsIdenticalResponses is hard gate 2: the parameter is ignored, so
// the module must not spend a report line on it.
func TestProbeDropsIdenticalResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>static dashboard</html>")
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/fetch?url=https%3A%2F%2Fexample.org%2F",
		Param:   "url",
	})
	if ok || candidate != nil {
		t.Fatalf("identical responses were reported: %+v", candidate)
	}
}

// TestProbeIgnoresIrrelevantParameter is hard gate 1, and it must cost the
// target nothing at all.
func TestProbeIgnoresIrrelevantParameter(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/?utm_source=newsletter",
		Param:   "utm_source",
	})
	if ok || candidate != nil {
		t.Fatalf("a tracking parameter was probed: %+v", candidate)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0: the gate must precede the network", got)
	}
}

// TestProbeReportsAsyncSink covers the asynchronous invariant: 202 means the
// fetch left the request path, so a differential cannot see it. Reporting nothing
// would be a false negative, so the module explains itself at low confidence.
func TestProbeReportsAsyncSink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("webhook")
		if strings.Contains(value, "127.0.0.1:65530") || strings.Contains(value, "192.0.2.1") {
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprint(w, `{"status":"queued"}`)
			return
		}
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/hooks?webhook=https%3A%2F%2Fexample.org%2Fhook",
		Param:   "webhook",
	})
	if !ok || candidate == nil {
		t.Fatal("a 202 Accepted probe was reported as safe")
	}
	if candidate.RuleID != RuleAsync {
		t.Errorf("RuleID = %q, want %q", candidate.RuleID, RuleAsync)
	}
	if candidate.Confidence.Value > asyncMaxScore {
		t.Errorf("score = %.1f, want <= %.1f", candidate.Confidence.Value, asyncMaxScore)
	}
	title := strings.ToLower(candidate.Title)
	if !strings.Contains(title, "asynchronous") {
		t.Errorf("title %q does not mention the asynchronous case", candidate.Title)
	}
	if !strings.Contains(title, "queued") {
		t.Errorf("title %q does not mention the queue", candidate.Title)
	}
}

// TestProbeReportsAsyncSinkWhenEveryResponseIs202 is the case a differential
// cannot distinguish: the endpoint queues every job, so the baseline and the
// probe look identical. Dropping it would be the false negative the async rule
// exists to prevent.
func TestProbeReportsAsyncSinkWhenEveryResponseIs202(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"status":"queued"}`)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/hooks?webhook=https%3A%2F%2Fexample.org%2Fhook",
		Param:   "webhook",
	})
	if !ok || candidate == nil {
		t.Fatal("an endpoint that queues every payload was reported as safe")
	}
	if candidate.RuleID != RuleAsync {
		t.Errorf("RuleID = %q, want %q", candidate.RuleID, RuleAsync)
	}
	if candidate.Confidence.Value > asyncMaxScore {
		t.Errorf("score = %.1f, want <= %.1f", candidate.Confidence.Value, asyncMaxScore)
	}
}

// TestProbePenalisesWAFBlock checks that an edge block page is scored as what it
// is: the probe never reached the application. The module still returns the
// result with its honest low score and leaves the filtering to the report.
func TestProbePenalisesWAFBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("url")
		if strings.Contains(value, "127.0.0.1:65530") || strings.Contains(value, "192.0.2.1") {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><title>Attention Required! | Cloudflare</title><body>Request blocked</body></html>")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/fetch?url=https%3A%2F%2Fexample.org%2F",
		Param:   "url",
	})
	if !ok || candidate == nil {
		t.Fatal("the module must return the honest, low score; the report applies the threshold")
	}
	if candidate.Confidence.Value != 20 {
		t.Fatalf("score = %.1f, want 20 (40 - 20 WAF)", candidate.Confidence.Value)
	}
	if candidate.Confidence.Value >= confidence.ThresholdDefault {
		t.Errorf("score = %.1f, want below the default threshold", candidate.Confidence.Value)
	}
	if !hasSignal(candidate.Confidence, signalWAFBlock) {
		t.Errorf("missing %s in the trace: %+v", signalWAFBlock, candidate.Confidence.Signals)
	}
}

// TestProbeDetectsSYNLatencyDifferential lowers LatencyThreshold to 200ms so the
// time-based signal is exercised without a multi-second test.
func TestProbeDetectsSYNLatencyDifferential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("url")
		if strings.Contains(value, "192.0.2.1") {
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Fprintf(w, "fetched %s", value)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	analyzer.LatencyThreshold = 200 * time.Millisecond

	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/fetch?url=https%3A%2F%2Fexample.org%2F",
		Param:   "url",
	})
	if !ok || candidate == nil {
		t.Fatal("a SYN latency differential was dropped")
	}
	if candidate.Confidence.Value != 65 {
		t.Fatalf("score = %.1f, want 65 (40 + 25)", candidate.Confidence.Value)
	}
	if !hasSignal(candidate.Confidence, signalLatencyDelta) {
		t.Errorf("missing %s in the trace: %+v", signalLatencyDelta, candidate.Confidence.Signals)
	}
	if hasSignal(candidate.Confidence, signalErraticLatency) {
		t.Error("the erratic penalty fired although only the SYN probe was slow")
	}
}

// TestProbeIssuesThreeRequestsAndKeepsOtherParams pins the probe budget and the
// promise that the probed value is the only thing that changes.
func TestProbeIssuesThreeRequestsAndKeepsOtherParams(t *testing.T) {
	var mu sync.Mutex
	var queries []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query())
		mu.Unlock()
		if strings.Contains(r.URL.Query().Get("url"), "127.0.0.1:65530") {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "bad gateway")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	if _, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/proxy?url=https%3A%2F%2Fexample.org%2F&lang=de&page=2",
		Param:   "url",
	}); !ok {
		t.Fatal("no finding for a gateway status shift")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 3 {
		t.Fatalf("requests = %d, want exactly 3", len(queries))
	}
	want := []string{"https://example.org/", LoopbackPayload, SYNPayload}
	for i, query := range queries {
		if got := query.Get("url"); got != want[i] {
			t.Errorf("request %d url = %q, want %q", i, got, want[i])
		}
		if query.Get("lang") != "de" || query.Get("page") != "2" {
			t.Errorf("request %d lost a parameter: %v", i, query)
		}
	}
}

// TestProbeDiscountsErraticLatency covers the penalty for the case the roadmap
// warns about: every response is slow, so the SYN delta proves nothing.
func TestProbeDiscountsErraticLatency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("url")
		if strings.Contains(value, "127.0.0.1:65530") || strings.Contains(value, "192.0.2.1") {
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Fprintf(w, "fetched %s", value)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	analyzer.LatencyThreshold = 200 * time.Millisecond

	candidate, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/fetch?url=https%3A%2F%2Fexample.org%2F",
		Param:   "url",
	})
	if !ok || candidate == nil {
		t.Fatal("the honest 40 result should still be returned for --all")
	}
	if candidate.Confidence.Value != 40 {
		t.Fatalf("score = %.1f, want 40 (40 + 25 - 25)", candidate.Confidence.Value)
	}
	if !hasSignal(candidate.Confidence, signalLatencyDelta) || !hasSignal(candidate.Confidence, signalErraticLatency) {
		t.Errorf("missing latency signals: %+v", candidate.Confidence.Signals)
	}
}

// TestProbePOSTParameterTravelsInBody checks the form-field shape: the value has
// to reach the endpoint where a form parameter actually lives.
func TestProbePOSTParameterTravelsInBody(t *testing.T) {
	var mu sync.Mutex
	var bodies, langs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		value := r.PostForm.Get("url")
		mu.Lock()
		bodies = append(bodies, value)
		langs = append(langs, r.URL.Query().Get("lang"))
		mu.Unlock()

		if strings.Contains(value, "127.0.0.1:65530") {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "bad gateway")
			return
		}
		fmt.Fprintf(w, "recv %s", value)
	}))
	defer server.Close()

	analyzer := newTestAnalyzer(t)
	if _, ok := analyzer.Probe(context.Background(), Target{
		BaseURL: server.URL + "/hook?lang=de&url=https%3A%2F%2Fexample.org%2F",
		Param:   "url",
		Method:  http.MethodPost,
	}); !ok {
		t.Fatal("no finding for a POST form field")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("requests = %d, want 3", len(bodies))
	}
	want := []string{"https://example.org/", LoopbackPayload, SYNPayload}
	for i, body := range bodies {
		if body != want[i] {
			t.Errorf("request %d body url = %q, want %q", i, body, want[i])
		}
		if langs[i] != "de" {
			t.Errorf("request %d lost the lang parameter: %q", i, langs[i])
		}
	}
}
