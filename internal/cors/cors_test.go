package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

// fieldValue returns the value of a named detail line, or "" when absent.
func fieldValue(f *finding.Finding, name string) string {
	for _, field := range f.Fields {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

// signalDelta returns the delta recorded for a named signal.
func signalDelta(f *finding.Finding, name string) (float64, bool) {
	for _, signal := range f.Confidence.Signals {
		if signal.Name == name {
			return signal.Delta, true
		}
	}
	return 0, false
}

// reflectingServer echoes the arbitrary canary origin with
// Access-Control-Allow-Credentials: true, then lets prepare shape the rest of
// the response. It stands in for a backend that reflects whatever Origin it is
// given.
func reflectingServer(t *testing.T, prepare func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if strings.HasPrefix(origin, "https://soli-") && strings.HasSuffix(origin, ".invalid") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if prepare != nil {
			prepare(w)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestProbeCredentialedArbitraryOriginReflection covers the worst case: a
// backend echoes an origin the site cannot allowlist and sends credentials.
func TestProbeCredentialedArbitraryOriginReflection(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user_id":"u-42","email":"victim@example.test"}`))
	})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/me", IsAPI: true})
	if !ok {
		t.Fatal("a credentialed arbitrary-origin reflection must be reported")
	}
	if f.Confidence.Value < 85 {
		t.Fatalf("confidence = %v, want 85 or more for a credentialed reflection", f.Confidence.Value)
	}
	if f.Confidence.Value != 100 {
		t.Fatalf("confidence = %v, want 65 base + 20 reflection + 15 sensitive JSON", f.Confidence.Value)
	}
	if !strings.HasPrefix(f.Value, "https://soli-") || !strings.HasSuffix(f.Value, ".invalid") {
		t.Fatalf("value = %q, want the reflected canary origin", f.Value)
	}
	if f.Kind != kindCORS || f.Category != "CORS Misconfiguration" || f.RuleID != "cors.misconfiguration" {
		t.Fatalf("kind/category/rule = %q/%q/%q", f.Kind, f.Category, f.RuleID)
	}
	if f.URL != server.URL+"/api/me" {
		t.Fatalf("url = %q, want the probed target", f.URL)
	}
	if got := fieldValue(f, "ACAO"); got != f.Value {
		t.Fatalf("field ACAO = %q, want %q", got, f.Value)
	}
	if got := fieldValue(f, "ACAC"); got != "true" {
		t.Fatalf("field ACAC = %q, want \"true\"", got)
	}
	if got := fieldValue(f, "Status"); got != "200" {
		t.Fatalf("field Status = %q, want \"200\"", got)
	}
	if got := fieldValue(f, "ProbeType"); got != probeArbitrary {
		t.Fatalf("field ProbeType = %q, want %q", got, probeArbitrary)
	}

	delta, found := signalDelta(f, "arbitrary-origin-reflected")
	if !found {
		t.Fatalf("arbitrary-origin-reflected missing from %+v", f.Confidence.Signals)
	}
	if delta != 20 {
		t.Fatalf("arbitrary-origin-reflected = %v, want 20 when credentialed", delta)
	}
	delta, found = signalDelta(f, "sensitive-api-data")
	if !found || delta != 15 {
		t.Fatalf("sensitive-api-data = %v (found %t), want 15", delta, found)
	}
	if _, found := signalDelta(f, "auth-cookies-present"); found {
		t.Fatal("an anonymous scan must not claim authentication evidence")
	}
}

// TestProbeUncredentialedReflectionIsReturned pins the deliberate deviation: a
// medium score is returned with its honest value instead of being suppressed
// inside the module.
func TestProbeUncredentialedReflectionIsReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/items"})
	if !ok {
		t.Fatal("an uncredentialed reflection must still be returned for -all")
	}
	if f.Confidence.Value >= confidence.ThresholdDefault {
		t.Fatalf("confidence = %v, want below the default threshold of %v", f.Confidence.Value, confidence.ThresholdDefault)
	}
	if f.Confidence.Value != 40 {
		t.Fatalf("confidence = %v, want 25 base + 15 reflection", f.Confidence.Value)
	}
	if f.Confidence.Band != confidence.BandMedium {
		t.Fatalf("band = %q, want %q", f.Confidence.Band, confidence.BandMedium)
	}
	if delta, found := signalDelta(f, "arbitrary-origin-reflected"); !found || delta != 15 {
		t.Fatalf("arbitrary-origin-reflected = %v (found %t), want 15", delta, found)
	}
	if got := fieldValue(f, "ACAC"); got != "false" {
		t.Fatalf("field ACAC = %q, want \"false\"", got)
	}
}

func TestProbeNullOriginTrust(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/null"})
	if !ok {
		t.Fatal("a trusted null origin must be reported even though the other variants were refused")
	}
	if f.Value != "null" {
		t.Fatalf("value = %q, want \"null\"", f.Value)
	}
	if got := fieldValue(f, "ProbeType"); got != probeNull {
		t.Fatalf("ProbeType = %q, want %q", got, probeNull)
	}
	if f.Confidence.Value != 75 {
		t.Fatalf("confidence = %v, want 65 base + 10 null origin", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "null-origin-trusted"); !found || delta != 10 {
		t.Fatalf("null-origin-trusted = %v (found %t), want 10", delta, found)
	}
}

// TestProbeNullOriginWithoutCredentialsScoresLow keeps the lowest honest score
// visible: the null probe was accepted, but without credentials the finding is
// only worth -all.
func TestProbeNullOriginWithoutCredentialsScoresLow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/null"})
	if !ok {
		t.Fatal("an accepted null origin must be returned even at a low score")
	}
	if f.Confidence.Value != 25 {
		t.Fatalf("confidence = %v, want the 25 uncredentialed base with no signal", f.Confidence.Value)
	}
	if f.Confidence.Band != confidence.BandLow {
		t.Fatalf("band = %q, want %q", f.Confidence.Band, confidence.BandLow)
	}
	if _, found := signalDelta(f, "null-origin-trusted"); found {
		t.Fatal("null trust without credentials must not claim the credentialed signal")
	}
}

// TestProbeSuffixBypass emulates the classic unescaped-regex check that accepts
// any origin beginning with the target host.
func TestProbeSuffixBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if strings.HasPrefix(origin, "https://127.0.0.1.") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/suffix"})
	if !ok {
		t.Fatal("a suffix bypass must be reported")
	}
	if got := fieldValue(f, "ProbeType"); got != probeSuffix {
		t.Fatalf("ProbeType = %q, want %q", got, probeSuffix)
	}
	if !strings.HasSuffix(f.Value, ".soli-canary.invalid") {
		t.Fatalf("value = %q, want the suffix canary origin", f.Value)
	}
	if f.Confidence.Value != 80 {
		t.Fatalf("confidence = %v, want 65 base + 15 suffix bypass", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "regex-suffix-bypass"); !found || delta != 15 {
		t.Fatalf("regex-suffix-bypass = %v (found %t), want 15", delta, found)
	}
}

func TestProbeSubdomainTrust(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if strings.HasSuffix(origin, ".127.0.0.1") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/sub"})
	if !ok {
		t.Fatal("a subdomain wildcard must be reported")
	}
	if got := fieldValue(f, "ProbeType"); got != probeSubdomain {
		t.Fatalf("ProbeType = %q, want %q", got, probeSubdomain)
	}
	if f.Value != "https://soli-check.127.0.0.1" {
		t.Fatalf("value = %q, want the subdomain canary origin", f.Value)
	}
	if f.Confidence.Value != 75 {
		t.Fatalf("confidence = %v, want 65 base + 10 subdomain trust", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "subdomain-wildcard-trust"); !found || delta != 10 {
		t.Fatalf("subdomain-wildcard-trust = %v (found %t), want 10", delta, found)
	}
}

func TestProbeDropsWildcardWithCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every browser engine rejects this pairing, so it cannot be exploited.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte(`{"email":"victim@example.test"}`))
	}))
	t.Cleanup(server.Close)

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/me"}); ok {
		t.Fatal("ACAO * with ACAC true is browser-rejected and must be dropped")
	}
}

func TestProbeDropsStaticAssetReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Write([]byte("body{}"))
	}))
	t.Cleanup(server.Close)

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/assets/app.js"}); ok {
		t.Fatal("an uncredentialed reflection on a static asset is noise")
	}
	if _, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/api/app"}); !ok {
		t.Fatal("the same reflection on a dynamic endpoint must be returned")
	}
}

// TestProbeKeepsCredentialedStaticAssetReflection pins the scope of the asset
// gate: only an anonymous reflection on an asset is noise, because a
// credentialed one is still readable by another origin.
func TestProbeKeepsCredentialedStaticAssetReflection(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {
		w.Write([]byte("console.log('app')"))
	})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/assets/app.js"})
	if !ok {
		t.Fatal("a credentialed reflection on an asset must be reported")
	}
	if f.Confidence.Value != 85 {
		t.Fatalf("confidence = %v, want 65 base + 20 reflection", f.Confidence.Value)
	}
}

func TestProbeUncredentialedErrorStatusIsDropped(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		credentialed bool
		want         bool
		wantScore    float64
	}{
		{"404 anonymous", http.StatusNotFound, false, false, 0},
		{"500 anonymous", http.StatusInternalServerError, false, false, 0},
		{"500 credentialed", http.StatusInternalServerError, true, true, 55},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				if tc.credentialed {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(`{"error":"boom"}`))
			}))
			t.Cleanup(server.Close)

			f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/thing"})
			if ok != tc.want {
				t.Fatalf("ok = %t, want %t", ok, tc.want)
			}
			if !tc.want {
				return
			}
			if f.Confidence.Value != tc.wantScore {
				t.Fatalf("confidence = %v, want %v (65 + 20 - 30)", f.Confidence.Value, tc.wantScore)
			}
			if delta, found := signalDelta(f, "error-status"); !found || delta != -30 {
				t.Fatalf("error-status = %v (found %t), want -30", delta, found)
			}
		})
	}
}

func TestProbeSensitiveJSONSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Write([]byte(`{"balance":1042.55,"currency":"EUR"}`))
	}))
	t.Cleanup(server.Close)

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/wallet"})
	if !ok {
		t.Fatal("an uncredentialed reflection on a sensitive API must be returned for -all")
	}
	if f.Confidence.Value != 55 {
		t.Fatalf("confidence = %v, want 25 base + 15 reflection + 15 sensitive JSON", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "sensitive-api-data"); !found || delta != 15 {
		t.Fatalf("sensitive-api-data = %v (found %t), want 15", delta, found)
	}
}

func TestProbeIgnoresBodyWithoutCORSHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Origin: " + r.Header.Get("Origin")))
	}))
	t.Cleanup(server.Close)

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL}); ok {
		t.Fatal("an echoed origin in the body is not a CORS policy")
	}
}

// TestProbeIgnoresFixedAllowlistOrigin keeps a legitimate configuration from
// being reported: the canary origin was refused, so nothing was gained.
func TestProbeIgnoresFixedAllowlistOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.test")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte(`{"email":"victim@example.test"}`))
	}))
	t.Cleanup(server.Close)

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/me"}); ok {
		t.Fatal("a fixed allowlist entry is not a reflection")
	}
}

func TestProbeSendsFourCanaryOrigins(t *testing.T) {
	var mu sync.Mutex
	var origins []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		origins = append(origins, r.Header.Get("Origin"))
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL}); ok {
		t.Fatal("a response without Access-Control-Allow-Origin is not a finding")
	}

	mu.Lock()
	got := append([]string(nil), origins...)
	mu.Unlock()
	if len(got) != 4 {
		t.Fatalf("probes = %d %v, want the four-request budget", len(got), got)
	}

	arbitrary := 0
	others := make(map[string]int, 3)
	for _, origin := range got {
		if isArbitraryCanary(origin) {
			arbitrary++
			continue
		}
		others[origin]++
	}
	if arbitrary != 1 {
		t.Fatalf("arbitrary canary sent %d times, want exactly once (probes: %v)", arbitrary, got)
	}
	for _, origin := range []string{"null", "https://127.0.0.1.soli-canary.invalid", "https://soli-check.127.0.0.1"} {
		if others[origin] != 1 {
			t.Fatalf("Origin %q probed %d times, want once (probes: %v)", origin, others[origin], got)
		}
	}
	if len(others) != 3 {
		t.Fatalf("unexpected extra origins: %v", got)
	}
}

func isArbitraryCanary(origin string) bool {
	const prefix, suffix = "https://soli-", ".invalid"
	if !strings.HasPrefix(origin, prefix) || !strings.HasSuffix(origin, suffix) {
		return false
	}
	id := origin[len(prefix) : len(origin)-len(suffix)]
	if len(id) != 8 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// TestProbePenalizesCacheableResponse checks that doubts lower the score and
// stay visible in the audit trail instead of suppressing the finding.
func TestProbePenalizesCacheableResponse(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write([]byte(`{"ok":true}`))
	})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/thing"})
	if !ok {
		t.Fatal("a penalised reflection must still be returned for -all")
	}
	if f.Confidence.Value != 70 {
		t.Fatalf("confidence = %v, want 65 + 20 - 15", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "public-cacheable"); !found || delta != -15 {
		t.Fatalf("public-cacheable = %v (found %t), want -15", delta, found)
	}
}

func TestProbePenalizesLoginPage(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><form action="/login"><input type="password" name="pw"></form></html>`))
	})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/thing"})
	if !ok {
		t.Fatal("a penalised reflection must still be returned for -all")
	}
	if f.Confidence.Value != 65 {
		t.Fatalf("confidence = %v, want 65 + 20 - 20", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "unauthenticated-login-page"); !found || delta != -20 {
		t.Fatalf("unauthenticated-login-page = %v (found %t), want -20", delta, found)
	}
}

func TestProbePenalizesEmptyBody(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/thing"})
	if !ok {
		t.Fatal("a penalised reflection must still be returned for -all")
	}
	if f.Confidence.Value != 70 {
		t.Fatalf("confidence = %v, want 65 + 20 - 15", f.Confidence.Value)
	}
	if delta, found := signalDelta(f, "empty-body"); !found || delta != -15 {
		t.Fatalf("empty-body = %v (found %t), want -15", delta, found)
	}
}

func TestProbeAuthCookieAndExposedHeader(t *testing.T) {
	server := reflectingServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Set-Cookie", "sessionid=s3cr3t; HttpOnly; Path=/")
		w.Header().Set("Access-Control-Expose-Headers", "X-Trace, Authorization")
		w.Write([]byte(`{"ok":true}`))
	})

	f, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/api/me"})
	if !ok {
		t.Fatal("a credentialed reflection must be reported")
	}
	if f.Confidence.Value != 100 {
		t.Fatalf("confidence = %v, want 65 + 20 + 10 + 10 clamped to 100", f.Confidence.Value)
	}
	delta, found := signalDelta(f, "auth-cookies-present")
	if !found || delta != 10 {
		t.Fatalf("auth-cookies-present = %v (found %t), want 10", delta, found)
	}
	delta, found = signalDelta(f, "exposed-sensitive-headers")
	if !found || delta != 10 {
		t.Fatalf("exposed-sensitive-headers = %v (found %t), want 10", delta, found)
	}
}

func TestProbeWithNilClientOrInvalidTarget(t *testing.T) {
	var analyzer *Analyzer
	if _, ok := analyzer.Probe(context.Background(), Target{URL: "https://example.test"}); ok {
		t.Fatal("a nil analyzer must not report")
	}
	if _, ok := New(nil).Probe(context.Background(), Target{URL: "https://example.test"}); ok {
		t.Fatal("a nil client must not report")
	}

	client := newTestClient(t)
	for _, target := range []string{"", "not-a-url", "/relative", "ftp://example.test/x", "https://"} {
		if _, ok := New(client).Probe(context.Background(), Target{URL: target}); ok {
			t.Fatalf("target %q must be rejected", target)
		}
	}
}

func TestSensitiveJSONKey(t *testing.T) {
	cases := []struct {
		name string
		body string
		key  string
		want bool
	}{
		{"email field", `{"email":"a@b.c"}`, "email", true},
		{"snake case id", `{"user_id":42}`, "user_id", true},
		{"case insensitive", `{"Data":{"Email":"a@b.c"}}`, "Email", true},
		{"array container", `[{"balance":10}]`, "balance", true},
		{"value is not a key", `["email","token"]`, "", false},
		{"harmless field", `{"status":"ok"}`, "", false},
		{"html wrapper", `<script>{"email":"a@b.c"}</script>`, "", false},
		{"escaped value", `{"a":"b\"c","api_key":"k"}`, "api_key", true},
		{"truncated string", `{"email":`, "", false},
		{"empty body", ``, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := sensitiveJSONKey(tc.body)
			if ok != tc.want {
				t.Fatalf("ok = %t, want %t", ok, tc.want)
			}
			if ok && key != tc.key {
				t.Fatalf("key = %q, want %q", key, tc.key)
			}
		})
	}
}

func TestLooksLikeLoginPage(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"password input", `<html><form action="/login"><input type="password"></form></html>`, true},
		{"single quoted", `<input type='password'>`, true},
		{"login form", `<form action="/account/login"><button>Sign in</button></form>`, true},
		{"plain page", `<html><body>hello</body></html>`, false},
		{"json", `{"login":"ok"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeLoginPage(tc.body); got != tc.want {
				t.Fatalf("looksLikeLoginPage = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestIsStaticAsset(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/app.js", true},
		{"/APP.JS", true},
		{"/fonts/x.woff2", true},
		{"/logo.svg", true},
		{"/api/data", false},
		{"/data.json", false},
		{"/", false},
	}
	for _, tc := range cases {
		if got := isStaticAsset(tc.path); got != tc.want {
			t.Fatalf("isStaticAsset(%q) = %t, want %t", tc.path, got, tc.want)
		}
	}
}

func TestSensitiveExposedHeader(t *testing.T) {
	cases := []struct {
		header http.Header
		want   string
	}{
		{http.Header{"Access-Control-Expose-Headers": {"X-Trace, Authorization"}}, "Authorization"},
		{http.Header{"Access-Control-Expose-Headers": {"set-cookie"}}, "set-cookie"},
		{http.Header{"Access-Control-Expose-Headers": {"X-CSRF-Token"}}, "X-CSRF-Token"},
		{http.Header{"Access-Control-Expose-Headers": {"X-Trace"}}, ""},
		{http.Header{}, ""},
	}
	for _, tc := range cases {
		if got := sensitiveExposedHeader(tc.header); got != tc.want {
			t.Fatalf("sensitiveExposedHeader = %q, want %q", got, tc.want)
		}
	}
}

func TestAuthEvidence(t *testing.T) {
	cases := []struct {
		name    string
		header  http.Header
		hasAuth bool
		want    bool
	}{
		{"session cookie", http.Header{"Set-Cookie": {"sessionid=abc; Path=/"}}, false, true},
		{"jwt cookie", http.Header{"Set-Cookie": {"jwt=abc"}}, false, true},
		{"anonymous", http.Header{"Set-Cookie": {"theme=dark"}}, false, false},
		{"scan credentials", http.Header{}, true, true},
		{"nothing", http.Header{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := authEvidence(tc.hasAuth, tc.header)
			if ok != tc.want {
				t.Fatalf("ok = %t, want %t", ok, tc.want)
			}
			if ok && reason == "" {
				t.Fatal("a true verdict needs a reason for the audit trail")
			}
		})
	}
}

func TestOriginAccepted(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		origin string
		acao   string
		want   bool
	}{
		{"verbatim", probeArbitrary, "https://soli-ab.invalid", "https://soli-ab.invalid", true},
		{"case insensitive", probeArbitrary, "https://soli-ab.invalid", "HTTPS://SOLI-AB.INVALID", true},
		{"trailing slash", probeArbitrary, "https://soli-ab.invalid", "https://soli-ab.invalid/", false},
		{"null literal", probeNull, "null", "null", true},
		{"null replaced", probeNull, "null", "https://app.example.test", false},
		{"wildcard", probeSubdomain, "https://soli-check.x", "*", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originAccepted(tc.kind, tc.origin, tc.acao); got != tc.want {
				t.Fatalf("originAccepted = %t, want %t", got, tc.want)
			}
		})
	}
}
