package crlf

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 1000})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

// injectedCanary mimics a vulnerable application: it takes the already decoded
// parameter value and writes the line after the first CRLF into a response
// header. Only a value that really carries a CRLF-separated canary line yields a
// token, so a test server built on it cannot accidentally reward a payload that
// the application never decoded.
func injectedCanary(value string) (string, bool) {
	index := strings.Index(value, "\r\n")
	if index < 0 {
		return "", false
	}
	name, token, ok := strings.Cut(value[index+2:], ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), canaryHeader) {
		return "", false
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "soli_") {
		return "", false
	}
	return token, true
}

func hasSignal(score confidence.Score, name string) bool {
	for _, signal := range score.Signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}

func fieldValue(fields []finding.Field, name string) (string, bool) {
	for _, field := range fields {
		if field.Name == name {
			return field.Value, true
		}
	}
	return "", false
}

func TestProbeDetectsParsedHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := injectedCanary(r.URL.Query().Get("next"))
		if !ok {
			w.Write([]byte("ok"))
			return
		}
		w.Header().Set(canaryHeader, token)
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	found, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"})
	if !ok {
		t.Fatal("a canary parsed as a response header must be reported")
	}
	if found.Confidence.Value != 80 {
		t.Fatalf("confidence = %v, want 80 (50 base + 30 parsed header)", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalHeaderParsed) {
		t.Fatal("the parsed-header signal is missing from the trace")
	}
	if found.Kind != kindCRLF || found.Category != categoryCRLF || found.RuleID != ruleIDCRLF {
		t.Fatalf("identity = %q/%q/%q", found.Kind, found.Category, found.RuleID)
	}
	if !strings.HasPrefix(found.Value, "soli_") {
		t.Fatalf("value = %q, want the canary token", found.Value)
	}
	if got, _ := fieldValue(found.Fields, "Parameter"); got != "next" {
		t.Fatalf("Parameter field = %q", got)
	}
	if got, _ := fieldValue(found.Fields, "Injected Header"); got != canaryHeader {
		t.Fatalf("Injected Header field = %q", got)
	}
	if got, _ := fieldValue(found.Fields, "Value"); got != found.Value {
		t.Fatalf("Value field = %q, want %q", got, found.Value)
	}
	if got, _ := fieldValue(found.Fields, "Method"); got != http.MethodGet {
		t.Fatalf("Method field = %q", got)
	}
}

func TestProbeIgnoresBodyOnlyReflection(t *testing.T) {
	var sawCanary atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("next")
		if strings.Contains(value, canaryHeader) {
			sawCanary.Store(true)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// A classic scanner trap: the whole payload is echoed into the error
		// page, so the canary header name is literally present in the response.
		w.Write([]byte("400 Bad Request: invalid redirect " + value))
	}))
	defer server.Close()

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"}); ok {
		t.Fatal("a body reflection is not header injection")
	}
	if !sawCanary.Load() {
		t.Fatal("the canary was never reflected, so the hard gate was not exercised")
	}
}

func TestProbeIgnoresCanaryInAnotherHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := injectedCanary(r.URL.Query().Get("next"))
		if ok {
			// The token reached the header section, but not as the injected
			// header: a reflection into a diagnostic header is not injection.
			w.Header().Set("X-Debug", "reflected: "+token)
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	if _, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"}); ok {
		t.Fatal("the canary must be the injected header, not merely present in headers")
	}
}

func TestProbePenalisesRejectedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := injectedCanary(r.URL.Query().Get("next"))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set(canaryHeader, token)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	found, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"})
	if !ok {
		t.Fatal("a parsed canary is still evidence, even on a 400")
	}
	if found.Confidence.Value != 60 {
		t.Fatalf("confidence = %v, want 60 (50 + 30 - 20)", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalSyntaxError) {
		t.Fatal("the 400 penalty is missing from the trace")
	}
}

func TestProbeDetectsDoubleEncodedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("next")
		// An upstream proxy that rejects literal newlines: only a payload that
		// is still encoded when it arrives can survive the second decode.
		if strings.ContainsAny(raw, "\r\n") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			decoded = raw
		}
		token, ok := injectedCanary(decoded)
		if !ok {
			w.Write([]byte("ok"))
			return
		}
		w.Header().Set(canaryHeader, token)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	found, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"})
	if !ok {
		t.Fatal("a payload that survives one extra decode must be reported")
	}
	if found.Confidence.Value != 95 {
		t.Fatalf("confidence = %v, want 95 (50 + 30 + 15)", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalDoubleEncoding) {
		t.Fatal("the double-encoding signal is missing from the trace")
	}
	if got, _ := fieldValue(found.Fields, "Encoding"); got != "double-encoded" {
		t.Fatalf("Encoding field = %q, want double-encoded", got)
	}
}

func TestProbeDetectsSetCookieInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := injectedCanary(r.URL.Query().Get("next"))
		if !ok {
			w.Write([]byte("ok"))
			return
		}
		w.Header().Add("Set-Cookie", "solitools_canary="+token+"; Path=/; SameSite=Lax")
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	found, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"})
	if !ok {
		t.Fatal("a canary parsed as a cookie value is proof of injection")
	}
	if found.Confidence.Value != 75 {
		t.Fatalf("confidence = %v, want 75 (50 + 25)", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalSetCookie) {
		t.Fatal("the Set-Cookie signal is missing from the trace")
	}
	if _, present := fieldValue(found.Fields, "Evidence"); !present {
		t.Fatal("a cookie-only finding must say where the proof came from")
	}
}

func TestProbePenalisesSanitizedEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("next")
		token, ok := injectedCanary(value)
		if !ok {
			w.Write([]byte("ok"))
			return
		}
		w.Header().Set(canaryHeader, token)
		// The newline was flattened to a space, so the second copy is visible
		// as text rather than as a header.
		w.Header().Set("X-Debug", "/login?next="+strings.ReplaceAll(value, "\r\n", " "))
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	found, ok := New(newTestClient(t)).Probe(context.Background(), Target{URL: server.URL + "/?next=/home", Param: "next"})
	if !ok {
		t.Fatal("the finding still exists, it is only demoted")
	}
	if found.Confidence.Value != 55 {
		t.Fatalf("confidence = %v, want 55 (50 + 30 - 25)", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalSanitized) {
		t.Fatal("the sanitized-replacement penalty is missing from the trace")
	}
	if found.Confidence.Band != confidence.BandMedium {
		t.Fatalf("band = %q, want medium so the default report hides it", found.Confidence.Band)
	}
}

func TestVariantsCoverTheEncodingMatrix(t *testing.T) {
	got := variants("soli_abc")
	if len(got) != 4 {
		t.Fatalf("variants() has %d entries, want 4", len(got))
	}
	want := map[string]string{
		"crlf":           "\r\n",
		"lf":             "\n",
		"cr":             "\r",
		"double-encoded": "%0d%0a",
	}
	for _, v := range got {
		prefix, ok := want[v.name]
		if !ok {
			t.Fatalf("unexpected variant %q", v.name)
		}
		if !strings.HasPrefix(v.value, prefix) {
			t.Errorf("variant %q starts with %q, want %q", v.name, v.value, prefix)
		}
		if !strings.Contains(v.value, canaryHeader+": soli_abc") {
			t.Errorf("variant %q does not carry the canary line", v.name)
		}
		if v.double != (v.name == "double-encoded") {
			t.Errorf("variant %q has double = %v", v.name, v.double)
		}
	}
}

func TestWithParamKeepsTheRequestLegal(t *testing.T) {
	probeURL, err := withParam("https://target.test/?next=/home#frag", "next", "\r\nX-SoliTools-Canary: soli_abc")
	if err != nil {
		t.Fatalf("withParam: %v", err)
	}
	if strings.ContainsAny(probeURL, "\r\n") {
		t.Fatalf("probe URL %q carries a raw newline", probeURL)
	}
	if !strings.Contains(probeURL, "next=%0D%0AX-SoliTools-Canary%3A+soli_abc") {
		t.Fatalf("probe URL %q does not carry the encoded payload", probeURL)
	}
	if _, err := withParam("not-a-url", "next", "x"); err == nil {
		t.Fatal("a relative URL must be rejected")
	}
}

func TestProbeNeedsClientAndParameter(t *testing.T) {
	ctx := context.Background()
	if _, ok := New(nil).Probe(ctx, Target{URL: "https://target.test/?next=x", Param: "next"}); ok {
		t.Fatal("a nil client must not probe")
	}
	if _, ok := New(newTestClient(t)).Probe(ctx, Target{URL: "https://target.test/?next=x"}); ok {
		t.Fatal("an empty parameter must not probe")
	}
	if _, ok := New(newTestClient(t)).Probe(ctx, Target{URL: "not-a-url", Param: "next"}); ok {
		t.Fatal("an unusable target must not probe")
	}
}

// tokenPattern finds the canary the prober generated inside a raw request line.
var tokenPattern = regexp.MustCompile(`soli_[0-9a-f]+`)

func canaryFromRequestLine(line string) string { return tokenPattern.FindString(line) }

// startRawServer accepts connections on a loopback listener and answers each
// with respond(requestLine). It returns the probe URL and a channel carrying the
// request lines it saw.
func startRawServer(t *testing.T, respond func(requestLine string) string) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	lines := make(chan string, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				for {
					header, err := reader.ReadString('\n')
					if err != nil || header == "\r\n" || header == "\n" {
						break
					}
				}
				lines <- line
				_, _ = io.WriteString(conn, respond(line))
			}(conn)
		}
	}()
	return "http://" + listener.Addr().String() + "/?next=/home", lines
}

func TestProbeRawDetectsResponseSplitting(t *testing.T) {
	probeURL, lines := startRawServer(t, func(requestLine string) string {
		token := canaryFromRequestLine(requestLine)
		body := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nPWNED"
		return "HTTP/1.1 302 Found\r\n" +
			"Location: /login\r\n" +
			canaryHeader + ": " + token + "\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
	})

	found, ok := ProbeRaw(context.Background(), newTestClient(t), probeURL, "next")
	if !ok {
		t.Fatal("a canary header plus a second status line must be reported")
	}
	if found.Confidence.Value < 90 {
		t.Fatalf("confidence = %v, want the critical band for response splitting", found.Confidence.Value)
	}
	if !hasSignal(found.Confidence, signalSplitting) {
		t.Fatal("the response-splitting signal is missing from the trace")
	}
	if found.RuleID != ruleIDCRLF || found.Category != categoryCRLF {
		t.Fatalf("identity = %q/%q", found.RuleID, found.Category)
	}
	if got, _ := fieldValue(found.Fields, "Status Line"); !strings.HasPrefix(got, "HTTP/1.1 302") {
		t.Fatalf("Status Line field = %q", got)
	}

	line := <-lines
	if !strings.Contains(line, "next=%0d%0aX-SoliTools-Canary:%20soli_") {
		t.Fatalf("raw request line = %q, want the literal encoded payload", line)
	}
}

func TestProbeRawDetectsHeaderOnly(t *testing.T) {
	probeURL, _ := startRawServer(t, func(requestLine string) string {
		token := canaryFromRequestLine(requestLine)
		body := "<html>redirecting</html>"
		return "HTTP/1.1 200 OK\r\n" +
			canaryHeader + ": " + token + "\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
	})

	found, ok := ProbeRaw(context.Background(), newTestClient(t), probeURL, "next")
	if !ok {
		t.Fatal("expected a header injection finding")
	}
	if found.Confidence.Value != 80 {
		t.Fatalf("confidence = %v, want 80 (50 + 30)", found.Confidence.Value)
	}
	if hasSignal(found.Confidence, signalSplitting) {
		t.Fatal("a single response must not be reported as splitting")
	}
}

func TestProbeRawIgnoresBodyOnlyResponse(t *testing.T) {
	probeURL, lines := startRawServer(t, func(requestLine string) string {
		token := canaryFromRequestLine(requestLine)
		body := "error: " + canaryHeader + ": " + token
		return "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
	})

	if _, ok := ProbeRaw(context.Background(), newTestClient(t), probeURL, "next"); ok {
		t.Fatal("a canary that only appears in the body is not header injection")
	}
	if canaryFromRequestLine(<-lines) == "" {
		t.Fatal("the payload never reached the server, so the gate was not exercised")
	}
}

func TestProbeRawBodyCapHidesDistantStatusLine(t *testing.T) {
	probeURL, _ := startRawServer(t, func(requestLine string) string {
		token := canaryFromRequestLine(requestLine)
		// The second status line sits past the 4 KiB cap, so the prober must not
		// read it even though it is a genuine line boundary.
		body := strings.Repeat("0123456789\r\n", 500) + "HTTP/1.1 200 OK\r\n"
		return "HTTP/1.1 200 OK\r\n" +
			canaryHeader + ": " + token + "\r\n" +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" + body
	})

	found, ok := ProbeRaw(context.Background(), newTestClient(t), probeURL, "next")
	if !ok {
		t.Fatal("expected the header finding")
	}
	if found.Confidence.Value != 80 {
		t.Fatalf("confidence = %v, want 80: the status line past the cap must not count", found.Confidence.Value)
	}
}

func TestProbeRawSurvivesMalformedResponses(t *testing.T) {
	cases := map[string]string{
		"status-line": "garbage\r\n\r\n",
		"empty":       "",
		"headers":     "HTTP/1.1 200 OK\r\nnot a header line\r\n\r\n",
	}
	for name, response := range cases {
		response := response
		t.Run(name, func(t *testing.T) {
			probeURL, _ := startRawServer(t, func(string) string { return response })
			if _, ok := ProbeRaw(context.Background(), newTestClient(t), probeURL, "next"); ok {
				t.Fatal("a malformed response must not produce a finding")
			}
		})
	}
}

func TestProbeRawVerifiesCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If certificate verification were disabled this handler would run and
		// the echo below would turn into a finding, failing the test.
		if token := canaryFromRequestLine(r.URL.RawQuery); token != "" {
			w.Header().Set(canaryHeader, token)
		}
	}))
	defer server.Close()

	if _, ok := ProbeRaw(context.Background(), newTestClient(t), server.URL+"/?next=/home", "next"); ok {
		t.Fatal("a self-signed certificate must not be accepted")
	}
}

func TestProbeRawRequiresClientAndPlainParameter(t *testing.T) {
	ctx := context.Background()
	if _, ok := ProbeRaw(ctx, nil, "http://127.0.0.1:1/?next=x", "next"); ok {
		t.Fatal("a nil client must not dial")
	}
	if _, ok := ProbeRaw(ctx, newTestClient(t), "http://127.0.0.1:1/?next=x", "bad\r\nname"); ok {
		t.Fatal("a parameter that can rewrite the request line must be rejected")
	}
	if _, ok := ProbeRaw(ctx, newTestClient(t), "ftp://127.0.0.1/?next=x", "next"); ok {
		t.Fatal("a non-HTTP scheme must be rejected")
	}
}

func TestInjectQueryReplacesOnlyTheNamedParameter(t *testing.T) {
	const payload = "%0d%0aX-SoliTools-Canary:%20soli_abc"
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{"existing", "a=1&next=/home", "a=1&next=" + payload},
		{"only", "next=/home", "next=" + payload},
		{"missing", "a=1", "a=1&next=" + payload},
		{"empty", "", "next=" + payload},
		{"escaped-key", "%6Eext=/home&keep=1", "next=" + payload + "&keep=1"},
	}
	for _, c := range cases {
		target, err := url.Parse("http://target.test/path?" + c.query)
		if err != nil {
			t.Fatalf("%s: parse: %v", c.name, err)
		}
		injectQuery(target, "next", payload)
		if target.RawQuery != c.want {
			t.Errorf("%s: query = %q, want %q", c.name, target.RawQuery, c.want)
		}
	}
}

func TestHasSecondStatusLine(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", true},
		{"\r\nHTTP/1.1 500 Internal Server Error\r\n", true},
		{"HTTP/1.0 404 Not Found", true},
		{"<html>HTTP/1.1 200 OK</html>", false},
		{"prefix HTTP/1.1 200 OK", false},
		{"HTTP/1.1 20 OK", false},
		{"HTTP/1.1 2000 OK", false},
		{"HTTP/1.1 600 OK", false},
		{"HTTP/2 200 OK", false},
		{"nothing to see", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hasSecondStatusLine([]byte(c.body)); got != c.want {
			t.Errorf("hasSecondStatusLine(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestCanaryCookieNeedsABareValue(t *testing.T) {
	header := http.Header{}
	header.Add("Set-Cookie", "theme= X-SoliTools-Canary: soli_abc")
	if got := canaryCookie(header, "soli_abc"); got != "" {
		t.Fatalf("a reflected payload inside a cookie value must not count: %q", got)
	}

	header.Add("Set-Cookie", "lang=en; solitools_canary=soli_abc; Path=/")
	if got := canaryCookie(header, "soli_abc"); got == "" {
		t.Fatal("a cookie whose value is the canary must count")
	}
}

func TestSanitizedEchoIsDeterministicAndIgnoresTheCanaryHeader(t *testing.T) {
	header := http.Header{}
	header.Set(canaryHeader, "soli_abc")
	if got := sanitizedEcho(header, "soli_abc"); got != "" {
		t.Fatalf("the canary header itself must not look sanitized, got %q", got)
	}

	header.Set("Z-Debug", "next= X-SoliTools-Canary: soli_abc")
	header.Set("A-Debug", "next= X-SoliTools-Canary_soli_abc")
	for i := 0; i < 20; i++ {
		if got := sanitizedEcho(header, "soli_abc"); got != "A-Debug" {
			t.Fatalf("sanitizedEcho = %q, want the alphabetically first header", got)
		}
	}
}
