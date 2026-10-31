package pathscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
)

// spaIndex is what a single-page app returns for every unknown route.
const spaIndex = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Orchid Labs</title></head>
<body><div id="root"></div><script src="/assets/app.js"></script></body>
</html>`

// newPathClient builds a client fast enough for tests.
func newPathClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

// TestProbeSurvivesBaselineTransportFailure is the regression for the reported
// false-positive flood.
//
// A catch-all host answers index.html for every path. The baseline probe is the
// only thing that can distinguish that from an exposed file, so when the
// baseline request fails the scanner must not conclude "no catch-all" and then
// report the whole wordlist.
func TestProbeSurvivesBaselineTransportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The random baseline path is dropped at the transport level, exactly
		// like a transient reset or a CDN hiccup. Every real word still
		// answers the SPA shell.
		if strings.HasPrefix(r.URL.Path, "/soli-") {
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, spaIndex)
	}))
	defer server.Close()

	findings, warnings := New(newPathClient(t), nil, 4).Probe(context.Background(), server.URL)
	if len(findings) != 0 {
		if len(findings) > 3 {
			t.Fatalf("catch-all host produced %d findings (flood), want 0:\n%s", len(findings), summarize(findings))
		}
		t.Fatalf("catch-all host produced %d findings, want 0:\n%s", len(findings), summarize(findings))
	}
	if len(warnings) == 0 {
		t.Fatal("a failed baseline must be reported as a warning, not silently assumed away")
	}
}

// TestEvaluateRejectsHTMLForSensitiveFiles pins the content rule: a 200 with an
// HTML document is never an exposed .env, key or git file, even when there is
// no usable baseline to compare sizes against.
func TestEvaluateRejectsHTMLForSensitiveFiles(t *testing.T) {
	words := []string{".env", "id_rsa", ".git/config", ".git/HEAD", ".aws/credentials", "docker-compose.yml"}
	for _, word := range words {
		t.Run(word, func(t *testing.T) {
			response := &httpx.Response{
				Status: http.StatusOK,
				Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:   []byte(spaIndex),
			}
			if candidate, ok := evaluate(word, "https://target.test/"+word, response, baselineSample{}); ok {
				t.Fatalf("HTML shell accepted as %s: %+v", word, candidate.Confidence)
			}
		})
	}
}

// TestProbeRejectsSPAHTMLEvenWithBaseline documents the second hole: the size
// heuristic only compares lengths, so a catch-all shell whose bytes differ per
// route (a serialised route name, preloaded assets) slips past it. Content, not
// size, has to decide.
func TestProbeRejectsSPAHTMLEvenWithBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The shell grows with the requested path, the way a server-rendered
		// SPA inlines the route and its preload list.
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Orchid Labs</title></head><body><div id="root"></div><script>window.__ROUTE__=%q</script>%s</body></html>`,
			r.URL.Path, strings.Repeat("<li>nav</li>", len(r.URL.Path)*4))
	}))
	defer server.Close()

	findings, _ := New(newPathClient(t), []string{".env", "id_rsa", ".git/config", ".aws/credentials"}, 2).
		Probe(context.Background(), server.URL)
	if len(findings) != 0 {
		t.Fatalf("HTML shell reported as sensitive files:\n%s", summarize(findings))
	}
}

// TestEvaluateAcceptsRealSensitiveFiles guards against over-correction: the
// content rules must still accept genuine exposures.
func TestEvaluateAcceptsRealSensitiveFiles(t *testing.T) {
	cases := []struct {
		word string
		body string
	}{
		{".env", "APP_ENV=production\nDB_PASSWORD=s3cret\n"},
		{"id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n"},
		{".git/config", "[core]\n\trepositoryformatversion = 0\n"},
		{".git/HEAD", "ref: refs/heads/main\n"},
		{".aws/credentials", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"},
		{"docker-compose.yml", "services:\n  web:\n    image: nginx\n"},
	}
	for _, c := range cases {
		t.Run(c.word, func(t *testing.T) {
			response := &httpx.Response{
				Status: http.StatusOK,
				Header: http.Header{"Content-Type": []string{"text/plain"}},
				Body:   []byte(c.body),
			}
			if _, ok := evaluate(c.word, "https://target.test/"+c.word, response, baselineSample{}); !ok {
				t.Fatalf("real %s exposure was rejected", c.word)
			}
		})
	}
}

// summarize prints findings compactly for failure messages.
func summarize(findings []finding.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "  %s %v %s\n", f.URL, f.Confidence.Value, f.Context)
	}
	return b.String()
}
