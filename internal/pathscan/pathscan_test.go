package pathscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soliofski/SoliTools/internal/httpx"
)

// TestEvaluateRejectsWAFBlockPages is the path-side false-positive guard: a
// synthetic block is not an exposed file.
func TestEvaluateRejectsWAFBlockPages(t *testing.T) {
	header := http.Header{}
	header.Set("cf-ray", "8a1b2c3d-LHR")
	response := &httpx.Response{
		Status: http.StatusForbidden,
		Header: header,
		Body:   []byte("<html><title>Attention Required! | Cloudflare</title></html>"),
	}
	if _, ok := evaluate(".env", "https://target.test/.env", response, baselineSample{status: http.StatusNotFound}); ok {
		t.Fatal("a WAF block page must not be reported as a reachable path")
	}
}

func TestEvaluate(t *testing.T) {
	response := func(status int, body string) *httpx.Response {
		return &httpx.Response{Status: status, Body: []byte(body)}
	}

	cases := []struct {
		name       string
		word       string
		response   *httpx.Response
		baseStatus int
		baseSize   int
		want       bool
	}{
		{"exposed env file", ".env", response(200, "DB_HOST=db.internal"), 404, 0, true},
		{"forbidden admin", "admin", response(403, "denied"), 404, 0, true},
		{"not found", "admin", response(404, "nope"), 404, 0, false},
		{"redirect is not a hit", "admin", response(302, ""), 404, 0, false},
		{"default server page", "admin", response(200, "<title>404 Not Found</title>"), 404, 0, false},
		{"soft 404 catch-all", "admin", response(200, "same body"), 200, 9, false},
		// On a host that answers 200 for a random path, a 200 page is a soft 404
		// unless the body proves what it is.
		{"page under catch-all", "admin", response(200, "a much longer body than the baseline"), 200, 9, false},
		{"signed file under catch-all", ".env", response(200, "DB_HOST=db.internal"), 200, 9, true},
		// An HTML shell is never a credential file, whatever the baseline says.
		{"html shell for env", ".env", response(200, "<!DOCTYPE html><html><body>app</body></html>"), 404, 0, false},
		{"env without assignments", ".env", response(200, "not a dotenv file"), 404, 0, false},
		{"private key without header", "id_rsa", response(200, "some text"), 404, 0, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := evaluate(c.word, "https://target.test/"+c.word, c.response, baselineSample{status: c.baseStatus, size: c.baseSize, known: true})
			if ok != c.want {
				t.Fatalf("evaluate = %v, want %v", ok, c.want)
			}
		})
	}
}

func TestProbeReportsOnlyMeaningfulPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Write([]byte("DB_HOST=db.internal"))
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("denied"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	findings, warnings := New(client, []string{".env", "admin", "missing"}, 3).Probe(context.Background(), server.URL)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(findings), findings)
	}
	// .env is a known sensitive file and answered 200, so it must outrank a 403.
	if findings[0].RuleID != "path.reachable" || findings[0].Confidence.Value <= findings[1].Confidence.Value {
		t.Fatalf("unexpected ordering: %+v", findings)
	}
	if findings[0].Confidence.Value < 75 {
		t.Fatalf("exposed .env scored %v, want high confidence", findings[0].Confidence.Value)
	}
}

func TestProbeSkipsCatchAllHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this host answers everything the same way"))
	}))
	defer server.Close()

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	findings, _ := New(client, []string{".env", "admin"}, 2).Probe(context.Background(), server.URL)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 on a soft-404 host: %+v", len(findings), findings)
	}
}
