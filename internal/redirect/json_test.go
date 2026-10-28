package redirect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soliofski/SoliTools/internal/finding"
)

// redirectServer answers a JSON POST by redirecting to the submitted value when
// it points at the canary.
func redirectServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		target := payload["next"]
		if strings.HasPrefix(target, "https://example.com/solitools-redirect-check") {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	return server
}

func hasField(candidate finding.Finding, name, value string) bool {
	for _, field := range candidate.Fields {
		if field.Name == name && field.Value == value {
			return true
		}
	}
	return false
}

func TestProbeJSONDetectsOpenRedirect(t *testing.T) {
	server := redirectServer(t)

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL + "/api/go", Name: "next"})
	if !ok {
		t.Fatal("expected a JSON open redirect finding")
	}
	if finding.RuleID != "redirect.json" {
		t.Fatalf("rule = %q, want redirect.json", finding.RuleID)
	}
	if !hasField(finding, "Method", MethodJSON) {
		t.Fatalf("fields = %+v, want Method %q", finding.Fields, MethodJSON)
	}
	if finding.Confidence.Value < 90 {
		t.Fatalf("confidence = %v, want critical", finding.Confidence.Value)
	}
}

func TestProbeJSONIgnoresInternalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/home")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "next"}); ok {
		t.Fatal("an internal redirect is not an open redirect")
	}
}

func TestProbeJSONSuppressesWAFBlockPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A block page that happens to carry the canary in Location must not be
		// treated as a redirect: the WAF is answering, not the application.
		w.Header().Set("cf-ray", "8a1b2c3d-LHR")
		w.Header().Set("Location", "https://example.com/solitools-redirect-check")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html>Attention Required! | Cloudflare</html>"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "next"}); ok {
		t.Fatal("a WAF block page must not be reported as a redirect")
	}
}
