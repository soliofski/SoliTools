package reflect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jsonServer answers a POSTed JSON body by echoing the named field back.
func jsonServer(t *testing.T, status int, contentType, bodyTemplate string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("content-type = %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		value, _ := payload["q"].(string)
		if nested, ok := payload["filter"].(map[string]any); ok {
			value, _ = nested["url"].(string)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		if strings.HasPrefix(contentType, "application/json") {
			fmt.Fprintf(w, `{"message":%q}`, value)
			return
		}
		strings.NewReplacer("%s", value).WriteString(w, bodyTemplate)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestProbeJSONDetectsReflectionInJSON(t *testing.T) {
	server := jsonServer(t, http.StatusOK, "application/json", "%s")

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "q"})
	if !ok {
		t.Fatal("expected a JSON reflection finding")
	}
	if finding.RuleID != "reflect.json" {
		t.Fatalf("rule = %q, want reflect.json", finding.RuleID)
	}
	if !hasField(finding, "Method", MethodJSON) {
		t.Fatalf("fields = %+v, want Method %q", finding.Fields, MethodJSON)
	}
	if !hasField(finding, "Reflection Point", string(ContextJSON)) {
		t.Fatalf("fields = %+v, want JSON context", finding.Fields)
	}
	if finding.Confidence.Value < 60 {
		t.Fatalf("confidence = %v, want visible", finding.Confidence.Value)
	}
}

func TestProbeJSONDetectsReflectionInHTMLError(t *testing.T) {
	server := jsonServer(t, http.StatusBadRequest, "text/html", "<html><body><p>%s</p></body></html>")

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "q"})
	if !ok {
		t.Fatal("expected a reflection inside the API error page")
	}
	if !hasField(finding, "Reflection Point", string(ContextHTMLText)) {
		t.Fatalf("fields = %+v, want HTML body context", finding.Fields)
	}
	if finding.Confidence.Value < 60 {
		t.Fatalf("confidence = %v, want visible", finding.Confidence.Value)
	}
}

func TestProbeJSONNestsMinedPath(t *testing.T) {
	server := jsonServer(t, http.StatusOK, "application/json", "%s")

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{
		URL: server.URL, Name: "url", Path: []string{"filter", "url"},
	})
	if !ok {
		t.Fatal("expected a nested reflection finding")
	}
	if !hasField(finding, "Parameter", "url") {
		t.Fatalf("fields = %+v, want the nested key name", finding.Fields)
	}
}

func TestProbeJSONIgnoresUnsupportedStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnsupportedMediaType, http.StatusInternalServerError} {
		server := jsonServer(t, status, "text/plain", "no reflection here")
		analyzer := New(newTestClient(t))
		if _, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "q"}); ok {
			t.Fatalf("status %d produced a finding", status)
		}
	}
}

func TestProbeJSONSuppressesWAFBlockPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("cf-ray", "8a1b2c3d-LHR")
		w.WriteHeader(http.StatusForbidden)
		echo, _ := payload["q"].(string)
		json.NewEncoder(w).Encode(map[string]string{"error": "Attention Required! | Cloudflare", "echo": echo})
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.ProbeJSON(context.Background(), JSONTarget{URL: server.URL, Name: "q"}); ok {
		t.Fatal("a WAF block page must not become a JSON reflection finding")
	}
}
