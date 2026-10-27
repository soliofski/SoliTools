package reflect

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"solitools/internal/httpx"
	"solitools/internal/param"
)

func TestClassify(t *testing.T) {
	marker := "CANARY"
	cases := []struct {
		name string
		body string
		want Context
	}{
		{"html body", "<div>" + marker + "</div>", ContextHTMLText},
		{"attribute", `<a href="` + marker + `">x</a>`, ContextAttribute},
		{"script", `<script>var a = "` + marker + `";</script>`, ContextScript},
		{"comment", `<!-- ` + marker + ` -->`, ContextComment},
		{"json", `{"q":"` + marker + `"}`, ContextJSON},
		{"after comment", `<!-- x --><p>` + marker + `</p>`, ContextHTMLText},
	}
	for _, c := range cases {
		offset := strings.Index(c.body, marker)
		if offset < 0 {
			t.Fatalf("%s: marker missing", c.name)
		}
		if got := Classify(c.body, offset); got != c.want {
			t.Errorf("%s: Classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

func TestProbeReportsUnescapedReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	finding, ok := analyzer.Probe(context.Background(), Target{
		URL:      server.URL + "/?q=hello",
		Name:     "q",
		Interest: param.Medium,
	})
	if !ok {
		t.Fatal("expected a reflection finding")
	}
	if finding.Confidence.Value < 75 {
		t.Fatalf("confidence = %v, want high", finding.Confidence.Value)
	}
	if finding.Fields[1].Value != string(ContextHTMLText) {
		t.Fatalf("fields = %+v, want HTML body context", finding.Fields)
	}
}

func TestProbeRejectsEscapedReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", html.EscapeString(r.URL.Query().Get("q")))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	if _, ok := analyzer.Probe(context.Background(), Target{URL: server.URL + "/?q=hello", Name: "q"}); ok {
		t.Fatal("an escaped reflection must not be reported")
	}
}

func TestProbeDownranksErrorPages(t *testing.T) {
	normal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", r.URL.Query().Get("q"))
	}))
	defer normal.Close()

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "<html><body>Page not found: %s</body></html>", r.URL.Query().Get("q"))
	}))
	defer broken.Close()

	analyzer := New(newTestClient(t))
	good, ok := analyzer.Probe(context.Background(), Target{URL: normal.URL + "/?q=1", Name: "q"})
	if !ok {
		t.Fatal("expected a finding on the normal page")
	}
	bad, ok := analyzer.Probe(context.Background(), Target{URL: broken.URL + "/?q=1", Name: "q"})
	if !ok {
		t.Fatal("expected a low-confidence finding on the error page")
	}
	if bad.Confidence.Value >= good.Confidence.Value {
		t.Fatalf("error page scored %v, normal page %v: the error page must rank lower", bad.Confidence.Value, good.Confidence.Value)
	}
	if bad.Confidence.Value >= 75 {
		t.Fatalf("error page scored %v, want below the high band", bad.Confidence.Value)
	}
}
