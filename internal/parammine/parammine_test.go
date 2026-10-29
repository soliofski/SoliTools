package parammine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/soliofski/SoliTools/internal/httpx"
)

func testClient(t *testing.T) *httpx.Client {
	t.Helper()
	client, err := httpx.New(httpx.Options{Rate: 1000})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return client
}

func hasQuery(r *http.Request, name string) bool {
	values, ok := r.URL.Query()[name]
	return ok && len(values) > 0
}

func expectNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Mine = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Mine = %#v, want %#v", got, want)
		}
	}
}

func TestMineFindsHiddenBodyParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if hasQuery(r, "debug") {
			io.WriteString(w, "debug trace enabled")
			return
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta", "debug", "gamma", "delta"}
	analyzer.ChunkSize = 2

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	expectNames(t, got, []string{"debug"})
}

func TestMineFindsSeveralParametersInOneChunk(t *testing.T) {
	// Every body is the same length, so only the body hash can tell them
	// apart: this is the comparison that matters for real templates.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasQuery(r, "debug"):
			io.WriteString(w, "debug page")
		case hasQuery(r, "admin"):
			io.WriteString(w, "admin page")
		default:
			io.WriteString(w, "clean page")
		}
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"zeta", "admin", "beta", "debug"}
	analyzer.ChunkSize = 4

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	// Sorted, not in discovery order.
	expectNames(t, got, []string{"admin", "debug"})
}

func TestMineDetectsStatusOnlyChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuery(r, "beta") {
			w.WriteHeader(http.StatusInternalServerError)
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta"}
	analyzer.ChunkSize = 2

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	expectNames(t, got, []string{"beta"})
}

func TestMineReturnsNothingWhenServerIsIndifferent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta", "debug", "gamma"}
	analyzer.ChunkSize = 2

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want no parameters", got)
	}
}

func TestMineRejectsUnstableBaseline(t *testing.T) {
	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request, call int64)
	}{
		{
			name: "status",
			handler: func(w http.ResponseWriter, _ *http.Request, call int64) {
				if call > 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			},
		},
		{
			name: "length",
			handler: func(w http.ResponseWriter, _ *http.Request, call int64) {
				io.WriteString(w, strings.Repeat("x", int(call)))
			},
		},
		{
			name: "hash",
			handler: func(w http.ResponseWriter, _ *http.Request, call int64) {
				fmt.Fprintf(w, "page %d", call)
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.handler(w, r, calls.Add(1))
			}))
			defer server.Close()

			analyzer := New(testClient(t))
			analyzer.Words = []string{"debug"}

			_, err := analyzer.Mine(context.Background(), server.URL, nil)
			if !errors.Is(err, ErrUnstableBaseline) {
				t.Fatalf("Mine error = %v, want ErrUnstableBaseline", err)
			}
		})
	}
}

func TestMineSkipsParametersListedAsExisting(t *testing.T) {
	var (
		mu     sync.Mutex
		probed bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuery(r, "debug") {
			mu.Lock()
			probed = true
			mu.Unlock()
			io.WriteString(w, "debug trace enabled")
			return
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "debug", "beta"}
	analyzer.ChunkSize = 3

	got, err := analyzer.Mine(context.Background(), server.URL, []string{"debug"})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want the existing parameter to be excluded", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if probed {
		t.Fatal("an existing parameter must never be probed")
	}
}

func TestMinePreservesExistingQueryValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("session") != "abc" {
			io.WriteString(w, "missing session")
			return
		}
		io.WriteString(w, "welcome")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "debug"}
	analyzer.ChunkSize = 2

	got, err := analyzer.Mine(context.Background(), server.URL+"?session=abc", []string{"session"})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want no parameters; a probe disturbed the existing query", got)
	}
}

func TestMineChunksTheWordlist(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	words := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		words = append(words, fmt.Sprintf("word%02d", i))
	}

	analyzer := New(testClient(t))
	analyzer.Words = words
	analyzer.ChunkSize = 10

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want no parameters", got)
	}
	// Two baseline requests plus five chunks; nothing changed, so there is no
	// bisection to pay for.
	if count := requests.Load(); count != 7 {
		t.Fatalf("requests = %d, want 7", count)
	}
}

func TestMineStopsAtTheRequestBudget(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if hasQuery(r, "hit") {
			io.WriteString(w, "hit page")
			return
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	words := []string{"hit"}
	for i := 1; i < 60; i++ {
		words = append(words, fmt.Sprintf("word%02d", i))
	}

	analyzer := New(testClient(t))
	analyzer.Words = words
	analyzer.ChunkSize = 10
	analyzer.MaxRequests = 8

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if count := requests.Load(); count > 8 {
		t.Fatalf("requests = %d, want at most the budget of 8", count)
	}
	// The first chunk contains the only live name, so bisection reaches it
	// before the budget runs out.
	expectNames(t, got, []string{"hit"})
}

func TestMineStopsOnContextCancellation(t *testing.T) {
	var requests atomic.Int64
	cancels := make(chan context.CancelFunc, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 4 {
			select {
			case cancel := <-cancels:
				cancel()
			default:
			}
		}
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancels <- cancel
	defer cancel()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
	analyzer.ChunkSize = 2
	analyzer.MaxRequests = 50

	got, err := analyzer.Mine(ctx, server.URL, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Mine error = %v, want context.Canceled", err)
	}
	if got != nil {
		t.Fatalf("Mine = %#v, want nil after cancellation", got)
	}
}

func TestMineAcceptsCancelledAndNilContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha"}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzer.Mine(cancelled, server.URL, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v, want context.Canceled", err)
	}

	got, err := analyzer.Mine(nil, server.URL, nil)
	if err != nil {
		t.Fatalf("Mine with a nil context: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want no parameters", got)
	}
}

func TestMineRejectsInvalidInput(t *testing.T) {
	var nilAnalyzer *Analyzer
	if _, err := nilAnalyzer.Mine(context.Background(), "http://target.test/", nil); !errors.Is(err, ErrNoClient) {
		t.Fatalf("nil analyzer error = %v, want ErrNoClient", err)
	}
	if _, err := New(nil).Mine(context.Background(), "http://target.test/", nil); !errors.Is(err, ErrNoClient) {
		t.Fatalf("nil client error = %v, want ErrNoClient", err)
	}

	client := testClient(t)
	for _, target := range []string{"", "   ", "target.test/path", "ftp://target.test/", "http://", "://bad"} {
		if _, err := New(client).Mine(context.Background(), target, nil); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("Mine(%q) error = %v, want ErrInvalidTarget", target, err)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	analyzer := New(client)
	analyzer.Words = []string{"debug"}
	analyzer.MaxRequests = 1
	if _, err := analyzer.Mine(context.Background(), server.URL, nil); !errors.Is(err, ErrBudgetTooSmall) {
		t.Fatalf("MaxRequests=1 error = %v, want ErrBudgetTooSmall", err)
	}
}

func TestMineDoesNotFollowRedirects(t *testing.T) {
	var thirdParty atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		thirdParty.Add(1)
		io.WriteString(w, "third party")
	}))
	defer elsewhere.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/leak", http.StatusFound)
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta"}
	analyzer.ChunkSize = 2

	if _, err := analyzer.Mine(context.Background(), server.URL, nil); err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if count := thirdParty.Load(); count != 0 {
		t.Fatalf("third-party requests = %d, want 0", count)
	}
}

func TestMineTreatsRequestURITooLongAsInconclusive(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusRequestURITooLong)
			io.WriteString(w, "uri too long")
			return
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta", "debug"}
	analyzer.ChunkSize = 3

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Mine = %#v, want no parameters from a length rejection", got)
	}
	// Two baseline requests and one chunk: a length rejection must not trigger
	// bisection.
	if count := requests.Load(); count != 3 {
		t.Fatalf("requests = %d, want 3", count)
	}
}

func TestMineUsesConfiguredValue(t *testing.T) {
	var (
		mu     sync.Mutex
		values []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, current := range r.URL.Query() {
			values = append(values, current...)
		}
		mu.Unlock()
		io.WriteString(w, "static page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"alpha", "beta"}
	analyzer.ChunkSize = 2
	analyzer.Value = "probe_marker"

	if _, err := analyzer.Mine(context.Background(), server.URL, nil); err != nil {
		t.Fatalf("Mine: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(values) != 2 {
		t.Fatalf("values = %#v, want two probe values", values)
	}
	for _, value := range values {
		if value != "probe_marker" {
			t.Fatalf("probe value = %q, want probe_marker", value)
		}
	}
}

func TestMineDeduplicatesCandidates(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if hasQuery(r, "debug") {
			io.WriteString(w, "debug trace enabled")
			return
		}
		io.WriteString(w, "clean page")
	}))
	defer server.Close()

	analyzer := New(testClient(t))
	analyzer.Words = []string{"debug", "debug", "beta"}
	analyzer.ChunkSize = 3

	got, err := analyzer.Mine(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	expectNames(t, got, []string{"debug"})
	// Two baseline requests, one two-name chunk and two leaves; a repeated
	// name would make the chunk three names wide and cost an extra request.
	if count := requests.Load(); count != 5 {
		t.Fatalf("requests = %d, want 5", count)
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	analyzer := New(testClient(t))
	if analyzer.ChunkSize != DefaultChunkSize {
		t.Fatalf("ChunkSize = %d, want %d", analyzer.ChunkSize, DefaultChunkSize)
	}
	if analyzer.MaxRequests != DefaultMaxRequests {
		t.Fatalf("MaxRequests = %d, want %d", analyzer.MaxRequests, DefaultMaxRequests)
	}
	if analyzer.Value != DefaultValue {
		t.Fatalf("Value = %q, want %q", analyzer.Value, DefaultValue)
	}
	if len(analyzer.Words) < 200 || len(analyzer.Words) > 500 {
		t.Fatalf("default wordlist has %d entries, want 200 to 500", len(analyzer.Words))
	}

	seen := make(map[string]struct{}, len(analyzer.Words))
	for _, word := range analyzer.Words {
		if word == "" || strings.TrimSpace(word) != word {
			t.Fatalf("default wordlist contains a malformed name %q", word)
		}
		if strings.ContainsAny(word, "&=#?/") {
			t.Fatalf("default wordlist contains %q, which is not a bare parameter name", word)
		}
		if _, duplicate := seen[word]; duplicate {
			t.Fatalf("default wordlist repeats %q", word)
		}
		seen[word] = struct{}{}
	}

	for _, name := range []string{"debug", "test", "admin", "beta", "api_key", "redirect", "callback", "token", "preview"} {
		if _, ok := seen[name]; !ok {
			t.Errorf("default wordlist is missing %q", name)
		}
	}

	analyzer.Words[0] = "mutated"
	if New(testClient(t)).Words[0] == "mutated" {
		t.Fatal("New shares the built-in wordlist between analyzers")
	}
}
