package reflect

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSubmitRecordsReflectedCanaries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{URL: server.URL + "/?q=x", Name: "q"})
	if len(submission.Reflected) != len(Payloads()) {
		t.Fatalf("reflected canaries = %v, want all %d", submission.Reflected, len(Payloads()))
	}
	if submission.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", submission.Status)
	}
	if _, ok := Analyze(submission); !ok {
		t.Fatal("Analyze must still produce the reflected finding")
	}
}

// TestStoredDetectsPersistedCanary is the happy path: the POST is acknowledged
// without echoing the value, and a later GET serves it from storage.
func TestStoredDetectsPersistedCanary(t *testing.T) {
	var mu sync.Mutex
	var saved string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			saved = r.PostFormValue("comment")
			mu.Unlock()
			w.Write([]byte("thanks"))
			return
		}
		mu.Lock()
		value := saved
		mu.Unlock()
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", value)
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{
		URL: server.URL + "/post", Name: "comment", Method: http.MethodPost,
	})
	if len(submission.Reflected) != 0 {
		t.Fatalf("immediate response echoed %v, want nothing", submission.Reflected)
	}

	findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	stored := findings[0]
	if stored.RuleID != "reflect.stored" || stored.Category != "Stored XSS" {
		t.Fatalf("rule = %q category = %q", stored.RuleID, stored.Category)
	}
	if stored.Confidence.Value < 75 {
		t.Fatalf("confidence = %v, want high for a stored payload in the HTML body", stored.Confidence.Value)
	}
	if stored.Value != Payloads()[2] {
		t.Fatalf("payload = %q, want the tag-breaking canary", stored.Value)
	}
	if !hasField(stored, "Method", http.MethodPost) {
		t.Fatalf("fields = %+v, want a Method: POST line", stored.Fields)
	}
	if !hasField(stored, "Storage", "absent from the immediate response, served on re-fetch") {
		t.Fatalf("fields = %+v, want the storage explanation", stored.Fields)
	}
}

// TestStoredIgnoresImmediateReflection keeps the two rules disjoint: a value
// that came back at once is reflection, no matter that the page also keeps it.
func TestStoredIgnoresImmediateReflection(t *testing.T) {
	var mu sync.Mutex
	var saved string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			value := r.PostFormValue("comment")
			mu.Lock()
			saved = value
			mu.Unlock()
			fmt.Fprintf(w, "<div>%s</div>", value)
			return
		}
		mu.Lock()
		value := saved
		mu.Unlock()
		fmt.Fprintf(w, "<div>%s</div>", value)
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{
		URL: server.URL + "/post", Name: "comment", Method: http.MethodPost,
	})
	if len(submission.Reflected) != len(Payloads()) {
		t.Fatalf("reflected = %v, want every canary", submission.Reflected)
	}
	if findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission}); len(findings) != 0 {
		t.Fatalf("findings = %d, want none: reflection is already reported", len(findings))
	}
}

// TestStoredRejectsEncodedPersistence is the encoding guard: escaping the angle
// brackets means the value is stored but not injectable.
func TestStoredRejectsEncodedPersistence(t *testing.T) {
	var mu sync.Mutex
	var saved string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			saved = html.EscapeString(r.PostFormValue("comment"))
			mu.Unlock()
			w.Write([]byte("thanks"))
			return
		}
		mu.Lock()
		value := saved
		mu.Unlock()
		fmt.Fprintf(w, "<div>%s</div>", value)
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{
		URL: server.URL + "/post", Name: "comment", Method: http.MethodPost,
	})
	if findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission}); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for an HTML-escaped stored value", len(findings))
	}
}

// TestStoredNeedsTwoCanariesOrTagBreak mirrors the reflected rule: a lone
// alphanumeric canary proves storage but not injectability.
func TestStoredNeedsTwoCanariesOrTagBreak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write([]byte("thanks"))
			return
		}
		fmt.Fprintf(w, "<div>%s</div>", Payloads()[0])
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{
		URL: server.URL + "/post", Name: "comment", Method: http.MethodPost,
	})
	if findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission}); len(findings) != 0 {
		t.Fatalf("findings = %d, want none when only the alphanumeric canary survived", len(findings))
	}
}

// TestStoredScoresCommentLow keeps a stored payload in a comment visible to
// -all without letting it reach the default threshold.
func TestStoredScoresCommentLow(t *testing.T) {
	var mu sync.Mutex
	var saved string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			saved = r.PostFormValue("comment")
			mu.Unlock()
			w.Write([]byte("thanks"))
			return
		}
		mu.Lock()
		value := saved
		mu.Unlock()
		if value != "" {
			fmt.Fprintf(w, "<html><body><!-- %s --></body></html>", value)
			return
		}
		w.Write([]byte("<html><body>empty</body></html>"))
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := analyzer.Submit(context.Background(), Target{
		URL: server.URL + "/post", Name: "comment", Method: http.MethodPost,
	})
	findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the low-confidence comment finding", len(findings))
	}
	if findings[0].Confidence.Value >= 60 {
		t.Fatalf("confidence = %v, want below the default threshold", findings[0].Confidence.Value)
	}
	if !hasField(findings[0], "Reflection Point", string(ContextComment)) {
		t.Fatalf("fields = %+v, want the comment context", findings[0].Fields)
	}
}

func TestStoredIgnoresErrorResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "<div>%s</div>", Payloads()[2])
	}))
	defer server.Close()

	analyzer := New(newTestClient(t))
	submission := Submission{
		Target:    Target{URL: server.URL + "/post", Name: "comment", Method: http.MethodPost},
		Reflected: map[string]bool{},
	}
	if findings := analyzer.Stored(context.Background(), server.URL+"/list", []Submission{submission}); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a 404 page", len(findings))
	}
}

func TestStoredIgnoresEmptyInput(t *testing.T) {
	analyzer := New(newTestClient(t))
	if findings := analyzer.Stored(context.Background(), "", nil); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for an empty request", len(findings))
	}
	if findings := analyzer.Stored(context.Background(), "http://example.test/", nil); len(findings) != 0 {
		t.Fatalf("findings = %d, want none without submissions", len(findings))
	}
}
