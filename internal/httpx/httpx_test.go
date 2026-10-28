package httpx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

func TestPostFormEncodesBody(t *testing.T) {
	var (
		gotMethod string
		gotType   string
		gotBody   string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotType = r.Header.Get("Content-Type")
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		gotBody = string(raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	response, err := testClient(t).PostForm(context.Background(), server.URL+"/submit",
		url.Values{"a": {"1"}, "b": {"two words"}})
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	if response.Status != http.StatusNoContent {
		t.Fatalf("status = %d", response.Status)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if !strings.HasPrefix(gotType, "application/x-www-form-urlencoded") {
		t.Fatalf("content type = %q", gotType)
	}
	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("body %q is not form-encoded: %v", gotBody, err)
	}
	if values.Get("a") != "1" || values.Get("b") != "two words" {
		t.Fatalf("body values = %v", values)
	}
}

func TestFetchFollowsRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("landed"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	response, err := testClient(t).Fetch(context.Background(), server.URL+"/a")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if response.URL != server.URL+"/b" {
		t.Fatalf("final URL = %q, want %q", response.URL, server.URL+"/b")
	}
	if response.BodyString() != "landed" {
		t.Fatalf("body = %q", response.BodyString())
	}
}

func TestGetDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/solitools-redirect-check", http.StatusFound)
	}))
	defer server.Close()

	response, err := testClient(t).Get(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if response.Status != http.StatusFound {
		t.Fatalf("status = %d, want the raw 302", response.Status)
	}
	if response.Location() == "" {
		t.Fatal("Location header was lost")
	}
}

func TestInvalidURLIsClassified(t *testing.T) {
	client := testClient(t)
	for _, target := range []string{"ftp://example.com/x", "example.com", "javascript:alert(1)"} {
		_, err := client.Get(context.Background(), target)
		if err == nil {
			t.Fatalf("%q should be rejected", target)
		}
		if KindOf(err) != ErrInvalidURL {
			t.Fatalf("%q: kind = %q, want %q", target, KindOf(err), ErrInvalidURL)
		}
	}
}

func TestObserverSeesResponsesAndCanBeCleared(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := New(Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	var seen int32
	client.SetObserver(func(*Response) { atomic.AddInt32(&seen, 1) })

	for i := 0; i < 2; i++ {
		if _, err := client.Get(context.Background(), server.URL); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if got := atomic.LoadInt32(&seen); got != 2 {
		t.Fatalf("observer calls = %d, want 2", got)
	}

	client.SetObserver(nil)
	if _, err := client.Get(context.Background(), server.URL); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := atomic.LoadInt32(&seen); got != 2 {
		t.Fatalf("observer calls after clear = %d, want 2", got)
	}
}

func TestRequestCounter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := testClient(t)
	for i := 0; i < 3; i++ {
		if _, err := client.Get(context.Background(), server.URL+"/"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if got := client.Requests(); got != 3 {
		t.Fatalf("Requests() = %d, want 3", got)
	}
}

func TestCustomHeadersAreApplied(t *testing.T) {
	var gotAuth, gotCookie, gotAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(Options{
		Rate:    500,
		Headers: []string{"Authorization: Bearer token"},
		Cookie:  "session=abc",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Get(context.Background(), server.URL+"/"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotAuth != "Bearer token" || gotCookie != "session=abc" {
		t.Fatalf("auth = %q, cookie = %q", gotAuth, gotCookie)
	}
	if gotAgent != DefaultUserAgent {
		t.Fatalf("user agent = %q", gotAgent)
	}
}

func TestMalformedHeaderIsRejected(t *testing.T) {
	if _, err := New(Options{Headers: []string{"NoColonHere"}}); err == nil {
		t.Fatal("a header without a colon must be rejected")
	}
}
