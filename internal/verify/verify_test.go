package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
)

func tokenFinding(rule, token string) finding.Finding {
	return finding.Finding{
		Kind:        finding.KindSecret,
		Category:    "Test",
		RuleID:      rule,
		Title:       rule,
		URL:         "https://target.test/app.js",
		Value:       token,
		Context:     "const token = \"" + token + "\";",
		Fingerprint: "fp",
		Confidence:  confidence.Score{Base: 85, Value: 85, Band: confidence.BandOf(85)},
	}
}

func fieldValue(candidate finding.Finding, name string) string {
	for _, field := range candidate.Fields {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

// identityServer asserts the request shape and answers like a provider.
func identityServer(t *testing.T, method, path string, headers map[string]string, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			t.Errorf("method = %s, want %s", r.Method, method)
		}
		if r.URL.Path != path {
			t.Errorf("path = %s, want %s", r.URL.Path, path)
		}
		for name, want := range headers {
			if got := r.Header.Get(name); got != want {
				t.Errorf("header %s = %q, want %q", name, got, want)
			}
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestApplyVerifiesSupportedProviders(t *testing.T) {
	cases := []struct {
		name       string
		rule       string
		token      string
		method     string
		path       string
		headers    map[string]string
		body       string
		wantStatus string
	}{
		{
			name: "github classic", rule: "secret.github-token", token: "ghp_testtoken",
			method: http.MethodGet, path: "/user",
			headers: map[string]string{
				"Authorization": "Bearer ghp_testtoken",
				"User-Agent":    "solitools",
			},
			body: `{"login":"octocat"}`, wantStatus: "active (octocat)",
		},
		{
			name: "github fine grained", rule: "secret.github-fine-grained-pat", token: "github_pat_test",
			method: http.MethodGet, path: "/user",
			headers: map[string]string{
				"Authorization": "Bearer github_pat_test",
				"User-Agent":    "solitools",
			},
			body: `{"login":"fine-user"}`, wantStatus: "active (fine-user)",
		},
		{
			name: "slack", rule: "secret.slack-token", token: "xoxb-test-token",
			method: http.MethodPost, path: "/api/auth.test",
			headers:    map[string]string{"Authorization": "Bearer xoxb-test-token"},
			body:       `{"ok":true,"user":"alice","team":"acme"}`,
			wantStatus: "active (alice)",
		},
		{
			name: "gitlab", rule: "secret.gitlab-pat", token: "glpat-testtoken",
			method: http.MethodGet, path: "/api/v4/user",
			headers:    map[string]string{"Authorization": "Bearer glpat-testtoken"},
			body:       `{"username":"gl-user"}`,
			wantStatus: "active (gl-user)",
		},
		{
			name: "openai", rule: "secret.openai-api-key", token: "sk-proj-test",
			method: http.MethodGet, path: "/v1/models",
			headers:    map[string]string{"Authorization": "Bearer sk-proj-test"},
			body:       `{"data":[]}`,
			wantStatus: "active",
		},
		{
			name: "anthropic", rule: "secret.anthropic-api-key", token: "sk-ant-api03-test",
			method: http.MethodGet, path: "/v1/models",
			headers: map[string]string{
				"x-api-key":         "sk-ant-api03-test",
				"anthropic-version": "2023-06-01",
			},
			body: `{"data":[]}`, wantStatus: "active",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := identityServer(t, testCase.method, testCase.path, testCase.headers, http.StatusOK, testCase.body)

			spec, ok := specFor(testCase.rule)
			if !ok {
				t.Fatalf("no provider for %s", testCase.rule)
			}
			verifier := New()
			verifier.BaseURLs[spec.name] = server.URL

			findings := verifier.Apply(context.Background(), []finding.Finding{
				tokenFinding(testCase.rule, testCase.token),
			})
			if len(findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(findings))
			}
			verified := findings[0]

			if verified.Confidence.Value != 100 {
				t.Fatalf("confidence = %v, want clamped 100", verified.Confidence.Value)
			}
			if verified.Confidence.Band != confidence.BandCritical {
				t.Fatalf("band = %q, want critical", verified.Confidence.Band)
			}
			signals := verified.Confidence.Signals
			if len(signals) != 1 {
				t.Fatalf("signals = %+v, want one live-validation signal", signals)
			}
			if signals[0].Name != "live-validation" || signals[0].Delta != 15 {
				t.Fatalf("signal = %+v, want live-validation +15", signals[0])
			}
			if got := fieldValue(verified, "Status"); got != testCase.wantStatus {
				t.Fatalf("status = %q, want %q", got, testCase.wantStatus)
			}
			assertNoTokenInFields(t, verified, testCase.token)
		})
	}
}

func TestApplyMarksRevokedCredentials(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		server := identityServer(t, http.MethodGet, "/user", nil, status, `{"message":"Bad credentials"}`)
		verifier := New()
		verifier.BaseURLs["github"] = server.URL

		findings := verifier.Apply(context.Background(), []finding.Finding{
			tokenFinding("secret.github-token", "ghp_revoked"),
		})
		revoked := findings[0]
		if revoked.Confidence.Value != 55 {
			t.Fatalf("status %d: confidence = %v, want 55", status, revoked.Confidence.Value)
		}
		if revoked.Confidence.Band != confidence.BandMedium {
			t.Fatalf("status %d: band = %q, want medium", status, revoked.Confidence.Band)
		}
		if got := fieldValue(revoked, "Status"); got != "revoked / invalid" {
			t.Fatalf("status field = %q", got)
		}
		signals := revoked.Confidence.Signals
		if len(signals) != 1 || signals[0].Delta != -30 {
			t.Fatalf("signals = %+v, want one -30 signal", signals)
		}
		assertNoTokenInFields(t, revoked, "ghp_revoked")
	}
}

// TestApplyTreatsSlackOKFalseAsRevoked covers Slack answering 200 with ok:false.
func TestApplyTreatsSlackOKFalseAsRevoked(t *testing.T) {
	server := identityServer(t, http.MethodPost, "/api/auth.test", nil,
		http.StatusOK, `{"ok":false,"error":"invalid_auth"}`)
	verifier := New()
	verifier.BaseURLs["slack"] = server.URL

	findings := verifier.Apply(context.Background(), []finding.Finding{
		tokenFinding("secret.slack-token", "xoxb-invalid"),
	})
	if got := fieldValue(findings[0], "Status"); got != "revoked / invalid" {
		t.Fatalf("status = %q, want revoked", got)
	}
	if findings[0].Confidence.Value != 55 {
		t.Fatalf("confidence = %v, want 55", findings[0].Confidence.Value)
	}
}

func TestApplySkipsTransientFailures(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantReason string
	}{
		{"rate limited", http.StatusTooManyRequests, "rate limited by provider"},
		{"provider error", http.StatusInternalServerError, "provider returned 500"},
		{"not found", http.StatusNotFound, "provider returned 404"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := identityServer(t, http.MethodGet, "/user", nil, testCase.status, "")
			verifier := New()
			verifier.BaseURLs["github"] = server.URL

			findings := verifier.Apply(context.Background(), []finding.Finding{
				tokenFinding("secret.github-token", "ghp_transient"),
			})
			skipped := findings[0]
			if skipped.Confidence.Value != 85 || len(skipped.Confidence.Signals) != 0 {
				t.Fatalf("a skipped check must not change the score: %+v", skipped.Confidence)
			}
			if got := fieldValue(skipped, "Validation"); got != "skipped ("+testCase.wantReason+")" {
				t.Fatalf("validation = %q", got)
			}
		})
	}
}

func TestApplySkipsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, `{"login":"late"}`)
	}))
	defer server.Close()

	verifier := New()
	verifier.Client.Timeout = 30 * time.Millisecond
	verifier.BaseURLs["github"] = server.URL

	findings := verifier.Apply(context.Background(), []finding.Finding{
		tokenFinding("secret.github-token", "ghp_slow"),
	})
	skipped := findings[0]
	if skipped.Confidence.Value != 85 {
		t.Fatalf("confidence = %v, want the structural 85", skipped.Confidence.Value)
	}
	if got := fieldValue(skipped, "Validation"); got != "skipped (timeout)" {
		t.Fatalf("validation = %q, want timeout", got)
	}
}

func TestApplySkipsNetworkFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	address := server.URL
	server.Close()

	verifier := New()
	verifier.BaseURLs["gitlab"] = address

	findings := verifier.Apply(context.Background(), []finding.Finding{
		tokenFinding("secret.gitlab-pat", "glpat-dead"),
	})
	if got := fieldValue(findings[0], "Validation"); got != "skipped (network error)" {
		t.Fatalf("validation = %q, want network error", got)
	}
	if findings[0].Confidence.Signals != nil {
		t.Fatalf("a network failure must not add a signal: %+v", findings[0].Confidence.Signals)
	}
}

func TestApplyLeavesUnsupportedRulesAlone(t *testing.T) {
	verifier := New()
	findings := verifier.Apply(context.Background(), []finding.Finding{
		tokenFinding("secret.aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
	})
	untouched := findings[0]
	if untouched.Confidence.Value != 85 || len(untouched.Fields) != 0 {
		t.Fatalf("an unsupported rule must be untouched: %+v", untouched)
	}
	if Supported("secret.aws-access-key-id") {
		t.Fatal("AWS keys have no validator and must not be advertised as supported")
	}
	if !Supported("secret.github-token") {
		t.Fatal("GitHub tokens are supported")
	}
}

// TestApplyRefusesRedirects keeps a token from travelling along a redirect
// chain: the verifier must report the 302 and stop.
func TestApplyRefusesRedirects(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer server.Close()

	verifier := New()
	verifier.BaseURLs["github"] = server.URL
	findings := verifier.Apply(context.Background(), []finding.Finding{
		tokenFinding("secret.github-token", "ghp_redirect"),
	})

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("provider hits = %d, want 1; the redirect must not be followed", got)
	}
	if got := fieldValue(findings[0], "Validation"); got != "skipped (provider returned 302)" {
		t.Fatalf("validation = %q, want a skipped 302", got)
	}
}

func TestApplyDoesNotMutateInput(t *testing.T) {
	server := identityServer(t, http.MethodGet, "/user", nil, http.StatusOK, `{"login":"octocat"}`)
	verifier := New()
	verifier.BaseURLs["github"] = server.URL

	original := []finding.Finding{tokenFinding("secret.github-token", "ghp_original")}
	updated := verifier.Apply(context.Background(), original)

	if original[0].Confidence.Value != 85 || len(original[0].Confidence.Signals) != 0 {
		t.Fatalf("Apply mutated its input: %+v", original[0].Confidence)
	}
	if updated[0].Confidence.Value != 100 {
		t.Fatalf("updated confidence = %v, want 100", updated[0].Confidence.Value)
	}
}

func assertNoTokenInFields(t *testing.T, candidate finding.Finding, token string) {
	t.Helper()
	for _, field := range candidate.Fields {
		if strings.Contains(field.Value, token) {
			t.Fatalf("field %s leaked the token: %q", field.Name, field.Value)
		}
	}
}
