// Package verify checks detected credentials against provider identity APIs.
//
// It is the only code path in SoliTools that contacts a third party, and it
// runs only when the caller opts in. Three rules make that safe:
//
//   - Tokens travel in request headers, never in URLs, and are never written to
//     a field, a status line or an error message.
//   - The scan client is not reused. A fresh client with its own timeout and no
//     target headers or cookies is mandatory, otherwise a target's
//     Authorization header would leak to a provider.
//   - Every check is read-only: no writes, no state changes, no redirects.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/errgroup"
	"github.com/soliofski/SoliTools/internal/finding"
)

// Default provider origins. Tests override an entry in Verifier.BaseURLs with
// an httptest server, so nothing else needs to be configurable.
const (
	GitHubBase    = "https://api.github.com"
	SlackBase     = "https://slack.com"
	GitLabBase    = "https://gitlab.com"
	OpenAIBase    = "https://api.openai.com"
	AnthropicBase = "https://api.anthropic.com"
)

// maxBody bounds what a provider can make the verifier read.
const maxBody = 1 << 20

// Verifier performs read-only identity checks.
type Verifier struct {
	// Client performs the requests. It must not carry target credentials; New
	// builds a clean one.
	Client *http.Client
	// BaseURLs maps a provider name to its origin. A missing entry falls back
	// to the documented default, so a test overrides only what it exercises.
	BaseURLs map[string]string
	// Workers bounds concurrent checks. Zero means four.
	Workers int
}

// New returns a verifier with a clean, bounded HTTP client.
func New() *Verifier {
	return &Verifier{
		Client:   newHTTPClient(),
		BaseURLs: make(map[string]string),
		Workers:  4,
	}
}

// defaultClient is the fallback for a zero-value Verifier. Constructed clients
// are per-verifier, so a test that changes a timeout cannot affect another.
var defaultClient = newHTTPClient()

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		// A redirect is not an identity answer, and following one could carry a
		// token somewhere it was not meant to go.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpClient falls back to the default rather than panicking on a zero-value
// Verifier.
func (v *Verifier) httpClient() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return defaultClient
}

// verdict is the outcome of one provider check.
type verdict int

const (
	verdictSkipped verdict = iota
	verdictActive
	verdictRevoked
)

// outcome is what a provider said about one credential.
type outcome struct {
	Verdict  verdict
	Identity string
	Reason   string
}

// Apply validates every supported secret finding and returns a new slice; the
// input is not modified. Checks run with at most Workers concurrent requests,
// one request per finding, and unsupported providers are untouched.
func (v *Verifier) Apply(ctx context.Context, findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	workers := v.Workers
	if workers <= 0 {
		workers = 4
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(workers)
	for index := range out {
		if out[index].Kind != finding.KindSecret || out[index].Value == "" {
			continue
		}
		spec, ok := specFor(out[index].RuleID)
		if !ok {
			continue
		}
		index := index
		token := out[index].Value
		group.Go(func() error {
			apply(&out[index], v.check(groupCtx, spec, token))
			return nil
		})
	}
	_ = group.Wait()
	return out
}

// Supported reports whether a rule has a read-only validator, so a caller can
// tell "nothing to check" from "checked and clean".
func Supported(ruleID string) bool {
	_, ok := specFor(ruleID)
	return ok
}

// check performs one request and turns the answer into an outcome.
func (v *Verifier) check(ctx context.Context, spec providerSpec, token string) outcome {
	base := v.BaseURLs[spec.name]
	if base == "" {
		base = spec.baseURL
	}

	status, body, err := v.do(ctx, spec, base, token)
	if err != nil {
		return outcome{Verdict: verdictSkipped, Reason: classify(err)}
	}

	switch status {
	case http.StatusOK:
		return spec.interpret(body)
	case http.StatusUnauthorized, http.StatusForbidden:
		return outcome{Verdict: verdictRevoked}
	case http.StatusTooManyRequests:
		return outcome{Verdict: verdictSkipped, Reason: "rate limited by provider"}
	default:
		return outcome{Verdict: verdictSkipped, Reason: fmt.Sprintf("provider returned %d", status)}
	}
}

func (v *Verifier) do(ctx context.Context, spec providerSpec, base, token string) (int, []byte, error) {
	request, err := spec.build(ctx, base, token)
	if err != nil {
		return 0, nil, err
	}
	response, err := v.httpClient().Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, body, nil
}

// apply records the outcome on one finding: score signal, band, status field.
// Skipped checks deliberately leave the structural score untouched.
func apply(target *finding.Finding, outcome outcome) {
	switch outcome.Verdict {
	case verdictActive:
		target.Confidence = confidence.Adjust(target.Confidence,
			"live-validation", 15, "confirmed active by provider identity API")
		status := "active"
		if outcome.Identity != "" {
			status = fmt.Sprintf("active (%s)", outcome.Identity)
		}
		target.WithField("Status", status)
	case verdictRevoked:
		target.Confidence = confidence.Adjust(target.Confidence,
			"live-validation", -30, "provider returned 401/403 (revoked or expired)")
		target.WithField("Status", "revoked / invalid")
	case verdictSkipped:
		target.WithField("Validation", "skipped ("+outcome.Reason+")")
	}
}

// classify names the failure without ever echoing the request, which is how a
// token would otherwise reach a log line.
func classify(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "network error"
}

// providerSpec ties a set of rule IDs to one read-only endpoint.
type providerSpec struct {
	name      string
	baseURL   string
	rules     []string
	build     func(ctx context.Context, base, token string) (*http.Request, error)
	interpret func(body []byte) outcome
}

// specFor finds the validator for a rule id.
func specFor(ruleID string) (providerSpec, bool) {
	for _, spec := range providerSpecs {
		for _, rule := range spec.rules {
			if rule == ruleID {
				return spec, true
			}
		}
	}
	return providerSpec{}, false
}

// jsonRequest builds a bearer-authenticated GET/POST with an optional header
// hook (GitHub wants a User-Agent, Anthropic uses x-api-key instead).
func jsonRequest(method, path string, decorate func(*http.Request)) func(context.Context, string, string) (*http.Request, error) {
	return func(ctx context.Context, base, token string) (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Accept", "application/json")
		if decorate != nil {
			decorate(request)
		}
		return request, nil
	}
}

// identityFrom decodes one string field from a JSON object. A missing field is
// not a failure: several providers answer 200 without naming the caller.
func identityFrom(field string) func([]byte) outcome {
	return func(body []byte) outcome {
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		identity, _ := payload[field].(string)
		return outcome{Verdict: verdictActive, Identity: identity}
	}
}

// activeOutcome is for endpoints whose 200 proves the key works but names no
// caller (OpenAI and Anthropic model listings).
func activeOutcome([]byte) outcome {
	return outcome{Verdict: verdictActive}
}

// slackIdentity treats a 200 with ok=false as an auth failure: Slack answers
// invalid tokens that way instead of with a 401.
func slackIdentity(body []byte) outcome {
	var payload struct {
		OK    bool   `json:"ok"`
		User  string `json:"user"`
		Team  string `json:"team"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	if !payload.OK {
		reason := payload.Error
		if reason == "" {
			reason = "invalid_auth"
		}
		return outcome{Verdict: verdictRevoked, Reason: reason}
	}
	identity := payload.User
	if identity == "" {
		identity = payload.Team
	}
	return outcome{Verdict: verdictActive, Identity: identity}
}

func anthropicRequest(ctx context.Context, base, token string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-api-key", token)
	request.Header.Set("anthropic-version", "2023-06-01")
	request.Header.Set("Accept", "application/json")
	return request, nil
}

var providerSpecs = []providerSpec{
	{
		name:    "github",
		baseURL: GitHubBase,
		rules:   []string{"secret.github-token", "secret.github-fine-grained-pat"},
		build: jsonRequest(http.MethodGet, "/user", func(request *http.Request) {
			request.Header.Set("User-Agent", "solitools")
		}),
		interpret: identityFrom("login"),
	},
	{
		name:      "slack",
		baseURL:   SlackBase,
		rules:     []string{"secret.slack-token"},
		build:     jsonRequest(http.MethodPost, "/api/auth.test", nil),
		interpret: slackIdentity,
	},
	{
		name:      "gitlab",
		baseURL:   GitLabBase,
		rules:     []string{"secret.gitlab-pat"},
		build:     jsonRequest(http.MethodGet, "/api/v4/user", nil),
		interpret: identityFrom("username"),
	},
	{
		name:      "openai",
		baseURL:   OpenAIBase,
		rules:     []string{"secret.openai-api-key"},
		build:     jsonRequest(http.MethodGet, "/v1/models", nil),
		interpret: activeOutcome,
	},
	{
		name:      "anthropic",
		baseURL:   AnthropicBase,
		rules:     []string{"secret.anthropic-api-key"},
		build:     anthropicRequest,
		interpret: activeOutcome,
	},
}
