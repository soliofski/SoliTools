// Package parammine discovers hidden query parameters by differential probing.
//
// The technique is deliberately simple and measurable: request the target URL
// twice to prove the response is stable, then append chunks of candidate names
// with a benign marker value. A chunk that changes the response is split in
// half until the individual names that caused the change are isolated, so a
// wordlist that would need hundreds of requests is tested with a bounded,
// auditable number of them.
//
// Precision boundaries are part of the contract:
//
//   - An unstable baseline (status, body length or body hash moves between two
//     identical requests) is an error, never a guess.
//   - Only GET requests to the given origin are issued, through the shared
//     httpx client, so the global rate limiter applies and no redirect is
//     followed.
//   - 414 and 431 responses are inconclusive: they report that the request
//     line or headers grew, not that a parameter was understood. Bisecting
//     them would report every name in the chunk.
//   - Bisection assumes a parameter keeps its effect when probed alone.
//     Parameters that only matter together are out of scope.
//   - Bodies are compared after the client's body cap, so a difference that
//     exists only beyond the cap is invisible to the comparison.
//   - A name isolated at the end of bisection rests on one differential
//     response; callers that need stronger evidence should re-probe it.
package parammine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/soliofski/SoliTools/internal/httpx"
)

// Defaults applied when an Analyzer field is left at its zero value.
const (
	// DefaultChunkSize is how many candidate names each request appends.
	DefaultChunkSize = 25

	// DefaultMaxRequests bounds the total number of requests in one Mine call,
	// including the two baseline requests.
	DefaultMaxRequests = 120

	// DefaultValue is the benign marker sent as every probed parameter value.
	DefaultValue = "soli_probe"
)

// Errors returned by Mine. Every error except ErrUnstableBaseline means no
// probe ran; an unstable baseline is the one case where a difference was
// observed but cannot be attributed to any parameter.
var (
	// ErrNoClient reports that the Analyzer was built without an httpx client.
	ErrNoClient = errors.New("parammine: analyzer has no HTTP client")

	// ErrInvalidTarget reports a target that is not an absolute http(s) URL.
	ErrInvalidTarget = errors.New("parammine: target must be an absolute http(s) URL")

	// ErrBudgetTooSmall reports a MaxRequests value that cannot cover the two
	// baseline requests.
	ErrBudgetTooSmall = errors.New("parammine: MaxRequests must allow two baseline requests")

	// ErrUnstableBaseline reports a target whose identical requests produce
	// different responses.
	ErrUnstableBaseline = errors.New("parammine: baseline response is unstable")
)

// Analyzer mines hidden query parameters through a shared httpx client.
type Analyzer struct {
	client *httpx.Client

	// Words is the candidate wordlist. A nil or empty slice selects the
	// built-in list of common hidden parameter names.
	Words []string

	// ChunkSize is how many names are appended per request. Zero selects
	// DefaultChunkSize.
	ChunkSize int

	// MaxRequests bounds the whole Mine call, baseline included. Zero selects
	// DefaultMaxRequests. Values below two cannot verify a baseline and are
	// rejected.
	MaxRequests int

	// Value is the benign marker sent for every name. Zero selects
	// DefaultValue. The value stays constant during a run, so a body change is
	// attributable to the parameter name rather than to varying input length.
	Value string
}

// New builds an Analyzer around client. The returned Analyzer owns a copy of
// the built-in wordlist, so callers may edit Words without affecting others.
func New(client *httpx.Client) *Analyzer {
	return &Analyzer{
		client:      client,
		Words:       append([]string(nil), defaultWords...),
		ChunkSize:   DefaultChunkSize,
		MaxRequests: DefaultMaxRequests,
		Value:       DefaultValue,
	}
}

// Mine discovers hidden query parameters on targetURL.
//
// It requests targetURL twice and refuses to continue unless both responses
// share status, body length and body hash. It then appends chunks of candidate
// names to the existing query and bisects every chunk whose response differs
// from the baseline. The result is sorted, deduplicated and never longer than
// MaxRequests.
//
// Names in existing, and names already present in the target query, are never
// probed: re-adding them would change a value the baseline relies on.
//
// When the request budget runs out, Mine returns the parameters found so far
// with a nil error, because the cap is an intended bound rather than a
// failure. When ctx is cancelled it returns nil and ctx.Err(), because a
// partial list would be indistinguishable from a complete one. A nil ctx is
// treated as context.Background().
func (a *Analyzer) Mine(ctx context.Context, targetURL string, existing []string) ([]string, error) {
	if a == nil || a.client == nil {
		return nil, ErrNoClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	base, err := parseTarget(targetURL)
	if err != nil {
		return nil, err
	}

	chunkSize := a.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	budget := a.MaxRequests
	if budget <= 0 {
		budget = DefaultMaxRequests
	}
	if budget < 2 {
		return nil, fmt.Errorf("%w: got %d", ErrBudgetTooSmall, budget)
	}
	value := a.Value
	if value == "" {
		value = DefaultValue
	}

	run := &session{
		client: a.client,
		ctx:    ctx,
		base:   base,
		value:  value,
		budget: budget,
		found:  make(map[string]struct{}),
	}

	first, ok, err := run.fetch(nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: got %d", ErrBudgetTooSmall, budget)
	}
	second, ok, err := run.fetch(nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: got %d", ErrBudgetTooSmall, budget)
	}
	reference, err := stableFingerprint(first, second)
	if err != nil {
		return nil, err
	}
	run.reference = reference

	words := a.candidates(buildSkip(existing, base.RawQuery))
	for start := 0; start < len(words); start += chunkSize {
		end := start + chunkSize
		if end > len(words) {
			end = len(words)
		}
		if err := run.mine(words[start:end]); err != nil {
			return nil, err
		}
		if run.exhausted {
			break
		}
	}

	found := make([]string, 0, len(run.found))
	for name := range run.found {
		found = append(found, name)
	}
	sort.Strings(found)
	if len(found) > budget {
		found = found[:budget]
	}
	return found, nil
}

// session carries the state of one Mine call.
type session struct {
	client    *httpx.Client
	ctx       context.Context
	base      *url.URL
	reference fingerprint
	value     string
	budget    int
	used      int
	found     map[string]struct{}
	exhausted bool
}

// fingerprint is the part of a response the differential test compares.
type fingerprint struct {
	status int
	length int
	digest [sha256.Size]byte
}

func fingerprintOf(response *httpx.Response) fingerprint {
	return fingerprint{
		status: response.Status,
		length: len(response.Body),
		digest: sha256.Sum256(response.Body),
	}
}

func (f fingerprint) equal(other fingerprint) bool {
	return f.status == other.status && f.length == other.length && f.digest == other.digest
}

// stableFingerprint compares two baseline responses and refuses to treat a
// moving target as a reference.
func stableFingerprint(first, second *httpx.Response) (fingerprint, error) {
	if first.Status != second.Status {
		return fingerprint{}, fmt.Errorf("%w: status %d then %d", ErrUnstableBaseline, first.Status, second.Status)
	}
	if len(first.Body) != len(second.Body) {
		return fingerprint{}, fmt.Errorf("%w: body length %d then %d", ErrUnstableBaseline, len(first.Body), len(second.Body))
	}
	firstDigest := sha256.Sum256(first.Body)
	secondDigest := sha256.Sum256(second.Body)
	if firstDigest != secondDigest {
		return fingerprint{}, fmt.Errorf("%w: body hash %x then %x", ErrUnstableBaseline, firstDigest[:], secondDigest[:])
	}
	return fingerprint{status: first.Status, length: len(first.Body), digest: firstDigest}, nil
}

// mine isolates the changed names inside one chunk.
func (s *session) mine(names []string) error {
	changed, err := s.changes(names)
	if err != nil || !changed {
		return err
	}
	if len(names) == 1 {
		s.found[names[0]] = struct{}{}
		return nil
	}
	middle := len(names) / 2
	if err := s.mine(names[:middle]); err != nil {
		return err
	}
	return s.mine(names[middle:])
}

// changes reports whether appending names moves the response away from the
// baseline.
func (s *session) changes(names []string) (bool, error) {
	response, ok, err := s.fetch(names)
	if err != nil || !ok {
		return false, err
	}
	if inconclusive(response.Status) {
		// The request grew past a server or proxy limit. That says nothing
		// about whether a name was understood, and bisecting it would report
		// every name in the chunk.
		return false, nil
	}
	return !s.reference.equal(fingerprintOf(response)), nil
}

func inconclusive(status int) bool {
	return status == http.StatusRequestURITooLong || status == http.StatusRequestHeaderFieldsTooLarge
}

// fetch issues one probe. ok is false when the budget or the context stopped
// the run before a request was sent.
func (s *session) fetch(names []string) (*httpx.Response, bool, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, false, err
	}
	if s.used >= s.budget {
		s.exhausted = true
		return nil, false, nil
	}
	s.used++
	response, err := s.client.Get(s.ctx, s.probeURL(names))
	if err != nil {
		return nil, false, transportError(s.ctx, err)
	}
	return response, true, nil
}

// probeURL appends encoded name=value pairs to the target's raw query without
// re-encoding what the caller already supplied.
func (s *session) probeURL(names []string) string {
	probe := *s.base
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(s.value))
	}
	if addition := strings.Join(pairs, "&"); addition != "" {
		if probe.RawQuery == "" {
			probe.RawQuery = addition
		} else {
			probe.RawQuery += "&" + addition
		}
	}
	return probe.String()
}

// transportError turns a client failure into a context error when the context
// was the cause, so callers can tell cancellation from a network fault.
func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("parammine: request failed: %w", err)
}

func parseTarget(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrInvalidTarget, parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidTarget)
	}
	return parsed, nil
}

// candidates trims, deduplicates and filters the wordlist for one run.
func (a *Analyzer) candidates(skip map[string]struct{}) []string {
	words := a.Words
	if len(words) == 0 {
		words = defaultWords
	}
	seen := make(map[string]struct{}, len(words))
	out := make([]string, 0, len(words))
	for _, raw := range words {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		if _, skipped := skip[name]; skipped {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// buildSkip collects the names that must not be probed: the caller's existing
// list and every name already present in the target query.
func buildSkip(existing []string, rawQuery string) map[string]struct{} {
	skip := make(map[string]struct{}, len(existing)+8)
	for _, raw := range existing {
		if name := strings.TrimSpace(raw); name != "" {
			skip[name] = struct{}{}
		}
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		if name != "" {
			skip[name] = struct{}{}
		}
	}
	return skip
}

// defaultWords is the built-in list of common hidden parameter names, ordered
// alphabetically so duplicates and gaps are easy to audit. It covers debug and
// feature flags, credentials, redirect and callback sinks, template and file
// selectors, and framework switches; names are never sent as-is, only appended
// as query parameters with a benign value.
var defaultWords = strings.Fields(`
access account action activate activity admin agent ajax alert alias
allow amount api api_key api_secret apikey app arg args article asset
attach auth authenticate author auto avatar

back backend backup banner base base_url beta body branch brand build
button

callback cancel cat category channel charset check city class clear
client client_id cmd code color command comment company config confirm
content context cookie copy count country coupon create csrf currency
custom customer

dashboard data database date dbg debug default delete demo depth desc
description dest destination detail dev device dir directory disable
display doc document domain download draft driver

edit email embed enable encoding endpoint env environment error event
exclude exec execute expand expire export extra

feed fetch field file filename filepath filter flag folder force form
format forward frame from function

get global goto grant group

hash header help hidden hide history home hook host html

id ids ignore image img import include index info input inspect internal
ip item

job join json jsonp jwt

key keyword keys

lang language last layout level limit link list load locale local
location lock log login logout

mail manage map max media message meta method metric min mobile mode
module msg

name namespace next node note notification number

object offset open operation operator order org origin output owner

page page_id page_size param params parent parse pass password path
payload payment permission phone pid ping platform port post preview
private probe process profile project protocol proxy public pwd

q query query_string quick

redirect redirect_uri redirect_url ref reference refresh region regex
release remote render request reset resource response retry return
return_to return_url role root route run

sample save scope search secret section select send server service
session set setting settings share shell show sid sign signature site
size skip slug sort source src ssrf stage start state stat status step
store style sub subject submit switch sync system

tab tag target task team template tenant test text theme thread time
timeout timestamp title token tool trace track type

uid upload uri url usage user user_id username utm

valid validate value var verbose version view visible

webhook weight width window worker

xml xss

year

zero zip
`)
