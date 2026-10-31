// Package pathscan looks for sensitive paths that are reachable.
//
// The wordlist is short and high-value on purpose: a large list produces more
// requests and more noise. Only 200, 401 and 403 are reported, soft 404s are
// filtered against a random baseline, and default server pages are discarded.
//
// A 200 is never enough on its own. Single-page apps answer every unknown path
// with an HTML shell, so a reachable-looking status can mean nothing at all:
// the baseline is retried instead of being assumed 404, and a sensitive path
// must also look like the file it names (a private key header, git refs, INI
// sections, KEY=value lines). An HTML document is never a credential file.
package pathscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/errgroup"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/httpx"
	"github.com/soliofski/SoliTools/internal/waf"
)

// wordlist is the default set of sensitive paths, ordered by value.
var wordlist = []string{
	".env",
	".git/config",
	".git/HEAD",
	".aws/credentials",
	"id_rsa",
	"config.php",
	"config.json",
	"backup.zip",
	"backup.sql",
	"database.sql",
	"docker-compose.yml",
	"web.config",
	".DS_Store",
	"actuator",
	"actuator/health",
	"swagger-ui.html",
	"openapi.json",
	"phpinfo.php",
	"server-status",
	"admin",
	"administrator",
	"console",
	"login",
	"graphql",
	"uploads/",
	"backup/",
}

// sensitiveWords are paths whose exposure is more serious than a reachable page.
var sensitiveWords = map[string]struct{}{
	".env": {}, ".git/config": {}, ".git/HEAD": {}, ".aws/credentials": {},
	"id_rsa": {}, "backup.zip": {}, "backup.sql": {}, "database.sql": {},
	"config.php": {}, "config.json": {}, "web.config": {},
}

// MaxCustomWords is the hard ceiling for a user-supplied wordlist. A scanner
// that probes thousands of paths is no longer surgical, and the precision
// thesis does not survive that much noise.
const MaxCustomWords = 200

// DefaultWordlist returns a copy of the built-in, high-value path list.
func DefaultWordlist() []string {
	out := make([]string, len(wordlist))
	copy(out, wordlist)
	return out
}

// LoadWordlist reads a custom wordlist: one path per line, blank lines and
// #-comments ignored, duplicates removed, leading slashes trimmed because the
// probe joins values to the base URL itself. limit caps the result; zero means
// no cap, and the boolean reports whether entries were dropped.
func LoadWordlist(path string, limit int) ([]string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("wordlist: %w", err)
	}
	defer file.Close()

	words := make([]string, 0, 32)
	seen := make(map[string]struct{}, 32)
	truncated := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "/")
		if line == "" {
			continue
		}
		if _, duplicate := seen[line]; duplicate {
			continue
		}
		seen[line] = struct{}{}
		if limit > 0 && len(words) >= limit {
			truncated = true
			continue
		}
		words = append(words, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("wordlist: %w", err)
	}
	return words, truncated, nil
}

// Analyzer probes paths through a shared client.
type Analyzer struct {
	client *httpx.Client
	words  []string
	limit  int
}

// New builds an Analyzer. words may be nil to use the default wordlist; limit
// bounds concurrency and defaults to 8.
func New(client *httpx.Client, words []string, limit int) *Analyzer {
	if len(words) == 0 {
		words = DefaultWordlist()
	}
	if limit <= 0 {
		limit = 8
	}
	return &Analyzer{client: client, words: words, limit: limit}
}

// Probe checks every word against base and returns the reachable paths, highest
// confidence first. The second return value carries non-fatal warnings.
func (a *Analyzer) Probe(ctx context.Context, base string) ([]finding.Finding, []string) {
	if a == nil || a.client == nil {
		return nil, nil
	}
	base = strings.TrimSuffix(base, "/")

	sample := a.baseline(ctx, base)

	// One sample is all the scan normally needs, but it must never be *assumed*:
	// when every attempt fails there is no way to tell a catch-all router from an
	// empty one, and the content rules become the only defence.
	var warnings []string
	if !sample.known {
		warnings = append(warnings, fmt.Sprintf(
			"sensitive path baseline unavailable after %d attempts: 200 responses are only reported when the body matches the file signature",
			baselineAttempts))
	}

	var (
		mu       sync.Mutex
		results  []finding.Finding
		rejected int
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(a.limit)

	for _, word := range a.words {
		word := word
		group.Go(func() error {
			probeURL := base + "/" + strings.TrimPrefix(word, "/")
			response, err := a.client.Get(groupCtx, probeURL)
			if err != nil {
				return nil // a dead path is not a failure of the scan
			}
			candidate, ok, reason := classify(word, probeURL, response, sample)
			mu.Lock()
			defer mu.Unlock()
			if !ok {
				if reason == reasonContent || reason == reasonCatchAll {
					rejected++
				}
				return nil
			}
			results = append(results, candidate)
			return nil
		})
	}
	_ = group.Wait()

	// A handful of content rejections is a signature of a catch-all router:
	// the paths exist, but they are all the same HTML shell.
	if rejected >= 3 {
		warnings = append(warnings, fmt.Sprintf(
			"%d paths answered 200 without looking like the resource they name (catch-all router): suppressed", rejected))
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Confidence.Value != results[j].Confidence.Value {
			return results[i].Confidence.Value > results[j].Confidence.Value
		}
		return results[i].URL < results[j].URL
	})
	return results, warnings
}

// Baseline bounding. A single probe is not evidence: one reset, timeout or CDN
// hiccup used to read as "this host returns 404", which disabled the soft-404
// filter and reported every 200 as a sensitive path.
const (
	// baselineAttempts is how many random paths are tried before the host's
	// default response is declared unknown.
	baselineAttempts = 3
	// baselineBackoff is the delay before the first retry; it doubles per
	// attempt.
	baselineBackoff = 100 * time.Millisecond
)

// baselineSample is what the host does for a path that cannot exist.
type baselineSample struct {
	status int
	size   int
	// known is false when no attempt produced a usable response. Callers must
	// not treat an unknown baseline as 404.
	known bool
}

// baseline learns the default response with bounded retries over fresh random
// paths, so a cached failure cannot be mistaken for the host's behaviour.
//
// A WAF challenge page is not a "not found" answer and is retried rather than
// recorded: treating it as a baseline would hide the real catch-all handler.
func (a *Analyzer) baseline(ctx context.Context, base string) baselineSample {
	backoff := baselineBackoff
	for attempt := 0; attempt < baselineAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return baselineSample{}
			case <-timer.C:
			}
			backoff *= 2
		}

		random := make([]byte, 8)
		if _, err := rand.Read(random); err != nil {
			return baselineSample{}
		}
		response, err := a.client.Get(ctx, base+"/soli-"+hex.EncodeToString(random))
		if err != nil {
			continue
		}
		if waf.IsBlockPage(response) {
			continue
		}
		return baselineSample{status: response.Status, size: len(response.Body), known: true}
	}
	return baselineSample{}
}

// Suppression reasons, counted so the operator can see why a candidate was
// dropped instead of wondering where it went.
type suppression string

const (
	reasonBlockPage  suppression = "block page"
	reasonStatus     suppression = "status"
	reasonSoft404    suppression = "soft 404"
	reasonDefault    suppression = "default server page"
	reasonContent    suppression = "content mismatch"
	reasonCatchAll   suppression = "catch-all response"
	reasonUnverified suppression = "unverified content"
)

// evaluate decides whether one response is a reportable path. It is the
// boolean view of classify, kept because callers only need the verdict.
func evaluate(word, probeURL string, response *httpx.Response, base baselineSample) (finding.Finding, bool) {
	candidate, ok, _ := classify(word, probeURL, response, base)
	if !ok {
		return finding.Finding{}, false
	}
	return candidate, true
}

// classify decides whether one response is a reportable path and why not when
// it is rejected.
func classify(word, probeURL string, response *httpx.Response, base baselineSample) (finding.Finding, bool, suppression) {
	if waf.IsBlockPage(response) {
		// A WAF 403 is not a reachable application path. Reporting it would
		// turn every blocked word into a finding.
		return finding.Finding{}, false, reasonBlockPage
	}
	if response.Status != 200 && response.Status != 401 && response.Status != 403 {
		return finding.Finding{}, false, reasonStatus
	}

	verdict := verdictGeneric
	if response.Status == 200 {
		verdict = assessContent(word, response)
		if verdict == verdictReject {
			return finding.Finding{}, false, reasonContent
		}
		if looksDefaultPage(response.BodyString()) {
			return finding.Finding{}, false, reasonDefault
		}

		// A host that answers 200 for a path that cannot exist is telling us
		// nothing about any other path. Only a body that proves what it is can
		// then be reported; everything else is a soft 404 by definition, which
		// is the whole wordlist flood this module has to avoid.
		catchAll := base.known && base.status == 200
		switch verdict {
		case verdictStrong:
			// Content proof outranks any size heuristic: a catch-all shell
			// cannot carry a private key header, a git ref or an INI section.
		case verdictGeneric:
			if catchAll {
				return finding.Finding{}, false, reasonCatchAll
			}
			if !base.known {
				// No baseline, no proof: indistinguishable from a catch-all.
				return finding.Finding{}, false, reasonUnverified
			}
		}
	}

	builder := confidence.New(62)
	if response.Status == 200 {
		builder.Add("reachable", 10, "path answered 200")
		if verdict == verdictStrong {
			builder.Add("content-verified", 5, "body matches the signature of the file it names")
		}
	}
	if _, sensitive := sensitiveWords[word]; sensitive {
		builder.Add("sensitive", 10, "path is a known sensitive file")
	}

	candidate := finding.Finding{
		Kind:       finding.KindPath,
		Category:   "Sensitive Path",
		RuleID:     "path.reachable",
		Title:      "Reachable Sensitive Path",
		URL:        probeURL,
		Context:    fmt.Sprintf("GET %d, %d bytes", response.Status, len(response.Body)),
		Confidence: builder.Build(),
	}
	candidate.WithField("Path", "/"+strings.TrimPrefix(word, "/"))
	candidate.WithField("Status", fmt.Sprintf("%d", response.Status))
	candidate.WithField("Size", fmt.Sprintf("%d", len(response.Body)))
	if verdict == verdictStrong {
		candidate.WithField("Content", "matches the expected file signature")
	}
	return candidate, true, ""
}

// contentVerdict is how believable a 200 body is for the path it answers.
type contentVerdict int

const (
	// verdictReject means the body cannot be the file the path names.
	verdictReject contentVerdict = iota
	// verdictGeneric means the body is plausible but carries no marker that
	// proves it (plain text, SQL dump, an HTML page for a page-like path).
	verdictGeneric
	// verdictStrong means the body carries the signature only the real file has.
	verdictStrong
)

// expectation is the shape a path must have to be believable.
type expectation int

const (
	expectAnything expectation = iota
	expectEnv
	expectPrivateKey
	expectGitHead
	expectGitConfig
	expectAWSCredentials
	expectZip
	expectDSStore
	expectYAML
)

// Signatures. Each one is a marker that a catch-all router cannot produce by
// accident: an HTML shell has no PEM header, no git ref and no INI section.
var (
	// envAssignment matches KEY=value, optionally exported. A .env file is
	// nothing but these lines and comments.
	envAssignment = regexp.MustCompile(`(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=`)
	// gitRefLine matches the symbolic ref in .git/HEAD.
	gitRefLine = regexp.MustCompile(`(?m)^ref:\s+refs/`)
	// gitObjectID matches a detached HEAD.
	gitObjectID = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	// yamlRootKey matches the top-level keys a compose or config file starts
	// with. A catch-all HTML shell has none of them.
	yamlRootKey = regexp.MustCompile(`(?m)^\s*(?:services|version|x-[a-z0-9_-]+)\s*:`)
)

// assessContent decides whether a 200 body is believable for this path.
//
// This is the last line of defence and the most important one: it does not care
// what the baseline said, so it still holds when the baseline request failed or
// when the catch-all page varies in size per route.
func assessContent(word string, response *httpx.Response) contentVerdict {
	body := response.Body
	dataFile := isDataFile(word)

	if looksHTML(body, response.ContentType()) {
		if dataFile {
			// The core false positive: an SPA shell served for /.env or /id_rsa.
			return verdictReject
		}
		// Pages like /admin or /login are allowed to be HTML.
		return verdictGeneric
	}

	switch expectationFor(word) {
	case expectEnv:
		if envAssignment.Match(body) {
			return verdictStrong
		}
		return verdictReject
	case expectPrivateKey:
		if bytes.Contains(body, []byte("BEGIN ")) && bytes.Contains(body, []byte("PRIVATE KEY")) {
			return verdictStrong
		}
		return verdictReject
	case expectGitHead:
		trimmed := bytes.TrimSpace(body)
		if gitRefLine.Match(body) || gitObjectID.Match(trimmed) {
			return verdictStrong
		}
		return verdictReject
	case expectGitConfig:
		lower := bytes.ToLower(body)
		if bytes.Contains(lower, []byte("[core]")) ||
			(bytes.Contains(lower, []byte("[")) && bytes.Contains(lower, []byte("repositoryformatversion"))) {
			return verdictStrong
		}
		return verdictReject
	case expectAWSCredentials:
		lower := bytes.ToLower(body)
		if bytes.Contains(lower, []byte("aws_access_key_id")) && bytes.Contains(lower, []byte("[")) {
			return verdictStrong
		}
		return verdictReject
	case expectZip:
		if bytes.HasPrefix(body, []byte("PK\x03\x04")) || bytes.HasPrefix(body, []byte("PK\x05\x06")) {
			return verdictStrong
		}
		return verdictReject
	case expectDSStore:
		if bytes.Contains(body, []byte("Bud1")) {
			return verdictStrong
		}
		return verdictReject
	case expectYAML:
		if yamlRootKey.Match(body) {
			return verdictStrong
		}
		return verdictReject
	}
	return verdictGeneric
}

// expectationFor maps a path to the signature it must carry, if any.
func expectationFor(word string) expectation {
	clean := strings.ToLower(strings.Trim(strings.TrimPrefix(word, "/"), "/"))
	base := path.Base(clean)

	switch clean {
	case ".git/head":
		return expectGitHead
	case ".git/config":
		return expectGitConfig
	case ".aws/credentials":
		return expectAWSCredentials
	}

	switch {
	case base == ".env" || strings.HasSuffix(base, ".env"):
		return expectEnv
	case strings.HasPrefix(base, "id_rsa"), strings.HasPrefix(base, "id_dsa"),
		strings.HasPrefix(base, "id_ecdsa"), strings.HasPrefix(base, "id_ed25519"),
		strings.HasSuffix(base, ".pem"), strings.HasSuffix(base, ".key"):
		return expectPrivateKey
	case strings.HasSuffix(base, ".zip"):
		return expectZip
	case strings.HasSuffix(base, ".yml"), strings.HasSuffix(base, ".yaml"):
		return expectYAML
	case base == ".ds_store":
		return expectDSStore
	}
	return expectAnything
}

// isDataFile reports whether the path names a file that is never HTML: a
// dotfile, a dot-directory, an id_* key or anything with an extension other
// than a page one. It is deliberately word-shape based so custom wordlists get
// the same protection as the built-in list.
func isDataFile(word string) bool {
	clean := strings.ToLower(strings.Trim(strings.TrimPrefix(word, "/"), "/"))
	if clean == "" {
		return false
	}
	for _, segment := range strings.Split(clean, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	base := path.Base(clean)
	if strings.HasPrefix(base, "id_") {
		return true
	}
	switch path.Ext(base) {
	case "":
		return false
	case ".html", ".htm", ".php", ".asp", ".aspx", ".jsp":
		// Page generators legitimately return HTML, including phpinfo.php.
		return false
	default:
		return true
	}
}

// looksHTML reports whether a response is an HTML document, by declared type or
// by the markers at the head of the body.
func looksHTML(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	lower := strings.ToLower(string(head))
	for _, marker := range []string{"<!doctype html", "<html", "<head", "<body", "<meta", "<title"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// looksDefaultPage recognises stock server pages that say nothing about the app.
func looksDefaultPage(body string) bool {
	for _, marker := range []string{
		"Welcome to nginx",
		"Apache2 Ubuntu Default Page",
		"It works!",
		"Test Page for the Apache",
		"IIS Windows Server",
		"<title>404",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}
