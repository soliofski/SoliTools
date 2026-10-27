// Package pathscan looks for sensitive paths that are reachable.
//
// The wordlist is short and high-value on purpose: a large list produces more
// requests and more noise. Only 200, 401 and 403 are reported, soft 404s are
// filtered against a random baseline, and default server pages are discarded.
package pathscan

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"solitools/internal/confidence"
	"solitools/internal/errgroup"
	"solitools/internal/finding"
	"solitools/internal/httpx"
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

	baselineStatus, baselineSize := a.baseline(ctx, base)

	var (
		mu      sync.Mutex
		results []finding.Finding
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
			candidate, ok := evaluate(word, probeURL, response, baselineStatus, baselineSize)
			if !ok {
				return nil
			}
			mu.Lock()
			results = append(results, candidate)
			mu.Unlock()
			return nil
		})
	}
	_ = group.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Confidence.Value != results[j].Confidence.Value {
			return results[i].Confidence.Value > results[j].Confidence.Value
		}
		return results[i].URL < results[j].URL
	})
	return results, nil
}

// baseline requests a random path to learn what "not found" looks like on this
// host: status, and for a catch-all 200, the response size.
func (a *Analyzer) baseline(ctx context.Context, base string) (int, int) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return 404, 0
	}
	response, err := a.client.Get(ctx, base+"/soli-"+hex.EncodeToString(random))
	if err != nil {
		return 404, 0
	}
	return response.Status, len(response.Body)
}

// evaluate decides whether one response is a reportable path.
func evaluate(word, probeURL string, response *httpx.Response, baselineStatus, baselineSize int) (finding.Finding, bool) {
	if response.Status != 200 && response.Status != 401 && response.Status != 403 {
		return finding.Finding{}, false
	}
	if response.Status == 200 {
		if baselineStatus == 200 && similarSize(len(response.Body), baselineSize) {
			return finding.Finding{}, false // soft 404 behind a catch-all handler
		}
		if looksDefaultPage(response.BodyString()) {
			return finding.Finding{}, false
		}
	}

	builder := confidence.New(62)
	if response.Status == 200 {
		builder.Add("reachable", 10, "path answered 200")
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
	return candidate, true
}

// similarSize reports two body sizes that are close enough to be the same
// catch-all page.
//
// The comparison is relative, with a 200-byte floor on the scale: on a tiny
// baseline a 30-byte difference is a different page, while on a real page it is
// noise.
func similarSize(a, b int) bool {
	if b <= 0 {
		return false
	}
	diff := math.Abs(float64(a - b))
	scale := math.Max(float64(b), 200)
	return diff/scale <= 0.10
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
