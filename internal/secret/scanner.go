package secret

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
)

// MaxBody bounds how much of one document is scanned.
const MaxBody = 5 << 20

// Document is one body to scan.
type Document struct {
	// Source is the URL (or path) the body came from; it is reported verbatim.
	Source string
	Body   []byte
}

// Result is the outcome of scanning one document.
//
// Suppressed counts are reported per reason so a filtered credential is never
// silently invisible: the total always says how much was dropped and why.
type Result struct {
	Findings   []finding.Finding
	Suppressed int
	ByReason   map[string]int
}

// Scanner detects credentials in text.
//
// A Scanner is immutable after New and safe for concurrent use. It applies
// structural gates but no score threshold: filtering by confidence belongs to
// the caller, so the same detector serves --strict, the default and --all.
type Scanner struct {
	rules []*Rule
}

// New builds a Scanner and validates its rule set.
func New() (*Scanner, error) {
	rules := Rules()
	seen := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		if rule.ID == "" {
			return nil, fmt.Errorf("secret: rule with empty ID")
		}
		if rule.Title == "" || rule.Category == "" {
			return nil, fmt.Errorf("secret: rule %q needs a title and category", rule.ID)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return nil, fmt.Errorf("secret: duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.Base <= 0 || rule.Base > confidence.MaxScore {
			return nil, fmt.Errorf("secret: rule %q: base confidence %v outside (0, 100]", rule.ID, rule.Base)
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("secret: rule %q: %w", rule.ID, err)
		}
		if rule.Group < 0 || rule.Group > compiled.NumSubexp() {
			return nil, fmt.Errorf("secret: rule %q: capture group %d does not exist", rule.ID, rule.Group)
		}
	}

	return &Scanner{rules: rules}, nil
}

// Rules returns the active rule set. The slice must not be modified.
func (s *Scanner) Rules() []*Rule { return s.rules }

// Scan inspects one document and returns every candidate that passed the
// structural gates, highest confidence first.
func (s *Scanner) Scan(document Document) Result {
	result := Result{ByReason: make(map[string]int)}
	if len(document.Body) == 0 || isBinary(document.Body) {
		return result
	}
	body := document.Body
	if len(body) > MaxBody {
		body = body[:MaxBody]
	}
	text := string(body)

	comments := indexComments(text, hashCommentSource(document.Source))
	seen := make(map[string]struct{})
	candidates := make([]candidate, 0, 16)
	shields := shieldSpans(s.rules, text)

	for _, rule := range s.rules {
		for _, loc := range rule.Regexp().FindAllStringSubmatchIndex(text, -1) {
			group := 2 * rule.Group
			if group+1 >= len(loc) || loc[group] < 0 {
				continue
			}

			full := text[loc[0]:loc[1]]
			captured := text[loc[group]:loc[group+1]]
			payload := rule.StripPrefix(strings.TrimSpace(captured))
			entropy := Entropy(payload)

			if reason := gate(rule, full, payload, entropy); reason != "" {
				result.Suppressed++
				result.ByReason[reason]++
				continue
			}
			if !insideAny(loc[group], shields) && comments.contains(loc[group]) {
				result.Suppressed++
				result.ByReason["comment"]++
				continue
			}

			line, column := lineColumn(text, matchAnchor(rule, loc))
			key := fmt.Sprintf("%s|%d|%d", rule.ID, line, column)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}

			value := captured
			if rule.RedactFullMatch {
				// Only the header is legible; the body is key material and must
				// never reach a report, masked or not.
				value = blockHeader(full)
			}

			// For a block format the context is clamped to the header line:
			// the surrounding characters are opaque key material.
			contextStart, contextEnd := loc[group], loc[group+1]
			contextLimit := len(text)
			if rule.RedactFullMatch {
				contextStart = loc[0]
				contextEnd = loc[0] + len(blockHeader(full))
				contextLimit = contextEnd
			}

			built := finding.Finding{
				Kind:        finding.KindSecret,
				Category:    rule.Category,
				RuleID:      rule.ID,
				Title:       rule.Title,
				URL:         document.Source,
				Value:       strings.TrimSpace(value),
				Context:     contextWithin(text, contextStart, contextEnd, ContextRadius, contextLimit),
				Fingerprint: Fingerprint(payload),
				Confidence:  scoreCandidate(rule, full, payload, entropy),
			}
			built.WithField("Line", fmt.Sprintf("%d:%d", line, column))
			if rule.EntropyMin > 0 {
				built.WithField("Entropy", fmt.Sprintf("%.2f bits/symbol", entropy))
			}
			candidates = append(candidates, candidate{
				finding: built,
				generic: rule.Generic,
				start:   loc[0],
				end:     loc[1],
			})
		}
	}

	// A credential must be reported once, under its strongest rule. Generic
	// matches that overlap a provider-specific match are dropped here rather
	// than deduplicated later, because their spans differ and a fingerprint
	// comparison would miss them.
	specific := make([]candidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.generic {
			specific = append(specific, c)
		}
	}
	for _, c := range candidates {
		if c.generic && (overlapsAny(c, specific) || overlapsAny(c, shields)) {
			result.Suppressed++
			result.ByReason["superseded"]++
			continue
		}
		result.Findings = append(result.Findings, c.finding)
	}

	sortFindings(result.Findings)
	return result
}

// candidate pairs a finding with the span and rule class it came from.
type candidate struct {
	finding finding.Finding
	generic bool
	start   int
	end     int
}

// shieldSpans collects the spans of block-format rules so generic detectors
// stay silent inside them.
func shieldSpans(rules []*Rule, text string) []candidate {
	var spans []candidate
	for _, rule := range rules {
		if !rule.ShieldGeneric {
			continue
		}
		for _, loc := range rule.Regexp().FindAllStringSubmatchIndex(text, -1) {
			spans = append(spans, candidate{start: loc[0], end: loc[1]})
		}
	}
	return spans
}

// insideAny reports whether offset falls inside one of spans.
func insideAny(offset int, spans []candidate) bool {
	for _, span := range spans {
		if offset >= span.start && offset < span.end {
			return true
		}
	}
	return false
}

// overlapsAny reports whether c overlaps any candidate in others.
func overlapsAny(c candidate, others []candidate) bool {
	for _, other := range others {
		if c.start < other.end && other.start < c.end {
			return true
		}
	}
	return false
}

// blockHeader returns the first line of a block, treating a JSON-escaped "\n"
// as a line break too: everything past it is key material.
func blockHeader(block string) string {
	end := len(block)
	if newline := strings.IndexByte(block, '\n'); newline >= 0 && newline < end {
		end = newline
	}
	if escaped := strings.Index(block, `\n`); escaped >= 0 && escaped < end {
		end = escaped
	}
	return block[:end]
}

// gate applies a rule's hard structural requirements. An empty result means the
// candidate survives; otherwise the returned key is a stable stats label.
func gate(rule *Rule, full, payload string, entropy float64) string {
	switch {
	case payload == "":
		return "empty-payload"
	case rule.MinLen > 0 && len(payload) < rule.MinLen:
		return "length"
	case rule.MaxLen > 0 && len(payload) > rule.MaxLen:
		return "length"
	}
	if rule.Require != nil && !rule.Require(full, payload) {
		return "structure"
	}
	if rule.ShieldGeneric {
		// The payload is encoded binary, not a human-written value: placeholder
		// words and repetition heuristics would produce random false negatives.
		return ""
	}
	if _, ok := placeholderReason(payload); ok {
		return "placeholder"
	}
	if isDegenerate(payload) {
		return "degenerate"
	}
	if rule.EntropyMin > 0 && entropy < rule.EntropyMin {
		return "low-entropy"
	}
	return ""
}

// scoreCandidate derives a confidence score for a candidate that passed the
// gates. Entropy is graded rather than only gated: a value that clears its floor
// by a hair is genuinely weaker evidence than one that is far above it.
func scoreCandidate(rule *Rule, full, payload string, entropy float64) confidence.Score {
	builder := confidence.New(rule.Base)

	if rule.Generic {
		builder.Add("generic-rule", -10, "generic pattern without provider identity")
	}
	if rule.EntropyMin > 0 {
		switch {
		case entropy >= rule.EntropyMin+1.5:
			builder.Add("entropy", 5, fmt.Sprintf("%.2f bits/symbol, well above the %.1f floor", entropy, rule.EntropyMin))
		case entropy < rule.EntropyMin+0.5:
			builder.Add("entropy", -8, fmt.Sprintf("%.2f bits/symbol, close to the %.1f floor", entropy, rule.EntropyMin))
		}
	}
	if rule.Validate != nil {
		if signal, ok := rule.Validate(full, payload); ok {
			builder.Add(signal.Name, signal.Delta, signal.Reason)
		}
	}

	return builder.Build()
}

// matchAnchor returns the offset whose position is reported: the start of what
// the finding displays, so a result points at the secret rather than at the
// keyword that introduced it.
func matchAnchor(rule *Rule, loc []int) int {
	if rule.RedactFullMatch || rule.Group == 0 {
		return loc[0]
	}
	return loc[2*rule.Group]
}

// isBinary reports whether content looks binary. Only the first 8 KiB are
// inspected: a NUL there is a reliable signal, and reading further would cost
// more than it finds.
func isBinary(content []byte) bool {
	limit := len(content)
	if limit > 8192 {
		limit = 8192
	}
	for _, b := range content[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

// lineColumn converts a byte offset into a 1-based line and rune column.
func lineColumn(text string, offset int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(text) {
		offset = len(text)
	}
	line := 1 + strings.Count(text[:offset], "\n")
	lineStart := strings.LastIndexByte(text[:offset], '\n') + 1
	column := utf8.RuneCountInString(text[lineStart:offset]) + 1
	return line, column
}

func sortFindings(findings []finding.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Confidence.Value != b.Confidence.Value {
			return a.Confidence.Value > b.Confidence.Value
		}
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Value < b.Value
	})
}
