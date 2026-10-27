package secret

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"solitools/internal/confidence"
	"solitools/internal/finding"
)

// Defaults for Options.
const (
	// DefaultMinConfidence hides findings below this score. It sits at the
	// bottom of the medium band: beneath it a secret match is more likely to be
	// a placeholder than a credential.
	DefaultMinConfidence = 40.0
	// DefaultMaxFileSize is the largest file read, in bytes.
	DefaultMaxFileSize = 5 << 20
)

// DefaultIgnoreDirs are directory names skipped while walking. They hold
// third-party or generated code where a match is rarely actionable.
var DefaultIgnoreDirs = []string{".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "__pycache__"}

// binaryExts are skipped without being read. NUL detection would catch most of
// them anyway, but the extension check avoids reading large media files at all.
var binaryExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".ico": {}, ".bmp": {},
	".pdf": {}, ".zip": {}, ".gz": {}, ".tar": {}, ".7z": {}, ".rar": {},
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".class": {}, ".jar": {}, ".pyc": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".mp3": {}, ".mp4": {}, ".mov": {}, ".avi": {}, ".bin": {}, ".iso": {},
}

// Options configures a Scanner.
type Options struct {
	// MinConfidence drops findings below this value. Zero selects
	// DefaultMinConfidence; pass a small positive value to keep everything.
	MinConfidence float64
	// IncludeGeneric adds the low-precision generic rule set.
	IncludeGeneric bool
	// MaxFileSize is the largest file read, in bytes.
	MaxFileSize int64
	// IgnoreDirs replaces the default directory skip list when non-empty.
	IgnoreDirs []string
}

func (o Options) normalized() Options {
	if o.MinConfidence <= 0 {
		o.MinConfidence = DefaultMinConfidence
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	if len(o.IgnoreDirs) == 0 {
		o.IgnoreDirs = DefaultIgnoreDirs
	}
	return o
}

// Stats summarizes a scan.
//
// Suppressed findings are counted per reason so a filtered result is never
// silently invisible: the summary always states how much was dropped and why.
type Stats struct {
	FilesScanned int            `json:"files_scanned"`
	FilesSkipped int            `json:"files_skipped"`
	BytesRead    int64          `json:"bytes_read"`
	Findings     int            `json:"findings"`
	Suppressed   int            `json:"suppressed"`
	ByReason     map[string]int `json:"suppressed_by_reason,omitempty"`
}

func (s *Stats) merge(other Stats) {
	s.FilesScanned += other.FilesScanned
	s.FilesSkipped += other.FilesSkipped
	s.BytesRead += other.BytesRead
	s.Findings += other.Findings
	s.Suppressed += other.Suppressed
	if len(other.ByReason) == 0 {
		return
	}
	if s.ByReason == nil {
		s.ByReason = make(map[string]int, len(other.ByReason))
	}
	for reason, count := range other.ByReason {
		s.ByReason[reason] += count
	}
}

// FileResult is the outcome of scanning one input.
type FileResult struct {
	Findings []finding.Finding
	Stats    Stats
}

// Report is the outcome of scanning a set of paths.
type Report struct {
	Findings []finding.Finding `json:"findings"`
	Stats    Stats             `json:"stats"`
	// Warnings records inputs that could not be read. One unreadable file does
	// not fail the run, but it is never hidden either.
	Warnings []string `json:"warnings,omitempty"`
}

func (r *Report) mergeFile(res FileResult, warning string) {
	if warning != "" {
		r.Warnings = append(r.Warnings, warning)
	}
	r.Findings = append(r.Findings, res.Findings...)
	r.Stats.merge(res.Stats)
}

// Scanner detects secrets in text.
//
// A Scanner is immutable after New and safe for concurrent use.
type Scanner struct {
	opts  Options
	rules []*Rule
}

// New builds a Scanner and validates its rule set.
//
// Rule IDs must be unique and every pattern must compile, so a broken rule is
// an error at construction time rather than a panic mid-scan.
func New(opts Options) (*Scanner, error) {
	normalized := opts.normalized()

	rules := HighPrecisionRules()
	if normalized.IncludeGeneric {
		rules = append(rules, GenericRules()...)
	}

	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return nil, fmt.Errorf("secret: rule with empty ID")
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return nil, fmt.Errorf("secret: duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.Base <= 0 || rule.Base > confidence.MaxScore {
			return nil, fmt.Errorf("secret: rule %q: base confidence %v outside (0, 100]", rule.ID, rule.Base)
		}
		if rule.Group < 0 {
			return nil, fmt.Errorf("secret: rule %q: negative capture group", rule.ID)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return nil, fmt.Errorf("secret: rule %q: %w", rule.ID, err)
		}
	}

	return &Scanner{opts: normalized, rules: rules}, nil
}

// Rules returns the active rule set. The slice must not be modified.
func (s *Scanner) Rules() []*Rule { return s.rules }

// ScanText scans content as if it lived at path.
//
// The path drives fixture heuristics and reported locations only; nothing is
// read or written. This is the entry point used by tests and by in-memory
// callers.
func (s *Scanner) ScanText(path string, content []byte) FileResult {
	result := FileResult{Stats: Stats{ByReason: make(map[string]int)}}
	if isBinary(content) {
		result.Stats.FilesSkipped = 1
		return result
	}
	result.Stats.FilesScanned = 1
	result.Stats.BytesRead = int64(len(content))

	text := string(content)
	seen := make(map[string]struct{})

	for _, rule := range s.rules {
		for _, loc := range rule.Regexp().FindAllStringSubmatchIndex(text, -1) {
			group := 2 * rule.Group
			if group+1 >= len(loc) || loc[group] < 0 {
				continue
			}

			full := text[loc[0]:loc[1]]
			captured := text[loc[group]:loc[group+1]]
			payload := rule.StripPrefix(strings.TrimSpace(captured))

			if reason := s.suppressionReason(rule, full, payload); reason != "" {
				result.Stats.Suppressed++
				result.Stats.ByReason[reason]++
				continue
			}

			score := scoreCandidate(rule, full, payload, path)
			if !score.AtLeast(s.opts.MinConfidence) {
				result.Stats.Suppressed++
				result.Stats.ByReason["below-threshold"]++
				continue
			}

			line, column := lineColumn(text, matchAnchor(rule, loc))
			key := fmt.Sprintf("%s\x00%d\x00%d\x00%s", path, line, column, rule.ID)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}

			display := captured
			if rule.RedactFullMatch {
				display = full
			}

			result.Findings = append(result.Findings, finding.Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Description: rule.Description,
				Kind:        finding.KindSecret,
				File:        path,
				Line:        line,
				Column:      column,
				Match:       Redact(display),
				Fingerprint: Fingerprint(payload),
				Confidence:  score,
			})
		}
	}

	result.Stats.Findings = len(result.Findings)
	sortFindings(result.Findings)
	return result
}

// ScanPaths scans each path, expanding directories recursively.
//
// A missing root is an error; an unreadable file inside a tree is a warning.
func (s *Scanner) ScanPaths(ctx context.Context, paths []string) (Report, error) {
	report := Report{Stats: Stats{ByReason: make(map[string]int)}}

	for _, root := range paths {
		if err := ctx.Err(); err != nil {
			return report, err
		}

		info, err := os.Stat(root)
		if err != nil {
			return report, fmt.Errorf("stat %q: %w", root, err)
		}
		if !info.IsDir() {
			result, warning := s.scanFile(root)
			report.mergeFile(result, warning)
			continue
		}

		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				if path != root && s.skipDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			if s.skipExt(path) {
				report.Stats.FilesSkipped++
				return nil
			}
			result, warning := s.scanFile(path)
			report.mergeFile(result, warning)
			return nil
		})
		if walkErr != nil {
			return report, walkErr
		}
	}

	sortFindings(report.Findings)
	report.Stats.Findings = len(report.Findings)
	return report, nil
}

// suppressionReason applies a rule's hard gates. An empty result means the
// candidate survives; otherwise the returned key is a stable stats label.
func (s *Scanner) suppressionReason(rule *Rule, full, payload string) string {
	switch {
	case payload == "":
		return "empty-payload"
	case rule.MinLen > 0 && len(payload) < rule.MinLen:
		return "length"
	case rule.MaxLen > 0 && len(payload) > rule.MaxLen:
		return "length"
	}
	if _, ok := placeholderReason(payload); ok {
		return "placeholder"
	}
	if isDegenerate(payload) {
		return "degenerate"
	}
	if rule.EntropyMin > 0 && Entropy(payload) < rule.EntropyMin {
		return "low-entropy"
	}
	if rule.Require != nil && !rule.Require(full, payload) {
		return "structure"
	}
	return ""
}

// scoreCandidate derives a confidence score for a surviving candidate.
func scoreCandidate(rule *Rule, full, payload, path string) confidence.Score {
	builder := confidence.New(rule.Base)
	if rule.Generic {
		builder.Add("generic-rule", -10, "generic pattern without provider identity")
	}
	if delta, reason := pathPenalty(path); delta != 0 {
		builder.Add("path-context", delta, reason)
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

func (s *Scanner) scanFile(path string) (FileResult, string) {
	info, err := os.Stat(path)
	if err != nil {
		return FileResult{Stats: Stats{FilesSkipped: 1}}, fmt.Sprintf("%s: %v", path, err)
	}
	if info.Size() > s.opts.MaxFileSize {
		return FileResult{Stats: Stats{FilesSkipped: 1}}, ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FileResult{Stats: Stats{FilesSkipped: 1}}, fmt.Sprintf("%s: %v", path, err)
	}
	return s.ScanText(path, data), ""
}

func (s *Scanner) skipDir(name string) bool {
	for _, ignored := range s.opts.IgnoreDirs {
		if strings.EqualFold(ignored, name) {
			return true
		}
	}
	return false
}

func (s *Scanner) skipExt(path string) bool {
	_, found := binaryExts[strings.ToLower(filepath.Ext(path))]
	return found
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
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}
