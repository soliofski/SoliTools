// Package prototype detects DOM / client-side prototype pollution in
// first-party JavaScript.
//
// The module is lexical and AST-free. It looks for the one construct that
// actually causes client-side pollution - a for-in merge loop that copies
// attacker-reachable keys into an object without rejecting __proto__,
// constructor or prototype - and then weighs the surrounding evidence: whether
// the data can come from location.search/location.hash or postMessage, whether
// a DOM gadget consumes a possibly-inherited property, and whether the bundle
// ships a known-vulnerable merge utility.
//
// Deliberate limits, all of them precision choices:
//
//   - There is no network I/O, no browser and no JavaScript engine. Nothing
//     here proves exploitability: the module reports a sink together with the
//     evidence around it and lets the caller decide.
//   - Third-party scripts are rejected outright. Pollution inside a vendor
//     bundle is the vendor's bug, not the target's.
//   - A finding is returned even when its score falls below
//     confidence.ThresholdDefault. Filtering is the pipeline's job, which also
//     surfaces these candidates under --all.
package prototype

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
)

// Kind is the finding kind emitted by this module.
const Kind = finding.Kind("PROTOTYPE")

// Finding metadata, kept as constants so the wording cannot drift between the
// detector and its consumers.
const (
	Title    = "DOM / Client Prototype Pollution Heuristic"
	Category = "Client Prototype Pollution"
	RuleID   = "prototype.client.pollution"
)

// Base and signal deltas from Instruction/ROADMAP.md §5.2.4. The signal names
// are spelled exactly as the specification writes them so a finished trace can
// be read against the table.
const (
	baseConfidence = 50.0

	signalVulnerableLibrary = "signal.known-vulnerable-library"
	signalLocationSource    = "signal.source-location-linked"
	signalSinkGadget        = "signal.sink-gadget-detected"
	signalPostMessage       = "signal.unvalidated-postmessage"
	signalServerReflection  = "signal.server-reflection-json"
	signalFrozenPrototype   = "signal.frozen-prototype"
	signalMinified          = "signal.minified-uncertainty"
	signalNoGadget          = "signal.no-gadget-found"

	deltaVulnerableLibrary = 25.0
	deltaLocationSource    = 20.0
	deltaSinkGadget        = 15.0
	deltaPostMessage       = 15.0
	deltaServerReflection  = 10.0
	deltaFrozenPrototype   = -30.0
	deltaMinified          = -15.0
	deltaNoGadget          = -10.0
)

const (
	// guardWindow is the local scope inspected for a key filter: 250 characters
	// before a loop plus everything inside it. Wide enough to include the
	// enclosing function head and an early return, narrow enough that a filter
	// in an unrelated function is not credited.
	guardWindow = 250

	// maxLoopBody bounds brace matching on a single loop. Beyond it the loop is
	// analysed on its prefix rather than followed, which keeps a malicious or
	// pathological bundle from making detection quadratic.
	maxLoopBody = 4000

	// maxSnippetRunes bounds the evidence snippet carried by a finding.
	maxSnippetRunes = 160
)

// ScriptAnalysis is one script to inspect.
type ScriptAnalysis struct {
	// URL is where the script was fetched from. It is used as evidence and as
	// the finding URL.
	URL string
	// Content is the script source.
	Content string
	// IsThirdParty marks a script served by another site, which this module
	// never reports on.
	IsThirdParty bool
}

// AnalyzeScript reports a prototype pollution candidate in one first-party
// script.
//
// It returns the finding and true when the script shows either a naive merge
// sink or a known-vulnerable merge library, and false when a hard gate rejects
// the script: third-party, empty, prototype-filtered, hardened by a freeze, or
// with neither a sink nor a vulnerable utility.
func AnalyzeScript(script ScriptAnalysis) (*finding.Finding, bool) {
	if script.IsThirdParty || strings.TrimSpace(script.Content) == "" {
		return nil, false
	}

	raw := script.Content
	code, bare := maskSource(raw)

	merge := findMergeSink(code, bare)
	library := detectLibraries(raw, script.URL)
	gadget := gadgetPattern.MatchString(bare)

	// A merge utility alone is a library inventory note. It only becomes a
	// prototype pollution candidate in this script when the version is
	// unpatched (lodash < 4.17.12) or when the script also shows a merge sink
	// or a gadget for a deparam-style parser, as §5.2.4 requires.
	vulnerableLibrary := library.lodashVulnerable && !library.lodashPatched
	if !vulnerableLibrary && library.deparam && (merge.found || gadget) {
		vulnerableLibrary = true
	}

	// Hard gate: no sink and no vulnerable library means there is nothing to
	// report, however many __proto__ strings the bundle happens to carry.
	if !merge.found && !vulnerableLibrary {
		return nil, false
	}

	// Hard gate: Object.freeze(Object.prototype) is listed both as a gate and
	// as a -30 signal in §5.2.4, so position decides which applies. A freeze at
	// or before the first unguarded sink runs during initialisation, before any
	// attacker-controlled merge, and removes the script. A freeze placed after
	// the sink is still hardening, but it cannot be shown to precede the sink,
	// so the candidate survives with the penalty recorded instead of being
	// silently dropped.
	freezeAfterSink := false
	if freezeAt := freezeIndex(bare); freezeAt >= 0 {
		if !merge.found || freezeAt <= merge.start {
			return nil, false
		}
		freezeAfterSink = true
	}

	builder := confidence.New(baseConfidence)
	if vulnerableLibrary {
		builder.Add(signalVulnerableLibrary, deltaVulnerableLibrary, "Contains confirmed unpatched library signature")
	}
	if locationSourcePattern.MatchString(bare) {
		builder.Add(signalLocationSource, deltaLocationSource, "Source derived from location.search or location.hash")
	}
	if gadget {
		builder.Add(signalSinkGadget, deltaSinkGadget, "Identified DOM gadget consuming uninitialized Object property")
	}
	if postMessagePattern.MatchString(code) && !originCheckPattern.MatchString(bare) {
		builder.Add(signalPostMessage, deltaPostMessage, "postMessage event listener without origin verification")
	}
	if serverReflectionPattern.MatchString(code) {
		builder.Add(signalServerReflection, deltaServerReflection, "Server response carries a nested __proto__ key in JSON")
	}
	if freezeAfterSink {
		builder.Add(signalFrozenPrototype, deltaFrozenPrototype, "Object.prototype freeze follows the merge sink, so initialisation-time pollution is not prevented")
	}
	// Minification only clouds the reading of a located loop. It says nothing
	// about a library signature, which is why a minified vendor file with no
	// sink is not penalised for variable mangling.
	if merge.found && isMinified(raw, script.URL) {
		builder.Add(signalMinified, deltaMinified, "Variable mangling prevents unambiguous identification of recursive assignment")
	}
	if !gadget {
		builder.Add(signalNoGadget, deltaNoGadget, "No immediate DOM execution gadget identified in target script")
	}

	evidence := library.name
	if merge.found {
		evidence = merge.loop
	}
	value := script.URL
	if value == "" {
		value = collapse(evidence)
	}

	explanation := "First-party script merges attacker-reachable keys into an object without filtering __proto__, constructor or prototype"
	if !merge.found {
		explanation = "First-party script ships a known-vulnerable merge library without prototype key filtering"
	}
	if library.name != "" {
		explanation += " (" + library.name + ")"
	}

	candidate := finding.Finding{
		Kind:       Kind,
		Category:   Category,
		RuleID:     RuleID,
		Title:      Title,
		URL:        script.URL,
		Value:      value,
		Context:    collapse(explanation),
		Confidence: builder.Build(),
	}
	candidate.WithField("Script", script.URL)
	candidate.WithField("Risk", "Potential DOM XSS / Logic Override")
	return &candidate, true
}

// Patterns. None of them uses a backreference: Go's regexp is RE2, so the loop
// key is captured once and then quoted into a per-loop assignment pattern.
var (
	// forInPattern matches a for-in head and its opening brace. Group 1 is the
	// key variable, which the body is then searched for.
	forInPattern = regexp.MustCompile(`\bfor\s*\(\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s+in\s+[^;)]{1,120}\)\s*\{`)

	// guardPattern matches code shapes that reject a dangerous key before it is
	// assigned. Bare mentions of constructor/prototype are deliberately not
	// guards: they appear in every class definition on the page, and treating
	// them as filters would silence real sinks.
	guardPattern = regexp.MustCompile(`(?i)\bhasOwnProperty\s*(?:\.\s*call\s*)?\(|\bObject\.keys\s*\(|\bObject\.create\s*\(\s*null\s*\)|\b(?:includes|indexOf|startsWith)\s*\(\s*["'](?:__proto__|constructor|prototype)["']|["'](?:__proto__|constructor|prototype)["']\s*(?:===|!==|==|!=)|(?:===|!==|==|!=)\s*["'](?:__proto__|constructor|prototype)["']`)

	// gadgetPattern matches a DOM assignment that falls back to a default when
	// an option is missing - the exact shape that turns a polluted prototype
	// into script or markup execution.
	gadgetPattern = regexp.MustCompile(`\.(?:src|href|innerHTML|outerHTML|template|url|action)\s*=\s*[^;=]{0,80}?\|\|`)

	// postMessagePattern matches a cross-window message handler.
	postMessagePattern = regexp.MustCompile(`(?i)\baddEventListener\s*\(\s*["']message["']|\bonmessage\s*=`)

	// originCheckPattern matches verification of the sending origin: a
	// comparison, or a prefix/containment test on the origin string.
	originCheckPattern = regexp.MustCompile(`\.origin\s*(?:===|!==|==|!=)|\.origin\s*\.\s*(?:indexOf|includes|startsWith)\s*\(`)

	// locationSourcePattern matches the URL-derived sources named by §5.2.2.
	locationSourcePattern = regexp.MustCompile(`(?:window\.|document\.)?location\s*\.\s*(?:search|hash)|\bnew\s+URLSearchParams\s*\(`)

	// freezePattern matches executable prototype hardening.
	freezePattern = regexp.MustCompile(`\bObject\s*\.\s*freeze\s*\(\s*Object\s*\.\s*prototype\s*\)`)

	// lodashNamePattern locates a library reference. Matching case-insensitively
	// on the original text keeps every offset valid for slicing: a lowered copy
	// can change byte length on non-ASCII input.
	lodashNamePattern = regexp.MustCompile(`(?i)lodash`)

	// lodashVersionPattern is anchored to the character after the literal
	// "lodash" and accepts the separators a version appears behind: "@", "/",
	// "-", ".", "_", a space, or a "?v="/"&v=" query.
	lodashVersionPattern = regexp.MustCompile(`^(?:\.min)?(?:\.js)?(?:[@/\-._ ]|\?v?=|&v?=)*v?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

	// deparamPattern matches a jquery-deparam style parser: a bundled file, a
	// call, or a definition.
	deparamPattern = regexp.MustCompile(`(?i)jquery-deparam|jquery\.deparam|deparam\.(?:min\.)?js|function\s+deparam\s*\(|deparam\s*:\s*function|\.deparam\s*\(`)

	// serverReflectionPattern matches the only in-band evidence of server-side
	// JSON reflection this module can see: a nested object literal carrying a
	// prototype key. Without such evidence the signal is never raised, because
	// the module performs no network I/O and cannot observe a response.
	serverReflectionPattern = regexp.MustCompile(`\{\s*["'][\w$.-]{1,40}["']\s*:\s*\{[^{}]{0,300}["'](?:__proto__|constructor|prototype)["']\s*:`)
)

// mergeSink describes the first unguarded for-in merge loop in a script.
type mergeSink struct {
	found bool
	// start is the offset of the "for" keyword, used to order the sink against
	// prototype hardening.
	start int
	// loop is the collapsed loop source, carried as evidence.
	loop string
}

// findMergeSink returns the first for-in loop that assigns into an object by
// the loop key without a local key filter.
//
// code keeps string literals intact, so quoted key comparisons are recognisable
// as guards; bare additionally blanks literal contents, so bracket-assignment
// matching and brace counting cannot be fooled by text inside a string.
func findMergeSink(code, bare string) mergeSink {
	for _, match := range forInPattern.FindAllStringSubmatchIndex(bare, -1) {
		key := bare[match[2]:match[3]]
		open := match[1] - 1

		end := matchBrace(bare, open)
		if end < 0 {
			end = open + 1 + maxLoopBody
			if end > len(bare) {
				end = len(bare)
			}
		}
		if !mergeAssignment(key).MatchString(bare[open+1 : end]) {
			continue
		}

		scopeStart := match[0] - guardWindow
		if scopeStart < 0 {
			scopeStart = 0
		}
		if guarded(code[scopeStart:end]) {
			continue
		}
		return mergeSink{found: true, start: match[0], loop: collapse(code[match[0]:end])}
	}
	return mergeSink{}
}

// mergeAssignment matches an assignment whose target is indexed by the loop
// key, including dotted or nested bracket paths and the logical assignment
// operators.
//
// "=" is followed by a non-"=" byte rather than by a negative lookahead: RE2
// has no lookaround, so the comparison forms (==, ===) are excluded by
// consuming one character instead of asserting about it.
func mergeAssignment(key string) *regexp.Regexp {
	return regexp.MustCompile(`\[\s*` + regexp.QuoteMeta(key) + `\s*\]\s*(?:\.[\w$]+|\[[^\]\n]{0,60}\])*\s*(?:=(?:[^=]|$)|\?\?=|\|\|=|&&=)`)
}

// guarded reports whether scope rejects a dangerous key before assignment.
func guarded(scope string) bool {
	// A __proto__ mention next to a merge loop is a rejection test: ordinary
	// code has no other use for that exact key.
	if strings.Contains(scope, "__proto__") {
		return true
	}
	return guardPattern.MatchString(scope)
}

// matchBrace returns the offset of the brace closing the one at open, or -1
// when the loop body is unterminated or larger than the analysis budget.
func matchBrace(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
		if i-open > maxLoopBody*4 {
			return -1
		}
	}
	return -1
}

// freezeIndex returns the offset of an executable Object.prototype freeze, or
// -1.
func freezeIndex(bare string) int {
	if loc := freezePattern.FindStringIndex(bare); loc != nil {
		return loc[0]
	}
	return -1
}

// libraryEvidence is what a script says about the merge utilities it ships.
type libraryEvidence struct {
	lodashVulnerable bool
	lodashPatched    bool
	deparam          bool
	// name identifies the vulnerable utility for the finding context.
	name string
}

// detectLibraries reads library signatures from the raw source and from the
// script URL. Raw text is used because version strings live in comments,
// license headers and URLs, all of which the structural views blank or mangle.
func detectLibraries(raw, url string) libraryEvidence {
	var evidence libraryEvidence
	for _, text := range [2]string{raw, url} {
		if text == "" {
			continue
		}
		inspectLodash(text, &evidence)
	}
	if deparamPattern.MatchString(raw) || deparamPattern.MatchString(url) {
		evidence.deparam = true
		if evidence.name == "" {
			evidence.name = "jquery-deparam"
		}
	}
	return evidence
}

// inspectLodash records every lodash version reference in text.
//
// A patched reference anywhere wins: a script that bundles 4.17.21 next to a
// legacy 4.17.11 path is not shipping the vulnerable copy, and §5.2.4 says the
// signal is never raised for a patched version.
func inspectLodash(text string, evidence *libraryEvidence) {
	for _, loc := range lodashNamePattern.FindAllStringIndex(text, -1) {
		at := loc[0]
		// Skip identifiers such as "lodashfp": only a standalone name is a
		// library reference.
		if at > 0 && isIdentifierByte(text[at-1]) {
			continue
		}

		match := lodashVersionPattern.FindStringSubmatch(text[at+len("lodash"):])
		if match == nil {
			continue
		}
		major, majorErr := strconv.Atoi(match[1])
		minor, minorErr := strconv.Atoi(match[2])
		patch, patchErr := strconv.Atoi(match[3])
		if majorErr != nil || minorErr != nil || patchErr != nil {
			continue
		}

		version := match[1] + "." + match[2] + "." + match[3]
		if lodashPatched(major, minor, patch) {
			evidence.lodashPatched = true
			continue
		}
		evidence.lodashVulnerable = true
		if evidence.name == "" {
			evidence.name = "lodash " + version
		}
	}
}

// lodashPatched reports whether a lodash version contains the fix for
// CVE-2019-10744 (defaultsDeep / merge prototype pollution), released in
// 4.17.12. Everything from 5.0.0 on is fixed by definition.
func lodashPatched(major, minor, patch int) bool {
	if major != 4 {
		return major > 4
	}
	if minor != 17 {
		return minor > 17
	}
	return patch >= 12
}

// isMinified reports whether the script looks like a bundled, mangled build, so
// that variable names no longer identify a recursive merge with certainty.
func isMinified(content, url string) bool {
	if strings.Contains(strings.ToLower(url), ".min.js") {
		return true
	}
	if len(content) < 2048 {
		return false
	}
	longest := 0
	for _, line := range strings.Split(content, "\n") {
		if len(line) > longest {
			longest = len(line)
		}
	}
	return longest >= 500
}

// maskSource returns two same-length views of src.
//
// code has comments blanked and string literals intact: guards compare key
// names against quoted strings, so those literals must survive. bare also
// blanks literal contents, so structural matching (brace balance, "[key] =")
// cannot be satisfied by text inside a string.
//
// Blanking preserves offsets, so a match found in either view maps back onto
// the original content for snippets.
func maskSource(src string) (code, bare string) {
	codeBytes := []byte(src)
	bareBytes := []byte(src)

	for i := 0; i < len(src); {
		switch src[i] {
		case '/':
			switch {
			case i+1 < len(src) && src[i+1] == '/':
				i = blankLineComment(src, i, codeBytes, bareBytes)
			case i+1 < len(src) && src[i+1] == '*':
				i = blankBlockComment(src, i, codeBytes, bareBytes)
			default:
				i++
			}
		case '\'', '"', '`':
			i = blankString(src, i, bareBytes)
		default:
			i++
		}
	}
	return string(codeBytes), string(bareBytes)
}

// blankLineComment blanks a "//" comment and returns the offset of its newline.
func blankLineComment(src string, start int, views ...[]byte) int {
	end := start
	for end < len(src) && src[end] != '\n' {
		end++
	}
	for _, view := range views {
		for i := start; i < end; i++ {
			view[i] = ' '
		}
	}
	return end
}

// blankBlockComment blanks a "/* */" comment and returns the offset after it.
func blankBlockComment(src string, start int, views ...[]byte) int {
	end := len(src)
	for i := start + 2; i+1 < len(src); i++ {
		if src[i] == '*' && src[i+1] == '/' {
			end = i + 2
			break
		}
	}
	for _, view := range views {
		for i := start; i < end; i++ {
			if src[i] != '\n' {
				view[i] = ' '
			}
		}
	}
	return end
}

// blankString blanks a literal's contents in bare, keeping its quotes and any
// newlines, and returns the offset after the closing quote.
//
// Template interpolations are blanked with the rest of the literal: a merge
// sink written inside "${...}" is rare enough that losing it is cheaper than
// the confusion of parsing template grammar.
func blankString(src string, start int, bare []byte) int {
	quote := src[start]
	for i := start + 1; i < len(src); i++ {
		if src[i] == '\\' {
			if i+1 < len(src) && src[i+1] != '\n' {
				bare[i] = ' '
				bare[i+1] = ' '
			}
			i++
			continue
		}
		if src[i] == quote {
			return i + 1
		}
		if src[i] != '\n' {
			bare[i] = ' '
		}
	}
	return len(src)
}

// isIdentifierByte reports whether b can continue a JavaScript identifier.
func isIdentifierByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '$':
		return true
	default:
		return false
	}
}

// collapse folds whitespace so a snippet stays on one line, and bounds it.
func collapse(text string) string {
	joined := strings.Join(strings.Fields(text), " ")
	runes := []rune(joined)
	if len(runes) <= maxSnippetRunes {
		return joined
	}
	return string(runes[:maxSnippetRunes-3]) + "..."
}
