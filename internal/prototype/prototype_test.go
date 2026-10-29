package prototype

import (
	"strings"
	"testing"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
)

// mergeLoop is the canonical naive sink: a for-in loop that copies every key,
// including __proto__, into the target object.
const mergeLoop = `
function merge(target, source) {
	for (var key in source) {
		target[key] = source[key];
	}
	return target;
}
`

// runtimeFixture is a first-party script that reads URL parameters, merges them
// and feeds the result to a DOM gadget.
const runtimeFixture = `
var params = new URLSearchParams(location.search, location.hash);
var options = merge({}, {});
document.getElementById("banner").innerHTML = options.template || "";
`

func analyze(t *testing.T, script ScriptAnalysis) *finding.Finding {
	t.Helper()
	got, ok := AnalyzeScript(script)
	if !ok {
		t.Fatalf("AnalyzeScript(%q) = no finding, want a candidate", script.URL)
	}
	if got == nil {
		t.Fatal("AnalyzeScript reported ok with a nil finding")
	}
	return got
}

// signalDeltas indexes a finished trace by signal name.
func signalDeltas(score confidence.Score) map[string]float64 {
	deltas := make(map[string]float64, len(score.Signals))
	for _, signal := range score.Signals {
		deltas[signal.Name] = signal.Delta
	}
	return deltas
}

func requireSignal(t *testing.T, got *finding.Finding, name string, want float64) {
	t.Helper()
	delta, ok := signalDeltas(got.Confidence)[name]
	if !ok {
		t.Fatalf("signals %+v missing %s", got.Confidence.Signals, name)
	}
	if delta != want {
		t.Fatalf("%s delta = %v, want %v", name, delta, want)
	}
}

func rejectSignal(t *testing.T, got *finding.Finding, name string) {
	t.Helper()
	if delta, ok := signalDeltas(got.Confidence)[name]; ok {
		t.Fatalf("signals %+v unexpectedly contain %s (%v)", got.Confidence.Signals, name, delta)
	}
}

func TestAnalyzeScriptFindsMergeSinkWithSourceAndGadget(t *testing.T) {
	script := ScriptAnalysis{
		URL:     "https://app.example.test/static/app.js",
		Content: mergeLoop + runtimeFixture,
	}

	got := analyze(t, script)
	if got.Confidence.Value != 85 {
		t.Fatalf("confidence = %v, want 85.0 (50 base + 20 source + 15 gadget): %+v", got.Confidence.Value, got.Confidence.Signals)
	}
	if got.Confidence.Base != 50 {
		t.Fatalf("base = %v, want 50", got.Confidence.Base)
	}
	if got.Confidence.Band != confidence.BandHigh {
		t.Fatalf("band = %q, want high", got.Confidence.Band)
	}
	if got.Confidence.Value < 80 {
		t.Fatal("a sink with a URL source and a DOM gadget must score at least 80")
	}
	requireSignal(t, got, signalLocationSource, 20)
	requireSignal(t, got, signalSinkGadget, 15)
	rejectSignal(t, got, signalNoGadget)
	rejectSignal(t, got, signalVulnerableLibrary)

	if got.Kind != "PROTOTYPE" {
		t.Fatalf("kind = %q, want PROTOTYPE", got.Kind)
	}
	if got.Category != Category || got.RuleID != RuleID || got.Title != Title {
		t.Fatalf("metadata = %q/%q/%q", got.Category, got.RuleID, got.Title)
	}
	if got.URL != script.URL || got.Value != script.URL {
		t.Fatalf("url/value = %q/%q, want the script URL", got.URL, got.Value)
	}
	if got.Context == "" || strings.ContainsAny(got.Context, "\n\t") {
		t.Fatalf("context = %q, want a one-line explanation", got.Context)
	}
	wantFields := []struct{ name, value string }{
		{"Script", script.URL},
		{"Risk", "Potential DOM XSS / Logic Override"},
	}
	if len(got.Fields) != len(wantFields) {
		t.Fatalf("fields = %+v, want Script and Risk", got.Fields)
	}
	for i, want := range wantFields {
		if got.Fields[i].Name != want.name || got.Fields[i].Value != want.value {
			t.Fatalf("field %d = %+v, want %+v", i, got.Fields[i], want)
		}
	}
}

func TestAnalyzeScriptIgnoresPatchedLodash(t *testing.T) {
	script := ScriptAnalysis{
		URL: "https://app.example.test/static/app.js",
		// The version lives in a comment, which structural matching blanks, so
		// this also proves library detection reads the raw source.
		Content: mergeLoop + runtimeFixture + "\n// vendor: lodash 4.17.21\n",
	}

	got := analyze(t, script)
	if got.Confidence.Value != 85 {
		t.Fatalf("confidence = %v, want 85.0 without a library signal", got.Confidence.Value)
	}
	rejectSignal(t, got, signalVulnerableLibrary)
}

func TestAnalyzeScriptLetsPatchedVersionWin(t *testing.T) {
	script := ScriptAnalysis{
		URL: "https://app.example.test/static/app.js",
		Content: mergeLoop + runtimeFixture + `
var legacy = "lodash 4.17.11"; // historical pin, no longer loaded
// current: lodash 4.17.21
`,
	}

	got := analyze(t, script)
	if got.Confidence.Value != 85 {
		t.Fatalf("confidence = %v, want 85.0: a patched reference must suppress the library signal even next to an old pin", got.Confidence.Value)
	}
	rejectSignal(t, got, signalVulnerableLibrary)
}

func TestAnalyzeScriptDropsGuardedLoops(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "key equality guard",
			content: `
function merge(target, source) {
	for (var key in source) {
		if (key === "__proto__" || key === "constructor" || key === "prototype") {
			continue;
		}
		target[key] = source[key];
	}
}
`,
		},
		{
			name: "hasOwnProperty guard",
			content: `
function merge(target, source) {
	for (var key in source) {
		if (!Object.prototype.hasOwnProperty.call(source, key)) {
			continue;
		}
		target[key] = source[key];
	}
}
`,
		},
		{
			name: "deny list membership",
			content: `
var blocked = ["__proto__", "constructor", "prototype"];
function merge(target, source) {
	for (var key in source) {
		if (blocked.includes(key)) {
			continue;
		}
		target[key] = source[key];
	}
}
`,
		},
		{
			name: "own keys iteration instead of for-in",
			content: `
function merge(target, source) {
	Object.keys(source).forEach(function (key) {
		target[key] = source[key];
	});
	return target;
}
`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got, ok := AnalyzeScript(ScriptAnalysis{URL: "https://app.example.test/app.js", Content: testCase.content}); ok {
				t.Fatalf("guarded merge produced a finding: %+v", got.Confidence)
			}
		})
	}
}

func TestAnalyzeScriptKeepsCommentMentionsOutOfGuardScope(t *testing.T) {
	// The comment names __proto__, but comments are masked before the local
	// scope is inspected: a note is not a filter.
	content := `
function merge(target, source) {
	// no __proto__ / constructor filter here on purpose
	for (var key in source) {
		target[key] = source[key];
	}
}
`
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	if got.Confidence.Value != 40 {
		t.Fatalf("confidence = %v, want 40.0 (50 base - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalNoGadget, -10)
	rejectSignal(t, got, signalFrozenPrototype)
}

func TestAnalyzeScriptIgnoresDistantProtoMention(t *testing.T) {
	// The guard window is local by construction: a __proto__ mention outside it
	// says nothing about this loop.
	content := `var meta = {"__proto__": null};` + "\nvar pad = \"" + strings.Repeat("x", 260) + "\";\n" + mergeLoop

	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	requireSignal(t, got, signalNoGadget, -10)
}

func TestAnalyzeScriptDropsFrozenPrototype(t *testing.T) {
	content := "Object.freeze(Object.prototype);\n" + mergeLoop + runtimeFixture
	if got, ok := AnalyzeScript(ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content}); ok {
		t.Fatalf("hardened script produced a finding: %+v", got.Confidence)
	}
}

func TestAnalyzeScriptPenalisesFreezeAfterSink(t *testing.T) {
	content := mergeLoop + "Object.freeze(Object.prototype);\n"
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})

	if got.Confidence.Value != 10 {
		t.Fatalf("confidence = %v, want 10.0 (50 base - 30 late freeze - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalFrozenPrototype, -30)
}

func TestAnalyzeScriptIgnoresCommentedFreeze(t *testing.T) {
	// Hardening that only exists in a comment is not hardening: the gate reads
	// executable code, not raw text.
	content := "// Object.freeze(Object.prototype) was removed in v2\n" + mergeLoop
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	if got.Confidence.Value != 40 {
		t.Fatalf("confidence = %v, want 40.0 (50 base - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalNoGadget, -10)
}

func TestAnalyzeScriptDropsThirdPartyAndEmpty(t *testing.T) {
	cases := []struct {
		name   string
		script ScriptAnalysis
	}{
		{
			name:   "third-party vendor bundle",
			script: ScriptAnalysis{URL: "https://cdn.example.test/jquery.js", Content: mergeLoop, IsThirdParty: true},
		},
		{
			name:   "empty content",
			script: ScriptAnalysis{URL: "https://app.example.test/app.js"},
		},
		{
			name:   "whitespace only",
			script: ScriptAnalysis{URL: "https://app.example.test/app.js", Content: "  \n\t\n"},
		},
		{
			name:   "third-party even when vulnerable",
			script: ScriptAnalysis{URL: "https://cdn.example.test/lodash.js", Content: "/* lodash 4.17.11 */", IsThirdParty: true},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got, ok := AnalyzeScript(testCase.script); ok {
				t.Fatalf("gate did not drop the script: %+v", got)
			}
		})
	}
}

func TestAnalyzeScriptReturnsLowScoreForMinifiedSink(t *testing.T) {
	// One mangled line, no source, no gadget. §5.2.4's example puts this at
	// 25.0, and the module must still return it: filtering is the pipeline's
	// job, not the detector's.
	content := strings.Repeat("var a=1,b=2,c=3;", 200) + "function m(t,s){for(var k in s){t[k]=s[k];}}"
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/static/bundle.js", Content: content})

	if got.Confidence.Value != 25 {
		t.Fatalf("confidence = %v, want 25.0 (50 base - 15 minified - 10 no gadget)", got.Confidence.Value)
	}
	if got.Confidence.Band != confidence.BandLow {
		t.Fatalf("band = %q, want low", got.Confidence.Band)
	}
	if got.Confidence.Value >= confidence.ThresholdDefault {
		t.Fatal("this case is used to prove low scores are returned, not thresholded away")
	}
	requireSignal(t, got, signalMinified, -15)
	requireSignal(t, got, signalNoGadget, -10)
}

func TestAnalyzeScriptDetectsUnvalidatedPostMessage(t *testing.T) {
	content := `
window.addEventListener("message", function (event) {
	var config = merge({}, event.data);
	render(config);
});
` + mergeLoop

	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	if got.Confidence.Value != 55 {
		t.Fatalf("confidence = %v, want 55.0 (50 base + 15 postMessage - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalPostMessage, 15)
}

func TestAnalyzeScriptCreditsOriginCheck(t *testing.T) {
	content := `
window.addEventListener("message", function (event) {
	if (event.origin !== "https://app.example.test") {
		return;
	}
	var config = merge({}, event.data);
	render(config);
});
` + mergeLoop

	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	if got.Confidence.Value != 40 {
		t.Fatalf("confidence = %v, want 40.0 (50 base - 10 no gadget)", got.Confidence.Value)
	}
	rejectSignal(t, got, signalPostMessage)
}

func TestAnalyzeScriptReportsVulnerableLibraryWithoutSink(t *testing.T) {
	script := ScriptAnalysis{
		URL:     "https://app.example.test/vendor/lodash.min.js",
		Content: "/*! lodash 4.17.11 | MIT License */\nvar _ = {};\n",
	}

	got := analyze(t, script)
	if got.Confidence.Value != 65 {
		t.Fatalf("confidence = %v, want 65.0 (50 base + 25 library - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalVulnerableLibrary, 25)
	requireSignal(t, got, signalNoGadget, -10)
	if !strings.Contains(got.Context, "lodash 4.17.11") {
		t.Fatalf("context = %q, want the vulnerable version named", got.Context)
	}
	if got.Value != script.URL {
		t.Fatalf("value = %q, want the script URL", got.Value)
	}
}

func TestAnalyzeScriptTreatsOldMajorLodashAsVulnerable(t *testing.T) {
	got := analyze(t, ScriptAnalysis{
		URL:     "https://app.example.test/vendor/lodash-3.10.1.min.js",
		Content: "var _ = {};",
	})
	requireSignal(t, got, signalVulnerableLibrary, 25)
}

func TestAnalyzeScriptRequiresCorroborationForDeparam(t *testing.T) {
	t.Run("signature alone is not a finding", func(t *testing.T) {
		content := `var params = $.deparam(location.search);`
		if got, ok := AnalyzeScript(ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content}); ok {
			t.Fatalf("uncorroborated deparam produced a finding: %+v", got.Confidence)
		}
	})

	t.Run("signature with a gadget is", func(t *testing.T) {
		content := `
var params = $.deparam(window.location.search);
var el = document.createElement("script");
el.src = params.src || "/static/player.js";
`
		got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
		requireSignal(t, got, signalVulnerableLibrary, 25)
		requireSignal(t, got, signalLocationSource, 20)
		requireSignal(t, got, signalSinkGadget, 15)
		if got.Confidence.Value != 100 {
			t.Fatalf("confidence = %v, want the clamped 100.0", got.Confidence.Value)
		}
	})
}

func TestAnalyzeScriptDetectsServerReflectionEvidence(t *testing.T) {
	// The only in-band evidence available without network I/O: the page carries
	// a JSON object whose nested key is a prototype key.
	content := mergeLoop + `
var snapshot = {"theme": {"__proto__": {"isAdmin": "1"}}};
`
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	if got.Confidence.Value != 50 {
		t.Fatalf("confidence = %v, want 50.0 (50 base + 10 reflection - 10 no gadget)", got.Confidence.Value)
	}
	requireSignal(t, got, signalServerReflection, 10)
}

func TestAnalyzeScriptFallsBackToSnippetWithoutURL(t *testing.T) {
	got := analyze(t, ScriptAnalysis{Content: mergeLoop})
	if got.Value == "" || !strings.Contains(got.Value, "for (var key in source)") {
		t.Fatalf("value = %q, want the matched loop as evidence", got.Value)
	}
	if got.URL != "" {
		t.Fatalf("url = %q, want empty", got.URL)
	}
	if len(got.Fields) != 1 || got.Fields[0].Name != "Risk" {
		t.Fatalf("fields = %+v, want only Risk when there is no script URL", got.Fields)
	}
}

func TestAnalyzeScriptDoesNotMatchBackreferences(t *testing.T) {
	// The loop key is captured and quoted rather than backreferenced, so a key
	// with regexp metacharacters must not change the verdict.
	content := `
function merge(target, source) {
	for (var k$ in source) {
		target[k$] = source[k$];
	}
}
`
	got := analyze(t, ScriptAnalysis{URL: "https://app.example.test/app.js", Content: content})
	requireSignal(t, got, signalNoGadget, -10)
}
