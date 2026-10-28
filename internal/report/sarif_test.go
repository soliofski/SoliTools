package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/soliofski/SoliTools/internal/confidence"
	"github.com/soliofski/SoliTools/internal/finding"
	"github.com/soliofski/SoliTools/internal/scan"
	"github.com/soliofski/SoliTools/internal/term"
)

// redirectSample is a network finding: no line number, warning band.
func redirectSample() finding.Finding {
	return finding.Finding{
		Kind:       finding.KindRedirect,
		Category:   "Open Redirect",
		RuleID:     "redirect.open",
		Title:      "Open Redirect",
		URL:        "https://target.test/?next=x",
		Value:      "//example.com/solitools-redirect-check",
		Confidence: confidence.New(65).Build(),
	}
}

func TestBuildSARIFStructure(t *testing.T) {
	secret := sampleResult().Findings[0] // 90 → critical, has a Line field
	redirect := redirectSample()

	log := buildSARIF(scan.Result{Target: "https://target.test/"}, []finding.Finding{secret, redirect}, Options{
		Version:   "test-version",
		Threshold: 60,
	})

	if log.Schema != sarifSchema {
		t.Fatalf("schema = %q", log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "SoliTools" || run.Tool.Driver.Version != "test-version" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	if run.Properties["target"] != "https://target.test/" {
		t.Fatalf("run properties = %v", run.Properties)
	}

	// Rules are emitted once each and sorted by id.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "redirect.open" || run.Tool.Driver.Rules[1].ID != "secret.github-token" {
		t.Fatalf("rules are not sorted: %+v", run.Tool.Driver.Rules)
	}

	byRule := make(map[string]sarifResult, len(run.Results))
	for _, result := range run.Results {
		byRule[result.RuleID] = result
	}

	secretResult, ok := byRule["secret.github-token"]
	if !ok {
		t.Fatal("secret result missing")
	}
	if secretResult.Level != "error" {
		t.Fatalf("secret level = %q, want error", secretResult.Level)
	}
	if secretResult.RuleIndex != 1 {
		t.Fatalf("secret ruleIndex = %d, want 1", secretResult.RuleIndex)
	}
	if secretResult.Locations[0].PhysicalLocation.ArtifactLocation.URI != secret.URL {
		t.Fatalf("artifact uri = %q", secretResult.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	region := secretResult.Locations[0].PhysicalLocation.Region
	if region == nil || region.StartLine != 1 {
		t.Fatalf("region = %+v, want startLine 1", region)
	}
	if secretResult.PartialFingerprints["solitoolsFingerprint/v1"] != secret.Fingerprint {
		t.Fatalf("fingerprints = %v", secretResult.PartialFingerprints)
	}
	if secretResult.Properties["band"] != "critical" {
		t.Fatalf("properties = %v", secretResult.Properties)
	}
	if secretResult.Message.Text == "" {
		t.Fatal("message is empty")
	}

	redirectResult := byRule["redirect.open"]
	if redirectResult.Level != "warning" {
		t.Fatalf("redirect level = %q, want warning", redirectResult.Level)
	}
	if redirectResult.Locations[0].PhysicalLocation.Region != nil {
		t.Fatalf("a network finding must not carry a region: %+v", redirectResult.Locations[0])
	}
	if redirectResult.RuleIndex != 0 {
		t.Fatalf("redirect ruleIndex = %d, want 0", redirectResult.RuleIndex)
	}
}

func TestSARIFLevels(t *testing.T) {
	cases := map[string]string{
		"critical":    "error",
		"high":        "error",
		"medium-high": "warning",
		"medium":      "note",
		"low":         "note",
		"unknown":     "note",
	}
	for band, want := range cases {
		if got := sarifLevel(band); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", band, got, want)
		}
	}
}

func TestSecuritySeverity(t *testing.T) {
	cases := map[string]string{
		"critical":    "9.0",
		"high":        "7.5",
		"medium-high": "5.5",
		"medium":      "3.5",
		"low":         "1.5",
	}
	for band, want := range cases {
		if got := securitySeverity(band); got != want {
			t.Errorf("securitySeverity(%q) = %q, want %q", band, got, want)
		}
	}
}

func TestSARIFRuleCarriesSecuritySeverity(t *testing.T) {
	log := buildSARIF(scan.Result{}, []finding.Finding{sampleResult().Findings[0]}, Options{})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties["security-severity"] != "9.0" {
		t.Fatalf("rule properties = %v", rule.Properties)
	}
	tags, ok := rule.Properties["tags"].([]string)
	if !ok || len(tags) != 2 || tags[1] != "secret" {
		t.Fatalf("tags = %v", rule.Properties["tags"])
	}
}

func TestSARIFEmptyOutputUsesArrays(t *testing.T) {
	log := buildSARIF(scan.Result{}, nil, Options{})
	encoded, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, `"results":null`) {
		t.Fatal("results must be an array, not null")
	}
	if strings.Contains(text, `"rules":null`) {
		t.Fatal("rules must be an array, not null")
	}
}

func TestSARIFOutputIsMaskedAndClean(t *testing.T) {
	var buf bytes.Buffer
	theme := term.New(&buf, term.ModeAlways)

	shown, err := Render(&buf, sampleResult(), Options{
		Threshold: 60, Mask: true, SARIF: true, Theme: theme, Version: "test",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if shown != 1 {
		t.Fatalf("shown = %d, want 1", shown)
	}

	output := buf.String()
	if strings.Contains(output, "\x1b[") {
		t.Fatal("SARIF output contains ANSI escapes")
	}
	if strings.Contains(output, sampleSecret) {
		t.Fatalf("SARIF output leaks the raw secret:\n%s", output)
	}

	var decoded struct {
		Schema string `json:"$schema"`
		Runs   []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.Schema == "" {
		t.Fatal("$schema is missing")
	}
	if !strings.Contains(decoded.Runs[0].Results[0].Message.Text, "*") {
		t.Fatalf("message is not masked: %q", decoded.Runs[0].Results[0].Message.Text)
	}
}
