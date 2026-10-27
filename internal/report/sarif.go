package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"solitools/internal/finding"
	"solitools/internal/scan"
)

// SARIF 2.1.0 object model, limited to what SoliTools emits.
//
// SARIF is file-oriented while this tool is URL-oriented: a finding's URL
// becomes the artifact URI, and a region is attached only when the detector
// knows a line number (secrets inside a response body). Network findings —
// path, redirect, reflection — have no line and omit the region entirely.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// writeSARIF renders displayed findings as a SARIF log.
func writeSARIF(w io.Writer, result scan.Result, shown []finding.Finding, opts Options) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(buildSARIF(result, shown, opts))
}

// buildSARIF assembles the log. Rules are emitted once per distinct RuleID and
// sorted, so two runs of the same scan produce byte-identical output.
func buildSARIF(result scan.Result, shown []finding.Finding, opts Options) sarifLog {
	type ruleEntry struct {
		rule  sarifRule
		index int
	}

	catalogue := make(map[string]*ruleEntry, len(shown))
	results := make([]sarifResult, 0, len(shown))

	for _, candidate := range shown {
		if _, exists := catalogue[candidate.RuleID]; !exists {
			catalogue[candidate.RuleID] = &ruleEntry{rule: sarifRule{
				ID:               candidate.RuleID,
				Name:             candidate.Title,
				ShortDescription: sarifMessage{Text: candidate.Title},
				Properties: map[string]any{
					"security-severity": securitySeverity(string(candidate.Confidence.Band)),
					"tags":              []string{"security", strings.ToLower(string(candidate.Kind))},
				},
			}}
		}

		location := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifact{URI: candidate.URL},
			},
		}
		if line := lineNumber(candidate); line > 0 {
			location.PhysicalLocation.Region = &sarifRegion{StartLine: line}
		}

		properties := map[string]any{
			"confidence": candidate.Confidence.Value,
			"base":       candidate.Confidence.Base,
			"band":       string(candidate.Confidence.Band),
			"kind":       string(candidate.Kind),
			"category":   candidate.Category,
		}
		if candidate.Context != "" {
			properties["context"] = candidate.Context
		}
		if candidate.Fingerprint != "" {
			properties["fingerprint"] = candidate.Fingerprint
		}
		if len(candidate.Confidence.Signals) > 0 {
			properties["signals"] = candidate.Confidence.Signals
		}
		if len(candidate.Fields) > 0 {
			properties["fields"] = candidate.Fields
		}

		item := sarifResult{
			RuleID:     candidate.RuleID,
			Level:      sarifLevel(string(candidate.Confidence.Band)),
			Message:    sarifMessage{Text: resultMessage(candidate)},
			Locations:  []sarifLocation{location},
			Properties: properties,
		}
		if candidate.Fingerprint != "" {
			item.PartialFingerprints = map[string]string{
				"solitoolsFingerprint/v1": candidate.Fingerprint,
			}
		}
		results = append(results, item)
	}

	ids := make([]string, 0, len(catalogue))
	for id := range catalogue {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for index, id := range ids {
		catalogue[id].index = index
		rules = append(rules, catalogue[id].rule)
	}
	for i := range results {
		results[i].RuleIndex = catalogue[results[i].RuleID].index
	}

	return sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "SoliTools",
				Version: opts.Version,
				Rules:   rules,
			}},
			Results: results,
			Properties: map[string]any{
				"target":    result.Target,
				"threshold": opts.Threshold,
			},
		}},
	}
}

// resultMessage builds the one-line summary a viewer shows.
func resultMessage(candidate finding.Finding) string {
	message := candidate.Title
	if candidate.Value != "" {
		message += ": " + candidate.Value
	}
	message += fmt.Sprintf(" (confidence %.0f, %s)", candidate.Confidence.Value, candidate.Confidence.Band)
	if candidate.URL != "" {
		message += " at " + candidate.URL
	}
	return message
}

// sarifLevel maps a confidence band to a SARIF result level.
func sarifLevel(band string) string {
	switch band {
	case "critical", "high":
		return "error"
	case "medium-high":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps a band to the 0-10 score GitHub reads from a rule.
func securitySeverity(band string) string {
	switch band {
	case "critical":
		return "9.0"
	case "high":
		return "7.5"
	case "medium-high":
		return "5.5"
	case "medium":
		return "3.5"
	default:
		return "1.5"
	}
}

// lineNumber returns the response-body line a finding points at, or 0 when the
// detector has no line information.
func lineNumber(candidate finding.Finding) int {
	for _, field := range candidate.Fields {
		if field.Name != "Line" {
			continue
		}
		value := field.Value
		if colon := strings.IndexByte(value, ':'); colon > 0 {
			value = value[:colon]
		}
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && number > 0 {
			return number
		}
	}
	return 0
}
