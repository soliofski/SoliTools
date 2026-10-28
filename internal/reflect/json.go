package reflect

import (
	"context"
	"encoding/json"

	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/param"
)

// MethodJSON is the field value that tells a report, and a reader, that the
// canary travelled in a JSON body rather than a form or a query string.
const MethodJSON = "POST (JSON)"

// JSON probe findings use their own rule id: they share a URL with a query
// probe, and dedupe is keyed on rule|URL, so reusing reflect.html would silently
// drop one of the two findings.
const jsonRuleID = "reflect.json"

// JSONTarget is one API parameter probed through a JSON body. Path is the object
// path from the mined document, including the parameter name; it is what makes
// a nested candidate (`{"filter":{"url": …}}`) probe the right shape.
type JSONTarget struct {
	URL      string
	Name     string
	Path     []string
	Interest param.Interest
}

// ProbeJSON posts each canary as a JSON value and reports a reflection.
func (a *Analyzer) ProbeJSON(ctx context.Context, target JSONTarget) (finding.Finding, bool) {
	return Analyze(a.SubmitJSON(ctx, target))
}

// SubmitJSON is the JSON counterpart of Submit, reusing the canary loop.
func (a *Analyzer) SubmitJSON(ctx context.Context, target JSONTarget) Submission {
	path := normalizeJSONPath(target.Path, target.Name)
	name := target.Name
	if len(path) > 0 {
		name = path[len(path)-1]
	}

	submission := a.submit(ctx, Target{
		URL:      target.URL,
		Name:     name,
		Interest: target.Interest,
		Method:   MethodJSON,
	}, func(payload string) (*httpx.Response, error) {
		body, err := jsonPayload(path, payload)
		if err != nil {
			return nil, err
		}
		return a.client.PostJSON(ctx, target.URL, body)
	})
	submission.RuleID = jsonRuleID
	return submission
}

// normalizeJSONPath guarantees a path that ends in the parameter name.
func normalizeJSONPath(path []string, name string) []string {
	if len(path) > 0 {
		return path
	}
	if name == "" {
		return nil
	}
	return []string{name}
}

// jsonPayload nests the canary at the mined path: ["filter","url"] becomes
// {"filter":{"url":"…"}}.
func jsonPayload(path []string, value string) ([]byte, error) {
	var node any = value
	for index := len(path) - 1; index >= 0; index-- {
		node = map[string]any{path[index]: node}
	}
	return json.Marshal(node)
}
