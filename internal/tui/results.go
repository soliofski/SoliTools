package tui

import (
	"strings"

	"solitools/internal/finding"
	"solitools/internal/scan"
	"solitools/internal/secret"
)

// ResultView is the findings explorer's state: the threshold-filtered list, the
// cursor, the scroll window and per-finding masking overrides.
type ResultView struct {
	Result    scan.Result
	Findings  []finding.Finding
	Selected  int
	Offset    int
	Threshold float64
	Mask      bool

	// masked records an explicit override per finding. Absent means "follow
	// Mask", so toggling works in both directions.
	masked map[string]bool
}

// NewResultView filters the result down to what the chosen threshold shows.
func NewResultView(result scan.Result, threshold float64, mask bool) *ResultView {
	view := &ResultView{Result: result, Threshold: threshold, Mask: mask, masked: make(map[string]bool)}
	for _, candidate := range result.Findings {
		if candidate.Confidence.Value >= threshold {
			view.Findings = append(view.Findings, candidate)
		}
	}
	return view
}

// Len is the number of visible findings.
func (v *ResultView) Len() int { return len(v.Findings) }

// Move shifts the selection, clamped to the list.
func (v *ResultView) Move(delta int) {
	if len(v.Findings) == 0 {
		v.Selected = 0
		return
	}
	v.Selected = clamp(v.Selected+delta, 0, len(v.Findings)-1)
}

// MoveTo selects an absolute index, clamped.
func (v *ResultView) MoveTo(index int) {
	if len(v.Findings) == 0 {
		v.Selected = 0
		return
	}
	v.Selected = clamp(index, 0, len(v.Findings)-1)
}

// Page moves by a screenful, clamped.
func (v *ResultView) Page(delta, height int) {
	if height < 1 {
		height = 1
	}
	v.Move(delta * height)
}

// Selected returns the highlighted finding.
func (v *ResultView) SelectedFinding() (finding.Finding, bool) {
	if len(v.Findings) == 0 {
		return finding.Finding{}, false
	}
	return v.Findings[clamp(v.Selected, 0, len(v.Findings)-1)], true
}

// KeepVisible scrolls the window so the selection stays on screen.
func (v *ResultView) KeepVisible(height int) {
	if height < 1 {
		height = 1
	}
	if v.Selected < v.Offset {
		v.Offset = v.Selected
	}
	if v.Selected >= v.Offset+height {
		v.Offset = v.Selected - height + 1
	}
	maxOffset := len(v.Findings) - height
	if maxOffset < 0 {
		maxOffset = 0
	}
	if v.Offset > maxOffset {
		v.Offset = maxOffset
	}
	if v.Offset < 0 {
		v.Offset = 0
	}
}

// Visible returns the slice of findings currently in the window.
func (v *ResultView) Visible(height int) []finding.Finding {
	if height < 1 || len(v.Findings) == 0 {
		return nil
	}
	v.KeepVisible(height)
	end := v.Offset + height
	if end > len(v.Findings) {
		end = len(v.Findings)
	}
	return v.Findings[v.Offset:end]
}

func findingKey(f finding.Finding) string {
	return f.RuleID + "|" + f.URL + "|" + f.Fingerprint
}

// IsMasked reports the effective masking state of one finding.
func (v *ResultView) IsMasked(f finding.Finding) bool {
	if state, ok := v.masked[findingKey(f)]; ok {
		return state
	}
	return v.Mask
}

// ToggleMask flips masking for one finding.
func (v *ResultView) ToggleMask(f finding.Finding) {
	v.masked[findingKey(f)] = !v.IsMasked(f)
}

// DisplayValue returns the value as it should appear in the detail panel.
func (v *ResultView) DisplayValue(f finding.Finding) string {
	if f.Value == "" {
		return ""
	}
	if v.IsMasked(f) && f.Kind == finding.KindSecret {
		return secret.Mask(f.Value)
	}
	return f.Value
}

// DisplayContext returns the context, with the secret masked when required.
func (v *ResultView) DisplayContext(f finding.Finding) string {
	if v.IsMasked(f) && f.Kind == finding.KindSecret && f.Value != "" {
		return strings.ReplaceAll(f.Context, f.Value, secret.Mask(f.Value))
	}
	return f.Context
}

// MaskLabel describes the current state for the detail panel.
func (v *ResultView) MaskLabel(f finding.Finding) string {
	if f.Kind != finding.KindSecret {
		return ""
	}
	if v.IsMasked(f) {
		return "MASKED"
	}
	return "REVEALED"
}
