// Package confidence implements SoliTools' explainable confidence model.
//
// Every finding starts from the base confidence declared by its detector and is
// then adjusted by named signals. All adjustments are recorded, so a finished
// score can be reconstructed and challenged after the fact: there is no opaque
// model and no randomness, and identical evidence always yields an identical
// score.
//
// Scores are clamped to [0, 100] and rounded to one decimal. The band
// boundaries are fixed constants, so a score means the same thing in every
// module and across releases:
//
//	90-100  critical     vendor-identified and structurally valid
//	 75-89  high         likely a real finding
//	 60-74  medium-high  default display threshold
//	 40-59  medium       shown with --all
//	  0-39  low          usually noise
package confidence

import (
	"fmt"
	"math"
)

// Band buckets a confidence value into an actionable label.
type Band string

const (
	// BandLow covers [0, 40): usually noise.
	BandLow Band = "low"
	// BandMedium covers [40, 60): shown only with --all.
	BandMedium Band = "medium"
	// BandMediumHigh covers [60, 75): the default display threshold.
	BandMediumHigh Band = "medium-high"
	// BandHigh covers [75, 90): likely a real finding.
	BandHigh Band = "high"
	// BandCritical covers [90, 100]: vendor-identified and validated.
	BandCritical Band = "critical"
)

// Band boundaries. Each Max value is exclusive and belongs to the next band up.
const (
	BandLowMax        = 40.0
	BandMediumMax     = 60.0
	BandMediumHighMax = 75.0
	BandHighMax       = 90.0
)

// Display thresholds. Default is the product default; Strict is --strict.
const (
	ThresholdDefault = 60.0
	ThresholdStrict  = 75.0
	ThresholdAll     = 0.0
)

// Score range.
const (
	MinScore = 0.0
	MaxScore = 100.0
)

// Signal is one named adjustment to a score.
type Signal struct {
	Name   string  `json:"name"`
	Delta  float64 `json:"delta"`
	Reason string  `json:"reason"`
}

// Score is a finished confidence value together with its full derivation.
type Score struct {
	Base    float64  `json:"base"`
	Value   float64  `json:"value"`
	Band    Band     `json:"band"`
	Signals []Signal `json:"signals,omitempty"`
}

// BandOf returns the band for an arbitrary value, clamped to [0, 100].
func BandOf(v float64) Band {
	switch {
	case v < BandLowMax:
		return BandLow
	case v < BandMediumMax:
		return BandMedium
	case v < BandMediumHighMax:
		return BandMediumHigh
	case v < BandHighMax:
		return BandHigh
	default:
		return BandCritical
	}
}

// Builder accumulates signals for a single score.
//
// A Builder is not safe for concurrent use; create one per candidate finding.
type Builder struct {
	base    float64
	signals []Signal
}

// New starts a score from a detector's base confidence.
func New(base float64) *Builder {
	return &Builder{base: base}
}

// Add records a named adjustment. Zero deltas are ignored so traces stay free
// of no-op entries.
func (b *Builder) Add(name string, delta float64, reason string) *Builder {
	if delta == 0 {
		return b
	}
	b.signals = append(b.signals, Signal{Name: name, Delta: delta, Reason: reason})
	return b
}

// AddSignal records an already-built signal when its delta is meaningful.
func (b *Builder) AddSignal(signal Signal, ok bool) *Builder {
	if !ok {
		return b
	}
	return b.Add(signal.Name, signal.Delta, signal.Reason)
}

// Build clamps, rounds and bands the value together with its trace.
func (b *Builder) Build() Score {
	value := round1(clamp(b.base + sum(b.signals)))
	return Score{
		Base:    round1(clamp(b.base)),
		Value:   value,
		Band:    BandOf(value),
		Signals: append([]Signal(nil), b.signals...),
	}
}

// AtLeast reports whether the score reaches min.
func (s Score) AtLeast(min float64) bool { return s.Value >= min }

// String renders the score for human output, e.g. "85.0 (high)".
func (s Score) String() string {
	return fmt.Sprintf("%.1f (%s)", s.Value, s.Band)
}

func sum(signals []Signal) float64 {
	var total float64
	for _, s := range signals {
		total += s.Delta
	}
	return total
}

// clamp normalizes to [0, 100]. NaN is mapped to MinScore rather than
// propagated: a NaN score would compare false against every threshold and
// silently suppress a finding, so the minimum is the honest equivalent.
func clamp(v float64) float64 {
	if math.IsNaN(v) {
		return MinScore
	}
	return math.Max(MinScore, math.Min(MaxScore, v))
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
