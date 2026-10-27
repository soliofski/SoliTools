package confidence

import (
	"math"
	"testing"
)

func TestBandOf(t *testing.T) {
	cases := []struct {
		value float64
		want  Band
	}{
		{-10, BandLow},
		{0, BandLow},
		{39.9, BandLow},
		{40, BandMedium},
		{59.9, BandMedium},
		{60, BandMediumHigh},
		{74.9, BandMediumHigh},
		{75, BandHigh},
		{89.9, BandHigh},
		{90, BandCritical},
		{100, BandCritical},
		{250, BandCritical},
	}
	for _, c := range cases {
		if got := BandOf(c.value); got != c.want {
			t.Errorf("BandOf(%v) = %q, want %q", c.value, got, c.want)
		}
	}
}

func TestThresholdsMatchBands(t *testing.T) {
	if got := BandOf(ThresholdDefault); got != BandMediumHigh {
		t.Errorf("default threshold %v falls in %q", ThresholdDefault, got)
	}
	if got := BandOf(ThresholdStrict); got != BandHigh {
		t.Errorf("strict threshold %v falls in %q", ThresholdStrict, got)
	}
	if got := BandOf(ThresholdAll); got != BandLow {
		t.Errorf("--all threshold %v falls in %q", ThresholdAll, got)
	}
}

func TestBuildAppliesSignalsInOrder(t *testing.T) {
	s := New(80).
		Add("path-context", -20, "test fixture").
		Add("structural", 5, "decodes").
		Build()

	if want := 65.0; s.Value != want {
		t.Fatalf("value = %v, want %v", s.Value, want)
	}
	if s.Base != 80 {
		t.Fatalf("base = %v, want 80", s.Base)
	}
	if s.Band != BandMediumHigh {
		t.Fatalf("band = %q, want %q", s.Band, BandMediumHigh)
	}
	if len(s.Signals) != 2 {
		t.Fatalf("signals = %d, want 2", len(s.Signals))
	}
	if s.Signals[0].Name != "path-context" || s.Signals[1].Name != "structural" {
		t.Fatalf("signals out of order: %+v", s.Signals)
	}
}

func TestBuildClampsAndRounds(t *testing.T) {
	cases := []struct {
		base     float64
		signals  []float64
		want     float64
		wantBand Band
	}{
		{95, []float64{20}, 100, BandCritical},
		{30, []float64{-20}, 10, BandLow},
		{55, []float64{-10, -3.33}, 41.7, BandMedium},
		{50, []float64{0.04}, 50, BandMedium},
		{89.96, nil, 90, BandCritical},
		{74.96, nil, 75, BandHigh},
	}
	for _, c := range cases {
		b := New(c.base)
		for _, d := range c.signals {
			b.Add("s", d, "test")
		}
		s := b.Build()
		if s.Value != c.want {
			t.Errorf("base %v with %v = %v, want %v", c.base, c.signals, s.Value, c.want)
		}
		if s.Band != c.wantBand {
			t.Errorf("base %v with %v band = %q, want %q", c.base, c.signals, s.Band, c.wantBand)
		}
	}
}

func TestZeroDeltaIsIgnored(t *testing.T) {
	s := New(70).Add("noise", 0, "no effect").Build()
	if len(s.Signals) != 0 {
		t.Fatalf("signals = %+v, want none", s.Signals)
	}
}

func TestAddSignalHonoursOkFlag(t *testing.T) {
	s := New(60).AddSignal(Signal{Name: "x", Delta: 5}, false).Build()
	if len(s.Signals) != 0 {
		t.Fatalf("signals = %+v, want none", s.Signals)
	}
	s = New(60).AddSignal(Signal{Name: "x", Delta: 5, Reason: "r"}, true).Build()
	if s.Value != 65 || len(s.Signals) != 1 {
		t.Fatalf("score = %+v, want 65 with one signal", s)
	}
}

func TestBuildDoesNotAliasBuilderSignals(t *testing.T) {
	b := New(60).Add("a", 5, "first")
	first := b.Build()
	b.Add("b", 5, "second")
	second := b.Build()

	if len(first.Signals) != 1 {
		t.Fatalf("earlier score changed: %+v", first.Signals)
	}
	if len(second.Signals) != 2 {
		t.Fatalf("later score = %+v, want 2 signals", second.Signals)
	}
	if first.Value != 65 || second.Value != 70 {
		t.Fatalf("values = %v/%v, want 65/70", first.Value, second.Value)
	}
}

func TestAtLeast(t *testing.T) {
	s := New(60).Build()
	if !s.AtLeast(60) {
		t.Error("AtLeast(60) = false, want true at the boundary")
	}
	if s.AtLeast(60.1) {
		t.Error("AtLeast(60.1) = true, want false")
	}
}

func TestString(t *testing.T) {
	if got := New(85).Build().String(); got != "85.0 (high)" {
		t.Fatalf("String() = %q", got)
	}
}

func TestNaNBaseDoesNotPanic(t *testing.T) {
	// Defensive: a NaN would otherwise fail every threshold comparison and
	// silently hide findings. clamp() maps it to the minimum band instead.
	s := New(math.NaN()).Build()
	if math.IsNaN(s.Value) {
		t.Fatalf("value is NaN")
	}
	if s.Value != MinScore {
		t.Fatalf("value = %v, want %v", s.Value, MinScore)
	}
}
