package secret

import "testing"

func TestEntropy(t *testing.T) {
	cases := []struct {
		input string
		want  float64
	}{
		{"", 0},
		{"a", 0},
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
		{"aaaaab", 0.6500224216483541},
	}
	for _, c := range cases {
		got := Entropy(c.input)
		if diff := got - c.want; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("Entropy(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestEntropyIsRuneBased(t *testing.T) {
	// Four distinct runes, two bytes each: byte-based counting would report a
	// different value, so this pins the rune semantics.
	got := Entropy("日本語だ")
	want := 2.0
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("Entropy(multibyte) = %v, want %v", got, want)
	}
}
