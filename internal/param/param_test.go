package param

import (
	"net/url"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		want Interest
	}{
		{"url", High},
		{"redirect", High},
		{"return_to", High},
		{"next", High},
		{"file", High},
		{"id", Medium},
		{"q", Medium},
		{"token", Medium},
		{"some_random_name", Low},
		{"utm_source", Noise},
		{"UTM_Medium", Noise},
		{"fbclid", Noise},
		{"gclid", Noise},
		{"", Noise},
	}
	for _, c := range cases {
		if got := Classify(c.name); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestInterestString(t *testing.T) {
	if High.String() != "high" || Noise.String() != "noise" {
		t.Fatalf("unexpected labels: %q %q", High.String(), Noise.String())
	}
}

func TestNamesSkipsNoiseAndDuplicates(t *testing.T) {
	parsed, err := url.Parse("https://x.test/?a=1&utm_source=z&b=2&a=3&fbclid=q&c")
	if err != nil {
		t.Fatal(err)
	}
	got := Names(parsed)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNamesHandlesEncodingAndEmptyQuery(t *testing.T) {
	parsed, err := url.Parse("https://x.test/?na%20me=1")
	if err != nil {
		t.Fatal(err)
	}
	if got := Names(parsed); len(got) != 1 || got[0] != "na me" {
		t.Fatalf("Names = %v, want [na me]", got)
	}
	empty, _ := url.Parse("https://x.test/")
	if got := Names(empty); len(got) != 0 {
		t.Fatalf("Names = %v, want none", got)
	}
	if got := Names(nil); len(got) != 0 {
		t.Fatalf("Names(nil) = %v", got)
	}
}
