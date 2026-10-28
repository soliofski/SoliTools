package param

import "testing"

func TestFromJSONExtractsInterestingKeys(t *testing.T) {
	body := []byte(`{
		"user": {"id": 7, "url": "/profile", "created_at": "2026-01-01"},
		"meta": {"callback": "cb", "count": 2},
		"utm_source": "newsletter",
		"random": true
	}`)
	got := FromJSON(body, 3)
	want := []string{"callback", "id", "url", "user"}
	if len(got) != len(want) {
		t.Fatalf("names = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("name %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestFromJSONRespectsDepth(t *testing.T) {
	body := []byte(`{"a": {"b": {"path": "/etc/passwd"}}}`)
	if got := FromJSON(body, 2); len(got) != 0 {
		t.Fatalf("names = %#v, want none beyond depth two", got)
	}
	if got := FromJSON(body, 3); len(got) != 1 || got[0] != "path" {
		t.Fatalf("names = %#v, want path at depth three", got)
	}
}

func TestFromJSONTraversesArraysWithoutDepthCost(t *testing.T) {
	body := []byte(`{"items": [{"next": "/page/2"}, {"target": "x"}]}`)
	got := FromJSON(body, 2)
	want := []string{"next", "target"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("names = %#v, want %#v", got, want)
	}
}

func TestFromJSONRejectsBadInput(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("{"),
		[]byte("not json"),
		[]byte(`{"url":`),
	}
	for _, body := range cases {
		if got := FromJSON(body, 3); got != nil {
			t.Errorf("FromJSON(%q) = %#v, want nil", body, got)
		}
	}
	if got := FromJSON([]byte(`{"url":"x"}`), 0); got != nil {
		t.Fatalf("a zero depth must return nothing: %#v", got)
	}
}

func TestLooksJSON(t *testing.T) {
	cases := []struct {
		contentType string
		body        string
		want        bool
	}{
		{"application/json", `{}`, true},
		{"application/json; charset=utf-8", `[]`, true},
		{"application/problem+json", `{}`, true},
		{"text/plain", ` {"url":"x"} `, true},
		{"text/html", `<html></html>`, false},
		{"", `plain text`, false},
		{"text/plain", `{`, false},
	}
	for _, testCase := range cases {
		if got := LooksJSON(testCase.contentType, []byte(testCase.body)); got != testCase.want {
			t.Errorf("LooksJSON(%q, %q) = %v, want %v", testCase.contentType, testCase.body, got, testCase.want)
		}
	}
}
