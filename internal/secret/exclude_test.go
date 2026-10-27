package secret

import "testing"

func TestPlaceholderReason(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{"IOSFNDNN7EXAMPLE", true}, // canonical AWS documentation key
		{"your_api_key_here", true},
		{"changeme123", true},
		{"<token>", true},
		{"first_test_key", true}, // spec: drop values containing "test"
		{"fake_credential", true},
		{"demo_account_key", true},
		{"localhost", true},
		{"Q3EGVZ7J4K2WN5TP", false},
		{"bT9xK2mQ7vL4nR8sW1zY", false},
	}
	for _, c := range cases {
		if _, got := placeholderReason(c.payload); got != c.want {
			t.Errorf("placeholderReason(%q) = %v, want %v", c.payload, got, c.want)
		}
	}
}

func TestIsDegenerate(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{"aaaaaaaaaaaa", true},
		{"abababababab", true},
		{"abc", true},
		{"abcd", false},
		{"aB3xZ9qLmN2p", false},
		{"ab0000000000cd", true}, // eight-in-a-row padding
		{"Q3EGVZ7J4K2WN5TP", false},
	}
	for _, c := range cases {
		if got := isDegenerate(c.payload); got != c.want {
			t.Errorf("isDegenerate(%q) = %v, want %v", c.payload, got, c.want)
		}
	}
}

func TestStripPrefix(t *testing.T) {
	rule := &Rule{Prefixes: []string{"ghp_", "gho_"}}
	if got := rule.StripPrefix("gho_abc"); got != "abc" {
		t.Errorf("StripPrefix = %q, want %q", got, "abc")
	}
	if got := rule.StripPrefix("ghp_"); got != "ghp_" {
		t.Errorf("bare prefix must not be stripped, got %q", got)
	}
	if got := rule.StripPrefix("xyz"); got != "xyz" {
		t.Errorf("unknown prefix changed: %q", got)
	}
}
