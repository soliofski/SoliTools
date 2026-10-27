package secret

import (
	"regexp"
	"strings"
	"testing"
)

func TestRuleSetInvariants(t *testing.T) {
	rules := Rules()
	seen := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			if rule.ID == "" || !strings.HasPrefix(rule.ID, "secret.") {
				t.Fatalf("rule ID %q must be namespaced", rule.ID)
			}
			if _, duplicate := seen[rule.ID]; duplicate {
				t.Fatalf("duplicate rule ID %q", rule.ID)
			}
			seen[rule.ID] = struct{}{}

			if rule.Title == "" || rule.Category == "" || rule.Description == "" {
				t.Fatal("rule needs a title, category and description")
			}
			if rule.Base <= 0 || rule.Base > 100 {
				t.Fatalf("base confidence %v outside (0, 100]", rule.Base)
			}

			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				t.Fatalf("pattern does not compile: %v", err)
			}
			if rule.Group > re.NumSubexp() {
				t.Fatalf("group %d does not exist (pattern has %d)", rule.Group, re.NumSubexp())
			}
			if rule.EntropyMin < 0 || rule.EntropyMin > 8 {
				t.Fatalf("entropy floor %v outside [0, 8]", rule.EntropyMin)
			}
			if rule.MaxLen > 0 && rule.MinLen > rule.MaxLen {
				t.Fatalf("MinLen %d > MaxLen %d", rule.MinLen, rule.MaxLen)
			}
		})
	}
}

func TestGenericRulesStayBelowDefaultThreshold(t *testing.T) {
	// The design contract: generic shape rules must not reach the default
	// display threshold on their own, otherwise they would flood normal runs.
	for _, rule := range Rules() {
		if !rule.Generic {
			continue
		}
		best := rule.Base + 5 // maximum entropy bonus, no structural signal
		if best >= 60 {
			t.Errorf("%s can reach %v, which clears the default threshold", rule.ID, best)
		}
	}
}

func TestRuleSetsAreIndependent(t *testing.T) {
	// Callers must be able to mutate the returned slice without corrupting the
	// next caller's view.
	first := Rules()
	first[0] = nil
	second := Rules()
	if second[0] == nil {
		t.Fatal("rule slices share backing storage")
	}
}

func TestNewValidatesRules(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(scanner.Rules()) != len(Rules()) {
		t.Fatalf("scanner has %d rules, want %d", len(scanner.Rules()), len(Rules()))
	}
}
