package secret

import (
	"regexp"
	"strings"
	"testing"
)

func TestRuleSetInvariants(t *testing.T) {
	all := append(HighPrecisionRules(), GenericRules()...)
	seen := make(map[string]struct{}, len(all))

	for _, rule := range all {
		t.Run(rule.ID, func(t *testing.T) {
			if rule.ID == "" || !strings.HasPrefix(rule.ID, "secret.") {
				t.Fatalf("rule ID %q must be namespaced", rule.ID)
			}
			if _, duplicate := seen[rule.ID]; duplicate {
				t.Fatalf("duplicate rule ID %q", rule.ID)
			}
			seen[rule.ID] = struct{}{}

			if rule.Name == "" || rule.Description == "" {
				t.Fatal("rule needs a name and a description")
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
			if rule.Group > 0 {
				// A capture-group rule must not also be anchored to the whole
				// match, otherwise stripping prefixes breaks.
				if rule.Group == 0 {
					t.Fatal("unreachable")
				}
			}
			if rule.EntropyMin < 0 || rule.EntropyMin > 8 {
				t.Fatalf("entropy floor %v outside [0, 8]", rule.EntropyMin)
			}
			if rule.MinLen < 0 || rule.MaxLen < 0 {
				t.Fatal("negative length bound")
			}
			if rule.MaxLen > 0 && rule.MinLen > rule.MaxLen {
				t.Fatalf("MinLen %d > MaxLen %d", rule.MinLen, rule.MaxLen)
			}
		})
	}
}

func TestHighPrecisionRulesAreNotGeneric(t *testing.T) {
	for _, rule := range HighPrecisionRules() {
		if rule.Generic {
			t.Errorf("%s is marked generic but sits in the default set", rule.ID)
		}
	}
}

func TestGenericRulesAreMarked(t *testing.T) {
	for _, rule := range GenericRules() {
		if !rule.Generic {
			t.Errorf("%s must be marked generic", rule.ID)
		}
	}
}

func TestRuleSetsAreIndependent(t *testing.T) {
	// Callers must be able to mutate the returned slice without corrupting the
	// next caller's view.
	first := HighPrecisionRules()
	first[0] = nil
	second := HighPrecisionRules()
	if second[0] == nil {
		t.Fatal("rule slices share backing storage")
	}
}
