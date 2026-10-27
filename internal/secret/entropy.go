package secret

import "math"

// Entropy returns the Shannon entropy of s, in bits per symbol.
//
// It is computed over runes so multi-byte content is not overcounted, and it
// is only ever applied to a payload (the captured value with any vendor prefix
// removed). Entropy is a gate here, not a score contribution: a value below a
// rule's floor is not a weak finding, it is a malformed one.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, len(s))
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
