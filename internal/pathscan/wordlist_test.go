package pathscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWordlist(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	return path
}

func TestLoadWordlistCleansEntries(t *testing.T) {
	path := writeWordlist(t, []string{
		"# a comment",
		"",
		"   ",
		".env",
		" /admin ",
		".env",
		"//backup.sql",
		"graphql",
	})

	words, truncated, err := LoadWordlist(path, MaxCustomWords)
	if err != nil {
		t.Fatalf("LoadWordlist: %v", err)
	}
	if truncated {
		t.Fatal("a short list must not be reported as truncated")
	}
	want := []string{".env", "admin", "backup.sql", "graphql"}
	if len(words) != len(want) {
		t.Fatalf("words = %#v, want %#v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Errorf("word %d = %q, want %q", i, words[i], want[i])
		}
	}
}

func TestLoadWordlistCapsEntries(t *testing.T) {
	lines := make([]string, 0, 250)
	for i := 0; i < 250; i++ {
		lines = append(lines, fmt.Sprintf("path-%03d", i))
	}
	path := writeWordlist(t, lines)

	words, truncated, err := LoadWordlist(path, MaxCustomWords)
	if err != nil {
		t.Fatalf("LoadWordlist: %v", err)
	}
	if !truncated {
		t.Fatal("a list beyond the cap must report truncation")
	}
	if len(words) != MaxCustomWords {
		t.Fatalf("words = %d, want the cap of %d", len(words), MaxCustomWords)
	}
	if words[0] != "path-000" || words[len(words)-1] != "path-199" {
		t.Fatalf("unexpected slice boundaries: %q ... %q", words[0], words[len(words)-1])
	}
}

func TestLoadWordlistRejectsMissingFile(t *testing.T) {
	if _, _, err := LoadWordlist(filepath.Join(t.TempDir(), "absent.txt"), MaxCustomWords); err == nil {
		t.Fatal("a missing file must be an error")
	}
}

func TestLoadWordlistWithNoUsableEntries(t *testing.T) {
	path := writeWordlist(t, []string{"# only comments", "", "   "})
	words, _, err := LoadWordlist(path, MaxCustomWords)
	if err != nil {
		t.Fatalf("LoadWordlist: %v", err)
	}
	if len(words) != 0 {
		t.Fatalf("words = %#v, want none", words)
	}
}

func TestDefaultWordlistIsACopy(t *testing.T) {
	first := DefaultWordlist()
	if len(first) != 26 {
		t.Fatalf("default wordlist = %d entries, want 26", len(first))
	}
	first[0] = "mutated"

	if second := DefaultWordlist(); second[0] != ".env" {
		t.Fatalf("DefaultWordlist leaked its backing slice: %q", second[0])
	}
}
