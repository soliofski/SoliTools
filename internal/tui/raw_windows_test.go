//go:build windows

package tui

import "testing"

// TestRawInputModeClearsVTInput pins the arrow-key fix: with the VT input flag
// left set, the console turns arrows into ESC [ A/B and ReadConsoleInputW
// delivers the trailing characters as printable runes.
func TestRawInputModeClearsVTInput(t *testing.T) {
	const unrelated = 0x0080
	mode := uint32(enableProcessedInput | enableLineInput | enableEchoInput | enableVirtualTerminalInput | unrelated)

	raw := rawInputMode(mode)
	for _, bit := range []uint32{enableProcessedInput, enableLineInput, enableEchoInput, enableVirtualTerminalInput} {
		if raw&bit != 0 {
			t.Fatalf("rawInputMode(%#x) = %#x, bit %#x must be cleared", mode, raw, bit)
		}
	}
	if raw&unrelated == 0 {
		t.Fatalf("rawInputMode(%#x) = %#x, unrelated flags must survive", mode, raw)
	}
}

func TestRawInputModeKeepsVTInputOffWhenAbsent(t *testing.T) {
	if got := rawInputMode(0); got != 0 {
		t.Fatalf("rawInputMode(0) = %#x, want 0", got)
	}
}
