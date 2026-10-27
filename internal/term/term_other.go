//go:build !windows

package term

import "os"

// enableVirtualTerminal is a no-op outside Windows: ANSI support is provided by
// the terminal emulator, and isTerminal already rejects pipes and files.
func enableVirtualTerminal(*os.File) bool { return true }
