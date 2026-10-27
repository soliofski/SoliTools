//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd

package term

import "os"

// consoleWidth reports 0 on platforms without a supported console query, which
// makes Width fall back to $COLUMNS or DefaultWidth.
func consoleWidth(*os.File) int { return 0 }

// consoleHeight behaves like consoleWidth for the row count.
func consoleHeight(*os.File) int { return 0 }
