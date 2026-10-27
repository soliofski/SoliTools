package term

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultWidth is used when the terminal size cannot be determined.
const DefaultWidth = 100

// DefaultHeight is used when the terminal row count cannot be determined.
const DefaultHeight = 24

// Width returns the usable column count for w.
//
// Order: the real console size, then $COLUMNS, then DefaultWidth. The console
// query is only attempted for a file handle, so callers can pass any writer.
func Width(w io.Writer) int {
	if file, ok := w.(*os.File); ok {
		if columns := consoleWidth(file); columns > 0 {
			return columns
		}
	}
	if columns := envColumns(); columns > 0 {
		return columns
	}
	return DefaultWidth
}

// envColumns reads $COLUMNS, rejecting values that cannot be a real width.
func envColumns() int {
	raw := strings.TrimSpace(os.Getenv("COLUMNS"))
	if raw == "" {
		return 0
	}
	columns, err := strconv.Atoi(raw)
	if err != nil || columns <= 0 || columns > 1000 {
		return 0
	}
	return columns
}

// Height returns the usable row count for w, with the same fallback order as
// Width: console, then $LINES, then a conservative default.
func Height(w io.Writer) int {
	if file, ok := w.(*os.File); ok {
		if rows := consoleHeight(file); rows > 0 {
			return rows
		}
	}
	if rows := envLines(); rows > 0 {
		return rows
	}
	return DefaultHeight
}

func envLines() int {
	raw := strings.TrimSpace(os.Getenv("LINES"))
	if raw == "" {
		return 0
	}
	rows, err := strconv.Atoi(raw)
	if err != nil || rows < 10 || rows > 1000 {
		return 0
	}
	return rows
}
