package term

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultWidth is used when the terminal size cannot be determined.
const DefaultWidth = 100

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
