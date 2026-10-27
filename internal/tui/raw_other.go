//go:build !windows && !linux && !darwin

package tui

import (
	"errors"
	"os"
)

func enterRawMode(*os.File, *os.File) (func(), error) {
	return nil, errors.New("tui: interactive mode is not supported on this platform")
}
