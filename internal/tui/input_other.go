//go:build !windows && !linux && !darwin

package tui

import (
	"errors"
	"os"
)

func newKeyReader(*os.File) (keyReader, error) {
	return nil, errors.New("tui: interactive input is not supported on this platform")
}
