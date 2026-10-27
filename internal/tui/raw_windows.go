//go:build windows

package tui

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	enableProcessedInput       = 0x0001
	enableLineInput            = 0x0002
	enableEchoInput            = 0x0004
	enableVTProcessing         = 0x0004
	enableVirtualTerminalInput = 0x0200
)

var (
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enterRawMode disables line buffering, echo and Ctrl+C processing, and turns
// on VT processing for output so ANSI frames are interpreted. The returned
// function restores the original modes and is safe to call once.
func enterRawMode(in, out *os.File) (func(), error) {
	inHandle := syscall.Handle(in.Fd())
	outHandle := syscall.Handle(out.Fd())

	var inMode, outMode uint32
	if result, _, _ := procGetConsoleMode.Call(uintptr(inHandle), uintptr(unsafe.Pointer(&inMode))); result == 0 {
		return nil, errors.New("tui: standard input is not a console")
	}
	if result, _, _ := procGetConsoleMode.Call(uintptr(outHandle), uintptr(unsafe.Pointer(&outMode))); result == 0 {
		return nil, errors.New("tui: standard output is not a console")
	}

	rawInput := inMode&^(enableLineInput|enableEchoInput|enableProcessedInput) | enableVirtualTerminalInput
	if result, _, _ := procSetConsoleMode.Call(uintptr(inHandle), uintptr(rawInput)); result == 0 {
		return nil, errors.New("tui: could not switch the console to raw input")
	}
	if result, _, _ := procSetConsoleMode.Call(uintptr(outHandle), uintptr(outMode|enableVTProcessing)); result == 0 {
		procSetConsoleMode.Call(uintptr(inHandle), uintptr(inMode))
		return nil, errors.New("tui: could not enable virtual terminal processing")
	}

	restore := func() {
		procSetConsoleMode.Call(uintptr(inHandle), uintptr(inMode))
		procSetConsoleMode.Call(uintptr(outHandle), uintptr(outMode))
	}
	return restore, nil
}
