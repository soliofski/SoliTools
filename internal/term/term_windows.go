//go:build windows

package term

import (
	"os"
	"syscall"
	"unsafe"
)

const enableVirtualTerminalProcessing = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enableVirtualTerminal switches the Windows console into VT mode so ANSI
// escape sequences are interpreted instead of printed literally.
//
// It reports false when the handle is not a console or the mode cannot be
// changed, which makes the caller fall back to plain text.
func enableVirtualTerminal(f *os.File) bool {
	handle := syscall.Handle(f.Fd())

	var mode uint32
	if result, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode))); result == 0 {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	result, _, _ := procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	return result != 0
}
