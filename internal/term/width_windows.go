//go:build windows

package term

import (
	"os"
	"syscall"
	"unsafe"
)

type coordinate struct {
	x int16
	y int16
}

type smallRect struct {
	left   int16
	top    int16
	right  int16
	bottom int16
}

type consoleScreenBufferInfo struct {
	size              coordinate
	cursorPosition    coordinate
	attributes        uint16
	window            smallRect
	maximumWindowSize coordinate
}

// consoleWidth asks the Windows console for its visible window width.
func consoleWidth(f *os.File) int {
	var info consoleScreenBufferInfo
	result, _, _ := procGetConsoleScreenBufferInfo.Call(
		uintptr(syscall.Handle(f.Fd())),
		uintptr(unsafe.Pointer(&info)),
	)
	if result == 0 {
		return 0
	}
	columns := int(info.window.right-info.window.left) + 1
	if columns < 0 {
		return 0
	}
	return columns
}
