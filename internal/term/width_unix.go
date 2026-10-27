//go:build linux || darwin || freebsd || netbsd || openbsd

package term

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type winsize struct {
	rows    uint16
	columns uint16
	xpixel  uint16
	ypixel  uint16
}

// consoleWidth asks the terminal for its width via TIOCGWINSZ.
//
// The ioctl request number differs between Linux and the BSD family; an
// unsupported platform simply reports 0 and the caller falls back.
func consoleWidth(f *os.File) int {
	size := winsizeFor(f)
	if size == nil {
		return 0
	}
	return int(size.columns)
}

// consoleHeight reads the same TIOCGWINSZ answer for the row count.
func consoleHeight(f *os.File) int {
	size := winsizeFor(f)
	if size == nil {
		return 0
	}
	return int(size.rows)
}

func winsizeFor(f *os.File) *winsize {
	size := &winsize{}
	request := uintptr(0x5413) // Linux TIOCGWINSZ
	if runtime.GOOS != "linux" {
		request = 0x40087468 // BSD and macOS TIOCGWINSZ
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, uintptr(unsafe.Pointer(size)))
	if errno != 0 {
		return nil
	}
	return size
}
