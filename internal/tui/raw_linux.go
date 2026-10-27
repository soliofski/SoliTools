//go:build linux

package tui

import (
	"os"
	"syscall"
	"unsafe"
)

// enterRawMode switches the terminal to non-canonical, no-echo input. Ctrl+C is
// delivered as a byte instead of a signal so the UI can cancel gracefully.
func enterRawMode(in, _ *os.File) (func(), error) {
	fd := in.Fd()

	var original syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&original)), 0, 0, 0); errno != 0 {
		return nil, errno
	}

	raw := original
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return nil, errno
	}

	restore := func() {
		syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&original)), 0, 0, 0)
	}
	return restore, nil
}
