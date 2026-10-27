//go:build windows

package tui

import (
	"os"
	"syscall"
	"unsafe"
)

const keyEventType = 0x0001

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procReadConsoleInputW = kernel32.NewProc("ReadConsoleInputW")
)

// inputRecord mirrors INPUT_RECORD: a type tag followed by a 16-byte union.
type inputRecord struct {
	eventType uint16
	_         uint16
	event     [16]byte
}

// keyEventRecord mirrors KEY_EVENT_RECORD, the union member we care about.
type keyEventRecord struct {
	keyDown        int32
	repeatCount    uint16
	virtualKeyCode uint16
	virtualScan    uint16
	unicodeChar    uint16
	controlState   uint32
}

type consoleKeys struct {
	handle syscall.Handle
}

func newKeyReader(in *os.File) (keyReader, error) {
	return &consoleKeys{handle: syscall.Handle(in.Fd())}, nil
}

// Read blocks for one key event, skipping mouse and resize records. Using
// console records instead of the raw byte stream is what gives arrow keys and
// Ctrl+C a stable representation on Windows.
func (c *consoleKeys) Read() (Event, error) {
	for {
		var record inputRecord
		var read uint32
		ok, _, err := procReadConsoleInputW.Call(
			uintptr(c.handle),
			uintptr(unsafe.Pointer(&record)),
			1,
			uintptr(unsafe.Pointer(&read)),
		)
		if ok == 0 {
			return Event{}, err
		}
		if read == 0 || record.eventType != keyEventType {
			continue
		}
		key := (*keyEventRecord)(unsafe.Pointer(&record.event[0]))
		if key.keyDown == 0 {
			continue
		}
		if event, ok := eventFromVirtualKey(key.virtualKeyCode, rune(key.unicodeChar)); ok {
			return event, nil
		}
	}
}
