package tui

import (
	"unicode/utf8"
)

// Key is a decoded key press.
type Key int

const (
	// KeyUnknown is an escape sequence this decoder does not recognise.
	KeyUnknown Key = iota
	KeyRune
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyEnter
	KeyEsc
	KeyTab
	KeySpace
	KeyBackspace
	KeyCtrlC
	KeyPageUp
	KeyPageDown
	KeyHome
	KeyEnd
)

// Event is one key press. Rune is only meaningful for KeyRune.
type Event struct {
	Key  Key
	Rune rune
}

// keyReader is the platform-specific source of events.
type keyReader interface {
	Read() (Event, error)
}

// eventFromRune maps a decoded character to a control event, falling back to a
// printable rune.
func eventFromRune(r rune) Event {
	switch r {
	case '\r', '\n':
		return Event{Key: KeyEnter}
	case 0x03:
		return Event{Key: KeyCtrlC}
	case 0x7f, 0x08:
		return Event{Key: KeyBackspace}
	case '\t':
		return Event{Key: KeyTab}
	case ' ':
		return Event{Key: KeySpace}
	}
	return Event{Key: KeyRune, Rune: r}
}

// decodeVT turns a complete chunk of terminal bytes into events. It is pure, so
// the awkward parts — multi-byte keys and escape sequences — are testable
// without a console.
func decodeVT(data []byte) []Event {
	events := make([]Event, 0, len(data))
	for index := 0; index < len(data); {
		if data[index] == 0x1b {
			event, size := decodeEscape(data[index:])
			events = append(events, event)
			index += size
			continue
		}
		r, size := utf8.DecodeRune(data[index:])
		if r == utf8.RuneError && size <= 1 {
			index++
			continue
		}
		events = append(events, eventFromRune(r))
		index += size
	}
	return events
}

// decodeEscape parses one escape sequence and reports how many bytes it used.
func decodeEscape(data []byte) (Event, int) {
	if len(data) < 2 {
		return Event{Key: KeyEsc}, 1
	}
	switch data[1] {
	case '[':
		return decodeCSI(data)
	case 'O':
		// SS3 sequences are used in application cursor mode.
		if len(data) < 3 {
			return Event{Key: KeyEsc}, len(data)
		}
		switch data[2] {
		case 'A':
			return Event{Key: KeyUp}, 3
		case 'B':
			return Event{Key: KeyDown}, 3
		case 'C':
			return Event{Key: KeyRight}, 3
		case 'D':
			return Event{Key: KeyLeft}, 3
		case 'H':
			return Event{Key: KeyHome}, 3
		case 'F':
			return Event{Key: KeyEnd}, 3
		}
		return Event{Key: KeyUnknown}, 3
	}
	return Event{Key: KeyEsc}, 1
}

// decodeCSI parses "ESC [ parameters final".
func decodeCSI(data []byte) (Event, int) {
	for index := 2; index < len(data); index++ {
		b := data[index]
		if b < 0x40 || b > 0x7e {
			continue // still in the parameter bytes
		}
		params := string(data[2:index])
		switch b {
		case 'A':
			return Event{Key: KeyUp}, index + 1
		case 'B':
			return Event{Key: KeyDown}, index + 1
		case 'C':
			return Event{Key: KeyRight}, index + 1
		case 'D':
			return Event{Key: KeyLeft}, index + 1
		case 'H':
			return Event{Key: KeyHome}, index + 1
		case 'F':
			return Event{Key: KeyEnd}, index + 1
		case 'Z':
			return Event{Key: KeyTab}, index + 1 // shift-tab: treated as tab
		case '~':
			switch params {
			case "5":
				return Event{Key: KeyPageUp}, index + 1
			case "6":
				return Event{Key: KeyPageDown}, index + 1
			case "1", "7":
				return Event{Key: KeyHome}, index + 1
			case "4", "8":
				return Event{Key: KeyEnd}, index + 1
			}
			return Event{Key: KeyUnknown}, index + 1
		}
	}
	return Event{Key: KeyUnknown}, len(data)
}

// Windows virtual-key codes, kept here so the mapping is testable on every
// platform even though only the Windows reader produces them.
const (
	vkBack     = 0x08
	vkTab      = 0x09
	vkReturn   = 0x0D
	vkEscape   = 0x1B
	vkSpace    = 0x20
	vkPageUp   = 0x21
	vkPageDown = 0x22
	vkEnd      = 0x23
	vkHome     = 0x24
	vkLeft     = 0x25
	vkUp       = 0x26
	vkRight    = 0x27
	vkDown     = 0x28
	vkKeyC     = 0x43
)

// eventFromVirtualKey maps a Windows KEY_EVENT_RECORD to an Event.
func eventFromVirtualKey(vk uint16, char rune) (Event, bool) {
	switch vk {
	case vkUp:
		return Event{Key: KeyUp}, true
	case vkDown:
		return Event{Key: KeyDown}, true
	case vkLeft:
		return Event{Key: KeyLeft}, true
	case vkRight:
		return Event{Key: KeyRight}, true
	case vkPageUp:
		return Event{Key: KeyPageUp}, true
	case vkPageDown:
		return Event{Key: KeyPageDown}, true
	case vkHome:
		return Event{Key: KeyHome}, true
	case vkEnd:
		return Event{Key: KeyEnd}, true
	case vkReturn:
		return Event{Key: KeyEnter}, true
	case vkEscape:
		return Event{Key: KeyEsc}, true
	case vkBack:
		return Event{Key: KeyBackspace}, true
	case vkTab:
		return Event{Key: KeyTab}, true
	case vkSpace:
		return Event{Key: KeySpace}, true
	case vkKeyC:
		if char == 0x03 {
			return Event{Key: KeyCtrlC}, true
		}
	}
	if char == 0x03 {
		return Event{Key: KeyCtrlC}, true
	}
	if char >= 0x20 && char != 0x7f {
		return Event{Key: KeyRune, Rune: char}, true
	}
	return Event{}, false
}
