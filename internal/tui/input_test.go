package tui

import "testing"

func TestDecodeVTArrowKeys(t *testing.T) {
	cases := map[string]Key{
		"\x1b[A":  KeyUp,
		"\x1b[B":  KeyDown,
		"\x1b[C":  KeyRight,
		"\x1b[D":  KeyLeft,
		"\x1bOA":  KeyUp,
		"\x1bOB":  KeyDown,
		"\x1b[H":  KeyHome,
		"\x1b[F":  KeyEnd,
		"\x1b[1~": KeyHome,
		"\x1b[4~": KeyEnd,
		"\x1b[5~": KeyPageUp,
		"\x1b[6~": KeyPageDown,
	}
	for sequence, want := range cases {
		events := decodeVT([]byte(sequence))
		if len(events) != 1 || events[0].Key != want {
			t.Errorf("decodeVT(%q) = %+v, want %v", sequence, events, want)
		}
	}
}

func TestDecodeControlCharacters(t *testing.T) {
	cases := map[string]Key{
		"\r":   KeyEnter,
		"\n":   KeyEnter,
		" ":    KeySpace,
		"\t":   KeyTab,
		"\x7f": KeyBackspace,
		"\x08": KeyBackspace,
		"\x03": KeyCtrlC,
		"\x1b": KeyEsc,
	}
	for input, want := range cases {
		events := decodeVT([]byte(input))
		if len(events) != 1 || events[0].Key != want {
			t.Errorf("decodeVT(%q) = %+v, want %v", input, events, want)
		}
	}
}

func TestDecodePrintableRunes(t *testing.T) {
	events := decodeVT([]byte("aé日"))
	if len(events) != 3 {
		t.Fatalf("events = %+v, want three runes", events)
	}
	for index, want := range []rune{'a', 'é', '日'} {
		if events[index].Key != KeyRune || events[index].Rune != want {
			t.Errorf("event %d = %+v, want rune %q", index, events[index], want)
		}
	}
}

func TestDecodeStreamCombinesKeys(t *testing.T) {
	events := decodeVT([]byte("\x1b[B\x1b[A\r"))
	want := []Key{KeyDown, KeyUp, KeyEnter}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for index := range want {
		if events[index].Key != want[index] {
			t.Errorf("event %d = %v, want %v", index, events[index].Key, want[index])
		}
	}
}

func TestDecodeUnknownSequence(t *testing.T) {
	events := decodeVT([]byte("\x1b[99X"))
	if len(events) != 1 || events[0].Key != KeyUnknown {
		t.Fatalf("events = %+v, want one unknown event", events)
	}
}

func TestEventFromVirtualKey(t *testing.T) {
	cases := []struct {
		vk   uint16
		char rune
		want Key
		ok   bool
	}{
		{vkUp, 0, KeyUp, true},
		{vkDown, 0, KeyDown, true},
		{vkLeft, 0, KeyLeft, true},
		{vkRight, 0, KeyRight, true},
		{vkPageUp, 0, KeyPageUp, true},
		{vkPageDown, 0, KeyPageDown, true},
		{vkHome, 0, KeyHome, true},
		{vkEnd, 0, KeyEnd, true},
		{vkReturn, '\r', KeyEnter, true},
		{vkEscape, 0, KeyEsc, true},
		{vkBack, 0, KeyBackspace, true},
		{vkTab, '\t', KeyTab, true},
		{vkSpace, ' ', KeySpace, true},
		{vkKeyC, 0x03, KeyCtrlC, true},
		{0x41, 'a', KeyRune, true},
		{0x00, 0, 0, false},
	}
	for _, c := range cases {
		event, ok := eventFromVirtualKey(c.vk, c.char)
		if ok != c.ok {
			t.Errorf("vk %#x char %q: ok = %v, want %v", c.vk, c.char, ok, c.ok)
			continue
		}
		if ok && event.Key != c.want {
			t.Errorf("vk %#x: key = %v, want %v", c.vk, event.Key, c.want)
		}
	}
}
