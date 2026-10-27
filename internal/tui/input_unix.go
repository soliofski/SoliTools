//go:build linux || darwin

package tui

import (
	"bufio"
	"os"
	"time"
)

// escapeGrace is how long a lone ESC waits for the rest of a sequence. Real
// terminals deliver a sequence in one burst; five milliseconds is generous for
// a local pty and too short to make a human's ESC feel laggy.
const escapeGrace = 5 * time.Millisecond

type byteKeys struct {
	reader *bufio.Reader
}

func newKeyReader(in *os.File) (keyReader, error) {
	return &byteKeys{reader: bufio.NewReader(in)}, nil
}

func (b *byteKeys) Read() (Event, error) {
	first, _, err := b.reader.ReadRune()
	if err != nil {
		return Event{}, err
	}
	if first != 0x1b {
		return eventFromRune(first), nil
	}

	sequence := []byte{0x1b}
	time.Sleep(escapeGrace)
	for len(sequence) < 8 && b.reader.Buffered() > 0 {
		next, err := b.reader.ReadByte()
		if err != nil {
			break
		}
		sequence = append(sequence, next)
		// A CSI sequence ends at the first byte in 0x40..0x7e after "ESC [".
		if len(sequence) >= 3 && sequence[1] == '[' && next >= 0x40 && next <= 0x7e {
			break
		}
	}

	events := decodeVT(sequence)
	if len(events) == 0 {
		return Event{Key: KeyEsc}, nil
	}
	return events[0], nil
}
