// Package progress renders a single-line live status while a scan runs.
//
// It animates only when the destination is an interactive terminal; with piped
// or redirected output it stays completely silent so the report remains
// machine-readable and free of carriage returns.
package progress

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/soliofski/SoliTools/internal/httpx"
	"github.com/soliofski/SoliTools/internal/term"
)

// spinner frames, in braille so the movement is smooth in any monospace font.
var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	frameInterval = 90 * time.Millisecond
	clearLine     = "\x1b[2K\r"
	labelWidth    = 18
)

// Status is a live, single-line progress indicator. A nil Status is valid.
type Status struct {
	out    io.Writer
	theme  *term.Theme
	client *httpx.Client

	mu    sync.Mutex
	stage string
	live  bool
	start time.Time

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// New builds a Status that reports request counts from client.
func New(out io.Writer, theme *term.Theme, client *httpx.Client) *Status {
	return &Status{
		out:    out,
		theme:  theme,
		client: client,
		stage:  "starting",
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start begins rendering. It is a no-op unless the destination is a real
// terminal and styling is on: an animated line written to a pipe or file would
// leave carriage returns in the output.
func (s *Status) Start() {
	if s == nil || s.out == nil || !s.theme.Enabled() || !term.IsTerminal(s.out) {
		return
	}
	s.mu.Lock()
	if s.live {
		s.mu.Unlock()
		return
	}
	s.live = true
	s.start = time.Now()
	s.mu.Unlock()

	go s.run()
}

// Stage sets the label shown next to the spinner. Safe to call from any
// goroutine, including before Start.
func (s *Status) Stage(stage string) {
	if s == nil || stage == "" {
		return
	}
	s.mu.Lock()
	s.stage = stage
	s.mu.Unlock()
}

// Stop halts rendering and clears the status line. It is idempotent.
func (s *Status) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		s.mu.Lock()
		live := s.live
		s.mu.Unlock()
		if !live {
			return
		}
		close(s.stop)
		<-s.done
	})
}

func (s *Status) run() {
	defer close(s.done)

	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()

	for frame := 0; ; frame++ {
		select {
		case <-s.stop:
			fmt.Fprint(s.out, clearLine)
			return
		case <-ticker.C:
			s.render(frame)
		}
	}
}

func (s *Status) render(frame int) {
	s.mu.Lock()
	stage := s.stage
	start := s.start
	s.mu.Unlock()

	requests := 0
	if s.client != nil {
		requests = int(s.client.Requests())
	}

	line := fmt.Sprintf("%s %s  %s",
		s.theme.Accent(spinner[frame%len(spinner)]),
		s.theme.Bold(pad(stage, labelWidth)),
		s.theme.Dim(fmt.Sprintf("%d requests · %s", requests, time.Since(start).Round(100*time.Millisecond))),
	)
	fmt.Fprint(s.out, clearLine+line)
}

// pad right-pads s to width runes so the counter does not jitter as the stage
// label changes.
func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + spaces(width-len(s))
}

func spaces(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	return string(out)
}
