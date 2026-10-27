package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"solitools/internal/term"
)

func TestRenderDrawsStatusLine(t *testing.T) {
	var buf bytes.Buffer
	status := New(&buf, term.New(&buf, term.ModeAlways), nil)
	status.mu.Lock()
	status.stage = "probing parameters"
	status.start = time.Now()
	status.live = true
	status.mu.Unlock()

	status.render(0)

	out := buf.String()
	if !strings.HasPrefix(out, clearLine) {
		t.Fatalf("status does not start with a clear-line: %q", out)
	}
	if !strings.Contains(out, "probing parameters") {
		t.Fatalf("status missing the stage: %q", out)
	}
	if !strings.Contains(out, "0 requests") {
		t.Fatalf("status missing the request counter: %q", out)
	}
	if !strings.Contains(out, spinner[0]) {
		t.Fatalf("status missing the spinner frame: %q", out)
	}
}

func TestStagePadsToFixedWidth(t *testing.T) {
	var buf bytes.Buffer
	status := New(&buf, term.New(&buf, term.ModeAlways), nil)
	status.mu.Lock()
	status.stage = "short"
	status.start = time.Now()
	status.live = true
	status.mu.Unlock()

	status.render(0)
	if !strings.Contains(buf.String(), "short             ") {
		t.Fatalf("stage was not padded: %q", buf.String())
	}
}

func TestStopWithoutStartIsSilent(t *testing.T) {
	var buf bytes.Buffer
	status := New(&buf, term.New(&buf, term.ModeAlways), nil)
	status.Stop()
	if buf.Len() != 0 {
		t.Fatalf("Stop wrote %q before Start", buf.String())
	}
}

func TestStartWithoutTerminalStaysSilent(t *testing.T) {
	var buf bytes.Buffer
	status := New(&buf, term.New(&buf, term.ModeAlways), nil)
	status.Start() // a buffer is not a terminal
	time.Sleep(150 * time.Millisecond)
	status.Stop()
	if buf.Len() != 0 {
		t.Fatalf("animation ran without a terminal: %q", buf.String())
	}
}

func TestStageIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	status := New(&buf, term.New(&buf, term.ModeAlways), nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			status.Stage("stage")
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		status.Stage("other")
	}
	<-done
}

func TestNilStatusIsSafe(t *testing.T) {
	var status *Status
	status.Start()
	status.Stage("x")
	status.Stop()
}
