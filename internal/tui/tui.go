package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"solitools/internal/finding"
	"solitools/internal/httpx"
	"solitools/internal/report"
	"solitools/internal/scan"
	"solitools/internal/term"
)

// Config wires the TUI to a terminal. In and Out must be real console handles:
// raw mode is a property of the device, not of a writer.
type Config struct {
	In      *os.File
	Out     *os.File
	Version string
	Theme   *term.Theme
}

type screen int

const (
	screenForm screen = iota
	screenScanning
	screenResults
)

type scanOutcome struct {
	result scan.Result
	err    error
}

type app struct {
	cfg    Config
	form   Form
	screen screen
	width  int
	height int

	baseCtx context.Context
	cancel  context.CancelFunc
	client  *httpx.Client
	stage   string
	bands   map[string]int
	mu      sync.Mutex

	started      time.Time
	lastSample   time.Time
	lastRequests int64
	rate         float64
	cancelled    bool
	done         chan scanOutcome

	result scan.Result
	runErr error
	waf    string

	view     *ResultView
	notice   string
	spinner  int
	saving   bool
	savePath string
}

// Run takes over the terminal, drives the UI and restores everything on exit.
func Run(ctx context.Context, cfg Config) error {
	if cfg.In == nil || cfg.Out == nil {
		return errors.New("tui: stdin and stdout are required")
	}
	restoreModes, err := enterRawMode(cfg.In, cfg.Out)
	if err != nil {
		return err
	}
	defer restoreModes()

	reader, err := newKeyReader(cfg.In)
	if err != nil {
		return err
	}

	// Alternate screen keeps the user's scrollback intact; the cursor is hidden
	// because every frame redraws the whole viewport.
	fmt.Fprint(cfg.Out, "\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
	defer fmt.Fprint(cfg.Out, "\x1b[?25h\x1b[?1049l")

	instance := &app{
		cfg:     cfg,
		form:    NewForm(),
		bands:   make(map[string]int),
		baseCtx: ctx,
	}

	keys := make(chan Event, 16)
	failures := make(chan error, 1)
	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				failures <- err
				return
			}
			keys <- event
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	instance.render()
	for {
		select {
		case <-ctx.Done():
			if instance.cancel != nil {
				instance.cancel()
			}
			return nil
		case event := <-keys:
			if instance.handle(event) {
				return nil
			}
			instance.render()
		case <-ticker.C:
			if instance.screen == screenScanning {
				instance.sample()
				instance.checkDone()
				instance.spinner++
				instance.render()
			}
		case err := <-failures:
			return err
		}
	}
}

// handle processes one key and reports whether the UI should close.
func (a *app) handle(event Event) bool {
	switch a.screen {
	case screenForm:
		return a.handleForm(event)
	case screenScanning:
		return a.handleScanning(event)
	default:
		return a.handleResults(event)
	}
}

func (a *app) handleForm(event Event) bool {
	switch event.Key {
	case KeyEsc:
		return true
	case KeyUp:
		a.form.MoveFocus(-1)
	case KeyDown, KeyTab:
		a.form.MoveFocus(1)
	case KeyLeft:
		if a.form.Focus == rowTarget {
			a.form.MoveCursor(-1)
		} else {
			a.form.Adjust(-1)
		}
	case KeyRight:
		if a.form.Focus == rowTarget {
			a.form.MoveCursor(1)
		} else {
			a.form.Adjust(1)
		}
	case KeySpace:
		switch a.form.Focus {
		case rowStart:
			a.startScan()
		case rowExit:
			return true
		default:
			a.form.Toggle()
		}
	case KeyEnter:
		if a.form.Focus == rowExit {
			return true
		}
		a.startScan()
	case KeyBackspace:
		if a.form.Focus == rowTarget {
			a.form.Backspace()
		} else {
			a.form.DeleteDigit()
		}
	case KeyRune:
		if a.form.Focus == rowTarget {
			a.form.Insert(event.Rune)
			return false
		}
		if event.Rune == 'q' {
			return true
		}
		if event.Rune >= '0' && event.Rune <= '9' {
			a.form.Digit(int(event.Rune - '0'))
		}
	}
	return false
}

// startScan validates the form, builds a fresh client (the rate can change
// between runs) and launches the orchestrator in a goroutine.
func (a *app) startScan() {
	target, err := NormalizeTarget(a.form.Target)
	if err != nil {
		a.notice = err.Error()
		a.form.Focus = rowTarget
		return
	}

	client, err := httpx.New(httpx.Options{Rate: float64(a.form.Rate)})
	if err != nil {
		a.notice = err.Error()
		return
	}

	scanCtx, cancel := context.WithCancel(a.baseCtx)
	a.client = client
	a.cancel = cancel
	a.started = time.Now()
	a.lastSample = a.started
	a.lastRequests = 0
	a.rate = 0
	a.bands = make(map[string]int)
	a.stage = "starting"
	a.cancelled = false
	a.result = scan.Result{}
	a.runErr = nil
	a.notice = ""
	a.waf = ""
	a.done = make(chan scanOutcome, 1)

	options := a.form.ScanOptions(client,
		func(stage string) {
			a.mu.Lock()
			a.stage = stage
			a.mu.Unlock()
		},
		func(candidate finding.Finding) {
			a.mu.Lock()
			a.bands[string(candidate.Confidence.Band)]++
			a.mu.Unlock()
		},
	)
	options.Target = target
	options.OnWAF = func(provider string) {
		a.mu.Lock()
		a.waf = provider
		a.mu.Unlock()
	}

	a.screen = screenScanning
	a.spinner = 0
	go func() {
		result, runErr := scan.Run(scanCtx, options)
		a.done <- scanOutcome{result: result, err: runErr}
	}()
}

func (a *app) handleScanning(event Event) bool {
	switch event.Key {
	case KeyEsc, KeyCtrlC:
		if a.cancel != nil {
			a.cancel()
		}
		a.cancelled = true
		a.mu.Lock()
		a.stage = "cancelling"
		a.mu.Unlock()
	case KeyRune:
		if event.Rune == 'q' {
			if a.cancel != nil {
				a.cancel()
			}
			a.cancelled = true
		}
	}
	return false
}

func (a *app) sample() {
	if a.client == nil {
		return
	}
	now := time.Now()
	requests := a.client.Requests()
	seconds := now.Sub(a.lastSample).Seconds()
	if seconds > 0 {
		a.rate = float64(requests-a.lastRequests) / seconds
	}
	a.lastRequests = requests
	a.lastSample = now
}

// checkDone moves to the explorer when the scan goroutine finishes.
func (a *app) checkDone() {
	if a.done == nil {
		return
	}
	select {
	case outcome := <-a.done:
		a.done = nil
		a.result = outcome.result
		a.runErr = outcome.err
		if outcome.result.WAF != "" {
			a.mu.Lock()
			a.waf = outcome.result.WAF
			a.mu.Unlock()
		}
		a.view = NewResultView(outcome.result, a.form.ThresholdValue(), a.form.Mask)
		a.screen = screenResults
		if a.cancelled {
			a.notice = "scan cancelled — showing what was found"
		} else if outcome.err != nil {
			a.notice = "scan error: " + outcome.err.Error()
		}
		a.render()
	default:
	}
}

func (a *app) handleResults(event Event) bool {
	if a.saving {
		return a.handleSavePrompt(event)
	}
	switch event.Key {
	case KeyEsc:
		return true
	case KeyUp:
		a.view.Move(-1)
	case KeyDown:
		a.view.Move(1)
	case KeyPageUp:
		a.view.Page(-1, a.listHeight())
	case KeyPageDown:
		a.view.Page(1, a.listHeight())
	case KeyHome:
		a.view.MoveTo(0)
	case KeyEnd:
		a.view.MoveTo(a.view.Len() - 1)
	case KeyRune:
		switch event.Rune {
		case 'q':
			return true
		case 'k':
			a.view.Move(-1)
		case 'j':
			a.view.Move(1)
		case 'm':
			if selected, ok := a.view.SelectedFinding(); ok {
				a.view.ToggleMask(selected)
			}
		case 's':
			a.saving = true
			a.savePath = "solitools-report.json"
			a.notice = ""
		}
	}
	return false
}

func (a *app) handleSavePrompt(event Event) bool {
	switch event.Key {
	case KeyEsc:
		a.saving = false
		a.notice = "save cancelled"
	case KeyEnter:
		a.saveReport()
	case KeyBackspace:
		if len(a.savePath) > 0 {
			_, size := utf8.DecodeLastRuneInString(a.savePath)
			a.savePath = a.savePath[:len(a.savePath)-size]
		}
	case KeySpace:
		a.savePath += " "
	case KeyRune:
		a.savePath += string(event.Rune)
	}
	return false
}

// saveReport writes through the existing report package so the exported file is
// byte-identical to what the CLI would produce. Secrets stay masked on disk.
func (a *app) saveReport() {
	path := strings.TrimSpace(a.savePath)
	if path == "" {
		a.notice = "a file path is required"
		return
	}
	file, err := os.Create(path)
	if err != nil {
		a.notice = "save failed: " + err.Error()
		return
	}
	defer file.Close()

	sarif := strings.HasSuffix(strings.ToLower(path), ".sarif")
	options := report.Options{
		Threshold: a.form.ThresholdValue(),
		Mask:      true,
		JSON:      !sarif,
		SARIF:     sarif,
		Elapsed:   time.Since(a.started),
		Version:   a.cfg.Version,
	}
	if _, err := report.Render(file, a.result, options); err != nil {
		a.notice = "save failed: " + err.Error()
		return
	}
	a.saving = false
	a.notice = "saved to " + path
}

func lastRune(s string) (rune, int) {
	return utf8.DecodeLastRuneInString(s)
}

// ---------------------------------------------------------------------------
// rendering

func (a *app) render() {
	a.width = term.Width(a.cfg.Out)
	a.height = term.Height(a.cfg.Out)
	if a.width < 40 {
		a.width = 40
	}
	if a.height < 12 {
		a.height = 12
	}

	var frame strings.Builder
	frame.WriteString("\x1b[H\x1b[2J")
	switch a.screen {
	case screenScanning:
		a.renderScanning(&frame)
	case screenResults:
		a.renderResults(&frame)
	default:
		a.renderForm(&frame)
	}
	fmt.Fprint(a.cfg.Out, frame.String())
}

func (a *app) title(text string) string {
	return a.cfg.Theme.Accent(text)
}

func (a *app) dim(text string) string {
	return a.cfg.Theme.Dim(text)
}

func (a *app) line(frame *strings.Builder, text string) {
	frame.WriteString(fit(text, a.width))
	frame.WriteString("\r\n")
}

func (a *app) blank(frame *strings.Builder) {
	frame.WriteString("\r\n")
}

func (a *app) renderForm(frame *strings.Builder) {
	a.line(frame, a.title("SoliTools "+a.cfg.Version)+a.dim(" — configure scan"))
	a.blank(frame)

	a.formRow(frame, rowTarget, "Target URL: "+a.targetField())
	a.blank(frame)
	a.formRow(frame, rowCrawl, checkbox(a.form.Crawl)+" Crawl same-origin pages "+a.dim("(-crawl)"))
	a.formRow(frame, rowForms, checkbox(a.form.Forms)+" Probe POST form parameters "+a.dim("(-forms)"))
	a.formRow(frame, rowStored, checkbox(a.form.Stored)+" Detect stored/blind reflection "+a.dim("(-stored)"))
	a.formRow(frame, rowVerify, checkbox(a.form.Verify)+" Verify credentials with providers "+a.dim("(-verify)"))
	a.formRow(frame, rowSkipPath, checkbox(a.form.SkipPath)+" Skip sensitive path scan "+a.dim("(-skip-path)"))
	a.formRow(frame, rowMask, checkbox(a.form.Mask)+" Mask secrets in output "+a.dim("(-mask)"))
	a.blank(frame)

	a.line(frame, a.dim("Confidence threshold"))
	a.formRow(frame, rowThresholdDefault, radio(a.form.Threshold == 0)+" Default (>= 60)")
	a.formRow(frame, rowThresholdStrict, radio(a.form.Threshold == 1)+" Strict (>= 75)")
	a.formRow(frame, rowThresholdAll, radio(a.form.Threshold == 2)+" All (>= 0)")
	a.blank(frame)

	a.formRow(frame, rowRate, fmt.Sprintf("Rate limit (req/s): %d", a.form.Rate))
	a.formRow(frame, rowMaxPages, fmt.Sprintf("Max pages (crawl): %d", a.form.MaxPages))
	a.blank(frame)

	a.formRow(frame, rowStart, "[ Start Scan ]")
	a.formRow(frame, rowExit, "[ Exit ]")
	a.blank(frame)

	if a.notice != "" {
		a.line(frame, a.cfg.Theme.Color("warning", a.notice))
	}
	a.line(frame, a.dim("↑/↓ move   space toggle   ←/→ adjust   enter start   esc exit"))
}

// formRow prefixes the focused row with a marker so focus is unambiguous even
// without color.
func (a *app) formRow(frame *strings.Builder, row int, text string) {
	marker := "  "
	if a.form.Focus == row {
		marker = "> "
	}
	a.line(frame, marker+text)
}

func (a *app) targetField() string {
	cursor := a.form.Cursor
	if cursor > len(a.form.Target) {
		cursor = len(a.form.Target)
	}
	if a.form.Focus == rowTarget {
		return a.form.Target[:cursor] + "|" + a.form.Target[cursor:]
	}
	return a.form.Target
}

func checkbox(checked bool) string {
	if checked {
		return "[x]"
	}
	return "[ ]"
}

func radio(selected bool) string {
	if selected {
		return "(•)"
	}
	return "( )"
}

func (a *app) wafName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.waf
}

// scanHeader is the title line shared by the monitor, with a WAF badge once a
// provider is known.
func (a *app) scanHeader(stage string) string {
	header := a.title("SoliTools "+a.cfg.Version) + a.dim(" — "+stage)
	if name := a.wafName(); name != "" {
		header += "   " + a.cfg.Theme.Color("warning", "[WAF: "+name+"]")
	}
	return header
}

func (a *app) renderScanning(frame *strings.Builder) {
	spin := []string{"|", "/", "-", "\\"}[a.spinner%4]

	a.line(frame, a.scanHeader("scanning"))
	a.blank(frame)
	a.line(frame, "Target: "+a.form.Target)
	a.blank(frame)
	a.mu.Lock()
	stage := a.stage
	bands := make(map[string]int, len(a.bands))
	for band, count := range a.bands {
		bands[band] = count
	}
	a.mu.Unlock()

	a.line(frame, fmt.Sprintf("%s  %s", spin, stage))
	a.blank(frame)
	a.line(frame, fmt.Sprintf("Elapsed: %s   Requests: %d   Rate: %.1f req/s",
		time.Since(a.started).Round(time.Second), a.lastRequests, a.rate))
	a.line(frame, fmt.Sprintf("Findings: critical %d · high %d · medium-high %d · low %d",
		bands["critical"], bands["high"], bands["medium-high"], bands["low"]+bands["medium"]))
	a.blank(frame)
	a.line(frame, a.dim("esc / ctrl+c cancels the scan and keeps the results"))
}

func (a *app) listHeight() int {
	height := a.height - 9
	if height < 3 {
		height = 3
	}
	return height
}

func (a *app) renderResults(frame *strings.Builder) {
	if a.view == nil {
		a.line(frame, "No results.")
		return
	}
	header := fmt.Sprintf("%s %s", a.title("SoliTools "+a.cfg.Version),
		a.dim(fmt.Sprintf("— findings %d/%d at threshold %.0f", a.view.Len(), len(a.result.Findings), a.view.Threshold)))
	if name := a.wafName(); name != "" {
		header += "   " + a.cfg.Theme.Color("warning", "[WAF: "+name+"]")
	}
	a.line(frame, header)
	a.blank(frame)

	height := a.listHeight()
	for index, candidate := range a.view.Visible(height) {
		absolute := a.view.Offset + index
		marker := "  "
		if absolute == a.view.Selected {
			marker = "> "
		}
		badge := fmt.Sprintf("[%s]", strings.ToUpper(string(candidate.Confidence.Band)))
		if a.cfg.Theme.Enabled() {
			badge = a.cfg.Theme.Color(term.BandColor(string(candidate.Confidence.Band)), badge)
		}
		kind := fmt.Sprintf("[%s]", candidate.Kind)
		if a.cfg.Theme.Enabled() {
			kind = a.cfg.Theme.Color(term.KindColor(string(candidate.Kind)), kind)
		}
		text := fmt.Sprintf("%s%s %s %s  %s", marker, badge, kind, candidate.Title, shortPath(candidate.URL, a.width/3))
		if absolute == a.view.Selected && a.cfg.Theme.Enabled() {
			text = "\x1b[7m" + fit(text, a.width) + "\x1b[0m"
		}
		a.line(frame, text)
	}
	if a.view.Len() == 0 {
		a.line(frame, a.dim("Nothing clears this threshold. Press q to quit."))
	}

	a.blank(frame)
	a.renderDetail(frame)

	if a.saving {
		a.line(frame, a.cfg.Theme.Color("warning", "Save report to: ")+a.savePath+"|")
		a.line(frame, a.dim("enter save   esc cancel   .json or .sarif picks the format"))
		return
	}
	if a.notice != "" {
		a.line(frame, a.cfg.Theme.Color("warning", a.notice))
	}
	a.line(frame, a.dim("↑/↓ j/k scroll   pgup/pgdn page   m mask   s save   q quit"))
}

func (a *app) renderDetail(frame *strings.Builder) {
	selected, ok := a.view.SelectedFinding()
	if !ok {
		return
	}
	a.line(frame, fmt.Sprintf("%s %s", selected.Title, a.dim("— "+string(selected.Kind))))
	if name := a.wafName(); name != "" {
		a.line(frame, "WAF: "+name)
	}
	a.line(frame, "URL: "+selected.URL)
	if parameter := fieldValue(selected, "Parameter"); parameter != "" {
		method := fieldValue(selected, "Method")
		if method == "" {
			method = "GET"
		}
		a.line(frame, fmt.Sprintf("Parameter: %s (%s)", parameter, method))
	}
	a.line(frame, "Rule: "+selected.RuleID+"   Category: "+selected.Category)

	value := a.view.DisplayValue(selected)
	label := ""
	if selected.Kind == finding.KindSecret {
		label = " [" + a.view.MaskLabel(selected) + "]"
	}
	a.line(frame, "Value: "+value+label)

	context := a.view.DisplayContext(selected)
	for _, wrapped := range wrapText(context, a.width-8) {
		a.line(frame, "  "+wrapped)
	}

	signals := selected.Confidence.Signals
	a.line(frame, fmt.Sprintf("Score: %.1f (%s)   base %.1f", selected.Confidence.Value, selected.Confidence.Band, selected.Confidence.Base))
	for _, signal := range signals {
		a.line(frame, fmt.Sprintf("  %+.1f %s — %s", signal.Delta, signal.Name, signal.Reason))
	}
	for _, field := range selected.Fields {
		switch field.Name {
		case "Parameter", "Method", "Reflection Point", "Payload", "Status", "Storage",
			"Path", "Size", "Entropy", "Line", "Occurrences", "Method ":
			a.line(frame, "  "+field.Name+": "+field.Value)
		}
	}
}

func fieldValue(candidate finding.Finding, name string) string {
	for _, field := range candidate.Fields {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

// shortPath keeps the end of a URL, which is the part that identifies a page.
func shortPath(rawURL string, limit int) string {
	if limit < 8 {
		limit = 8
	}
	runes := []rune(rawURL)
	if len(runes) <= limit {
		return rawURL
	}
	return "..." + string(runes[len(runes)-limit+3:])
}

// fit truncates to width visible columns. ANSI escape sequences are copied
// without counting, so colour codes are never cut in half and the closing reset
// survives.
func fit(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleLen(text) <= width {
		return text
	}

	var out strings.Builder
	count := 0
	sawEscape := false
	for index := 0; index < len(text) && count < width-1; {
		if text[index] == 0x1b {
			end := index + 1
			if end < len(text) && text[end] == '[' {
				end++
				for end < len(text) && (text[end] < 0x40 || text[end] > 0x7e) {
					end++
				}
				if end < len(text) {
					end++
				}
			}
			out.WriteString(text[index:end])
			sawEscape = true
			index = end
			continue
		}
		r, size := utf8.DecodeRuneInString(text[index:])
		out.WriteRune(r)
		count++
		index += size
	}
	out.WriteString("~")
	if sawEscape {
		out.WriteString("\x1b[0m")
	}
	return out.String()
}

// visibleLen counts printable runes, ignoring CSI sequences.
func visibleLen(text string) int {
	count := 0
	for index := 0; index < len(text); {
		switch text[index] {
		case 0x1b:
			index++
			if index < len(text) && text[index] == '[' {
				index++
				for index < len(text) && (text[index] < 0x40 || text[index] > 0x7e) {
					index++
				}
				if index < len(text) {
					index++
				}
			}
		default:
			_, size := utf8.DecodeRuneInString(text[index:])
			count++
			index += size
		}
	}
	return count
}

// wrapText splits on spaces into lines of at most width runes.
func wrapText(text string, width int) []string {
	if width < 10 {
		width = 10
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, len(words)/8+1)
	current := ""
	for _, word := range words {
		if current == "" {
			current = word
			continue
		}
		if len([]rune(current))+1+len([]rune(word)) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
