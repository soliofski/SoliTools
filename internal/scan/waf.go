package scan

import (
	"fmt"
	"sync"

	"github.com/soliofski/SoliTools/internal/httpx"
	"github.com/soliofski/SoliTools/internal/waf"
)

// blockWatcher counts consecutive blocked probe responses.
//
// The observer fires from concurrent requests, so "consecutive" means
// completion order: three blocks in a row with no application response in
// between. That is enough to tell a target that is dropping probes from one
// that happens to return a block page occasionally, and it keeps the watcher
// independent of module signatures.
type blockWatcher struct {
	mu       sync.Mutex
	streak   int
	blocked  bool
	provider waf.Provider
}

// observe is installed on httpx.Client only for the probing stage.
func (w *blockWatcher) observe(response *httpx.Response) {
	if response == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if !waf.IsBlockPage(response) {
		w.streak = 0
		return
	}
	w.streak++
	if provider, ok := waf.Detect(response); ok {
		w.provider = provider
	} else {
		w.provider = waf.ProviderGenericBlock
	}
	if w.streak >= 3 {
		w.blocked = true
	}
}

// interception reports the provider once a run of three blocks was seen.
func (w *blockWatcher) interception() (waf.Provider, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.blocked {
		return "", false
	}
	provider := w.provider
	if provider == "" {
		provider = waf.ProviderGenericBlock
	}
	return provider, true
}

// interceptionWarning is the exact message the report and TUI surface.
func interceptionWarning(provider waf.Provider) string {
	return fmt.Sprintf("WAF Interception: Target actively blocked probes (%s). Findings may be suppressed or incomplete.", provider)
}
