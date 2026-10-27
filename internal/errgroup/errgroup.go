// Package errgroup provides the subset of golang.org/x/sync/errgroup that
// SoliTools uses.
//
// It exists so the tool has no external module dependencies and always builds
// offline. Semantics match the upstream package: the first non-nil error
// cancels the derived context and is returned by Wait.
package errgroup

import (
	"context"
	"sync"
)

// Group runs functions concurrently and collects the first error.
type Group struct {
	cancel func()
	ctx    context.Context
	wg     sync.WaitGroup
	sem    chan struct{}
	once   sync.Once
	err    error
}

// WithContext returns a Group and its derived context.
func WithContext(ctx context.Context) (*Group, context.Context) {
	derived, cancel := context.WithCancel(ctx)
	return &Group{cancel: cancel, ctx: derived}, derived
}

// SetLimit bounds how many functions run at once. n <= 0 means unlimited.
func (g *Group) SetLimit(n int) {
	if n <= 0 {
		g.sem = nil
		return
	}
	g.sem = make(chan struct{}, n)
}

// Go runs f in a new goroutine.
func (g *Group) Go(f func() error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()

		if g.sem != nil {
			select {
			case g.sem <- struct{}{}:
				defer func() { <-g.sem }()
			case <-g.ctx.Done():
				return
			}
		}

		if err := f(); err != nil {
			g.once.Do(func() {
				g.err = err
				if g.cancel != nil {
					g.cancel()
				}
			})
		}
	}()
}

// Wait blocks until every function has returned and reports the first error.
func (g *Group) Wait() error {
	g.wg.Wait()
	if g.cancel != nil {
		g.cancel()
	}
	return g.err
}
