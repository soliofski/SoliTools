// Package httpx is SoliTools' HTTP client.
//
// It enforces one invariant that matters for accuracy: every request passes
// through a global token bucket, so the tool is polite by default and no module
// can accidentally flood a target. Redirects are never followed implicitly —
// the redirect module needs the raw 30x response, and following one silently
// would turn a detection into a request to a third party.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options.
const (
	DefaultRate      = 10.0
	DefaultTimeout   = 15 * time.Second
	DefaultMaxBody   = 3 << 20
	DefaultUserAgent = "SoliTools/0.2 (authorized security testing)"
	maxRedirects     = 5
)

// ErrorKind classifies a transport failure so callers can react differently to
// a timeout, a TLS problem and a refused connection.
type ErrorKind string

const (
	ErrTimeout    ErrorKind = "timeout"
	ErrTLS        ErrorKind = "tls"
	ErrDNS        ErrorKind = "dns"
	ErrConnection ErrorKind = "connection"
	ErrInvalidURL ErrorKind = "invalid-url"
	ErrCanceled   ErrorKind = "canceled"
)

// Error is a classified transport failure.
type Error struct {
	URL  string
	Kind ErrorKind
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Kind, e.URL)
	}
	return fmt.Sprintf("%s: %s: %v", e.Kind, e.URL, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the classification of err, or "" for unclassified errors.
func KindOf(err error) ErrorKind {
	var classified *Error
	if errors.As(err, &classified) {
		return classified.Kind
	}
	return ""
}

// Request describes one HTTP request.
type Request struct {
	URL     string
	Method  string
	Headers http.Header
	Body    io.Reader
}

// Response is a fully read response.
type Response struct {
	URL       string
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
}

// BodyString returns the body as a string.
func (r *Response) BodyString() string { return string(r.Body) }

// Location returns the Location header of a redirect response.
func (r *Response) Location() string { return r.Header.Get("Location") }

// ContentType returns the lowercased media type without parameters.
func (r *Response) ContentType() string {
	value := r.Header.Get("Content-Type")
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// IsRedirect reports whether status is a redirect that carries a Location.
func IsRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// Options configures a Client.
type Options struct {
	// Rate is the maximum number of requests per second, shared by all
	// goroutines. Zero selects DefaultRate.
	Rate float64
	// Timeout bounds a single request, including reading the body.
	Timeout time.Duration
	// Proxy is an HTTP or HTTPS proxy URL, e.g. http://127.0.0.1:8080.
	Proxy string
	// Headers are extra request headers in "Name: value" form.
	Headers []string
	// Cookie is a raw Cookie header value, e.g. "session=abc; theme=dark".
	Cookie string
	// UserAgent overrides the default agent string.
	UserAgent string
	// MaxBody caps how much of a response body is read.
	MaxBody int64
}

func (o Options) normalized() Options {
	if o.Rate <= 0 {
		o.Rate = DefaultRate
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	return o
}

// Client is safe for concurrent use.
type Client struct {
	http     *http.Client
	limiter  *limiter
	headers  http.Header
	maxBody  int64
	agent    string
	requests atomic.Int64
}

// Requests reports how many requests this client has attempted. The scan report
// uses it to state the real cost of a run.
func (c *Client) Requests() int64 { return c.requests.Load() }

// New builds a Client.
func New(opts Options) (*Client, error) {
	normalized := opts.normalized()

	headers := make(http.Header, len(normalized.Headers)+2)
	for _, raw := range normalized.Headers {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("httpx: malformed header %q, want \"Name: value\"", raw)
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if normalized.Cookie != "" {
		headers.Set("Cookie", normalized.Cookie)
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 8,
		ForceAttemptHTTP2:   true,
		Proxy:               http.ProxyFromEnvironment,
	}
	if normalized.Proxy != "" {
		proxyURL, err := url.Parse(normalized.Proxy)
		if err != nil {
			return nil, fmt.Errorf("httpx: invalid proxy %q: %w", normalized.Proxy, err)
		}
		if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" {
			return nil, fmt.Errorf("httpx: unsupported proxy scheme %q", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   normalized.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		limiter: newLimiter(normalized.Rate),
		headers: headers,
		maxBody: normalized.MaxBody,
		agent:   normalized.UserAgent,
	}, nil
}

// Get issues a single GET without following redirects.
func (c *Client) Get(ctx context.Context, target string) (*Response, error) {
	return c.Do(ctx, Request{URL: target, Method: http.MethodGet})
}

// Fetch issues a GET and follows up to five redirects manually, so each hop is
// still rate limited and the final URL is reported accurately.
func (c *Client) Fetch(ctx context.Context, target string) (*Response, error) {
	current := target
	for hop := 0; hop <= maxRedirects; hop++ {
		response, err := c.Get(ctx, current)
		if err != nil {
			return nil, err
		}
		if !IsRedirect(response.Status) || response.Location() == "" {
			return response, nil
		}
		next, err := resolveRedirect(current, response.Location())
		if err != nil {
			return response, nil // report what we have; the Location is malformed
		}
		current = next
	}
	return nil, &Error{URL: target, Kind: ErrConnection, Err: errors.New("too many redirects")}
}

// PostForm submits an application/x-www-form-urlencoded body.
//
// This is the only state-changing request the tool can issue. The scan
// pipeline reaches it exclusively through the opt-in form mode, and only for
// same-origin forms that do not look destructive.
func (c *Client) PostForm(ctx context.Context, target string, values url.Values) (*Response, error) {
	headers := make(http.Header, 1)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(ctx, Request{
		URL:     target,
		Method:  http.MethodPost,
		Headers: headers,
		Body:    strings.NewReader(values.Encode()),
	})
}

// Do performs one request.
func (c *Client) Do(ctx context.Context, request Request) (*Response, error) {
	parsed, err := url.Parse(request.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, &Error{URL: request.URL, Kind: ErrInvalidURL, Err: errors.New("want an absolute http(s) URL")}
	}
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, &Error{URL: request.URL, Kind: ErrCanceled, Err: err}
	}
	c.requests.Add(1)

	httpRequest, err := http.NewRequestWithContext(ctx, method, request.URL, request.Body)
	if err != nil {
		return nil, &Error{URL: request.URL, Kind: ErrInvalidURL, Err: err}
	}
	for name, values := range c.headers {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}
	for name, values := range request.Headers {
		httpRequest.Header.Del(name)
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}
	if httpRequest.Header.Get("User-Agent") == "" {
		httpRequest.Header.Set("User-Agent", c.agent)
	}

	raw, err := c.http.Do(httpRequest)
	if err != nil {
		return nil, classify(request.URL, err)
	}
	defer raw.Body.Close()

	body, err := io.ReadAll(io.LimitReader(raw.Body, c.maxBody+1))
	if err != nil {
		return nil, classify(request.URL, err)
	}
	truncated := int64(len(body)) > c.maxBody
	if truncated {
		body = body[:c.maxBody]
	}

	return &Response{
		URL:       request.URL,
		Status:    raw.StatusCode,
		Header:    raw.Header.Clone(),
		Body:      body,
		Truncated: truncated,
	}, nil
}

// classify maps a transport error to a Kind without losing the original.
func classify(target string, err error) error {
	var classified *Error
	if errors.As(err, &classified) {
		return err
	}

	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return &Error{URL: target, Kind: ErrDNS, Err: err}
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return &Error{URL: target, Kind: ErrTLS, Err: err}
	}
	var recordError tls.RecordHeaderError
	if errors.As(err, &recordError) {
		return &Error{URL: target, Kind: ErrTLS, Err: err}
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return &Error{URL: target, Kind: ErrTimeout, Err: err}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{URL: target, Kind: ErrCanceled, Err: err}
	}
	return &Error{URL: target, Kind: ErrConnection, Err: err}
}

// resolveRedirect resolves a Location value against the current URL.
func resolveRedirect(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(reference).String(), nil
}

// limiter is a strict token bucket: one request per interval, shared globally.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rate float64) *limiter {
	if rate <= 0 {
		rate = DefaultRate
	}
	return &limiter{interval: time.Duration(float64(time.Second) / rate)}
}

func (l *limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
