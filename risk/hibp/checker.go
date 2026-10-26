package hibp

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	clock "github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	password "github.com/faustbrian/go-password/v2"
)

// Outcome describes provider evidence, never password acceptance.
type Outcome uint8

const (
	OutcomeNoMatch Outcome = iota + 1
	OutcomeMatch
	OutcomeUnavailable
	OutcomeInvalidConfiguration
	OutcomeMalformed
	OutcomeCancelled
)

var (
	// ErrMalformedRange denies usable evidence from invalid or oversized rows.
	ErrMalformedRange = errors.New("hibp: malformed range")
	// ErrProviderUnavailable covers transport, timeout, redirect and status errors.
	ErrProviderUnavailable = errors.New("hibp: provider unavailable")
	// ErrInvalidConfiguration rejects an incomplete immutable client profile.
	ErrInvalidConfiguration = errors.New("hibp: invalid configuration")
	// ErrInvalidRequest rejects incomplete scope or an unusable borrowed candidate.
	ErrInvalidRequest = errors.New("hibp: invalid request")
	// ErrOverloaded reports exhausted bounded caller admission; a new call may retry.
	ErrOverloaded = errors.New("hibp: caller capacity exhausted")
	// ErrClosed reports shutdown; construct another client to resume service.
	ErrClosed = errors.New("hibp: closed")
)

// CheckError contains only a safe classification, never a provider error, URL,
// prefix, suffix or candidate. errors.Is exposes its stable Cause identity.
type CheckError struct {
	Outcome Outcome
	Cause   error
	// Events retains immutable records on observed-checker failure, including
	// when SignalProvider returns only neutral risk evidence and this error.
	Events EventDelivery
}

func (e *CheckError) Error() string { return "hibp: check failed" }
func (e *CheckError) Unwrap() error { return e.Cause }

// CheckRequest carries trusted workflow attribution and a synchronously borrowed
// exact-byte candidate. Candidate ownership stays with its caller.
type CheckRequest struct {
	OperationID   string
	TenantID      identity.TenantID
	Action        risk.Action
	Purpose       string
	SubjectScope  string
	PolicyVersion string
	ReplayID      identity.CommandID
	Candidate     password.Secret
	// Attribution is required only by ObservedChecker. It is trusted audit
	// attribution, never inferred from the free-form screening scope.
	Attribution *SecurityAttribution
}

// Format prevents request logging from revealing scope or borrowed custody.
func (CheckRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "hibp.CheckRequest(redacted)")
}

// MarshalJSON rejects accidental persistence or network serialization. The
// candidate must remain an in-process borrow, not silently become an empty object.
func (CheckRequest) MarshalJSON() ([]byte, error) { return nil, errSensitive }

// MarshalText rejects automatic string serialization for the same custody reason.
func (CheckRequest) MarshalText() ([]byte, error) { return nil, errSensitive }

// CheckResult copies scope from this caller, not from shared/cache data. CheckedAt
// is the original provider read start, unchanged on cache hits. Failures provide
// no usable evidence; callers must inspect error before using any fields.
type CheckResult struct {
	OperationID   string
	TenantID      identity.TenantID
	Action        risk.Action
	Purpose       string
	SubjectScope  string
	PolicyVersion string
	ReplayID      identity.CommandID
	Outcome       Outcome
	BreachCount   uint64
	CheckedAt     time.Time
	// ProviderValidUntil is the original observation plus immutable CacheTTL.
	// It is unchanged on cache hits and zero on failures.
	ProviderValidUntil time.Time
	// Events reports submission separately from provider evidence. The ordinary
	// Client leaves it zero; ObservedChecker retains immutable reconciliation IDs.
	Events EventDelivery
}

// Checker is safe for concurrent use. Check has no automatic retry and makes no
// allow/deny decision. Each caller's cancellation is independent of other callers.
type Checker interface {
	Check(context.Context, CheckRequest) (CheckResult, error)
}

// Config is copied at construction. All numeric limits are explicit. MaxWaiters
// bounds active and queued calls together (1..1024); MaxCandidateBytes is 1..1MiB.
// CacheBytes (1KiB..128MiB) additionally bounds retained row storage, conservatively
// charged at 48 bytes per row. Entry overhead is bounded by CacheEntries. Disabled
// caching still coalesces concurrent work. PolicyVersion must match every request.
// AddPadding true is recommended and required by the reference profile. False
// omits padding and its response-size privacy protection; it is a core-only
// alternative. Numeric bounds are still mandatory, so zero Config is invalid.
type Config struct {
	UserAgent           string
	AddPadding          bool
	CacheEntries        uint32
	CacheTTL            time.Duration
	ResponseBytes       int64
	MaxBreachCount      uint64
	OutboundConcurrency uint8
	Timeout             time.Duration
	PolicyVersion       string
	MaxWaiters          uint32
	MaxCandidateBytes   int
	CacheBytes          int64
	DisableCache        bool
}

type cachedRange struct {
	prefix [5]byte
	data   rangeData
	at     time.Time
	bytes  int64
}
type flight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	data    rangeData
	at      time.Time
	err     error
}

// Client owns request goroutines and private cache. mu is the sole synchronization
// owner; no clock callback, network operation or body parsing runs while held.
// Close cancels work, releases cached data, and waits within the supplied context.
// The zero value is invalid. Configuration and borrowed transport must not mutate.
type Client struct {
	config     Config
	http       *httpclient.Client
	clock      clock.Clock
	slots      chan struct{}
	mu         sync.Mutex
	flights    map[[5]byte]*flight
	cache      map[[5]byte]*list.Element
	lru        list.List
	cacheBytes int64
	lastNow    time.Time
	callers    uint32
	running    int
	closed     bool
	drained    chan struct{}
}

// New constructs an isolated client using only the supplied client's borrowed
// RoundTripper, not its middleware, cookie jar, redirect callbacks or headers.
// The supplied primitive is not mutated or closed. Its transport must be trusted,
// privacy-safe, HTTPS-verifying and context-cooperative; retain it until Close
// finishes. TLS/proxy/dial policy belongs to that transport. No alternate endpoint
// is accepted. The returned Checker is a *Client for explicit lifecycle ownership.
func New(config Config, transport *httpclient.Client, wall clock.Clock) (Checker, error) {
	if transport == nil || wall == nil || !config.valid() || transport.HTTPClient() == nil || transport.HTTPClient().Transport == nil {
		return nil, ErrInvalidConfiguration
	}
	h, e := httpclient.New(httpclient.Config{Transport: transport.HTTPClient().Transport, Timeout: config.Timeout})
	if e != nil {
		return nil, ErrInvalidConfiguration
	}
	h.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{config: config, http: h, clock: wall, slots: make(chan struct{}, config.OutboundConcurrency),
		flights: make(map[[5]byte]*flight), cache: make(map[[5]byte]*list.Element), drained: make(chan struct{})}, nil
}

func ascii(s string, max int, canonical bool) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
		if canonical && !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func (c Config) valid() bool {
	if len(c.UserAgent) == 0 || len(c.UserAgent) > 256 {
		return false
	}
	for _, b := range []byte(c.UserAgent) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return c.CacheEntries >= 100 && c.CacheEntries <= 100000 && c.CacheTTL >= time.Hour && c.CacheTTL <= 7*24*time.Hour &&
		c.ResponseBytes >= 1024 && c.ResponseBytes <= 2<<20 && c.MaxBreachCount > 0 && c.MaxBreachCount <= 1000000000 &&
		c.OutboundConcurrency >= 1 && c.OutboundConcurrency <= 64 && c.Timeout >= time.Second && c.Timeout <= 30*time.Second &&
		ascii(c.PolicyVersion, 64, false) && c.MaxWaiters >= 1 && c.MaxWaiters <= 1024 && c.MaxCandidateBytes >= 1 && c.MaxCandidateBytes <= 1<<20 &&
		c.CacheBytes >= 1024 && c.CacheBytes <= 128<<20
}

func (r CheckRequest) valid(version string) bool {
	_, e := identity.ParseCommandID(string(r.ReplayID))
	return e == nil && ascii(r.OperationID, 128, true) && string(r.Action) == r.OperationID && ascii(r.Purpose, 64, true) &&
		ascii(r.SubjectScope, 256, false) && r.PolicyVersion == version && len(r.TenantID) > 0 && len(r.TenantID) <= 128 && utf8.ValidString(string(r.TenantID))
}

func resultFor(r CheckRequest) CheckResult {
	return CheckResult{OperationID: r.OperationID, TenantID: r.TenantID, Action: r.Action, Purpose: r.Purpose,
		SubjectScope: r.SubjectScope, PolicyVersion: r.PolicyVersion, ReplayID: r.ReplayID}
}

func failure(r CheckResult, cause error) (CheckResult, error) {
	r.Outcome = OutcomeUnavailable
	switch {
	case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
		r.Outcome = OutcomeCancelled
	case errors.Is(cause, ErrInvalidConfiguration):
		r.Outcome = OutcomeInvalidConfiguration
	case errors.Is(cause, ErrMalformedRange):
		r.Outcome = OutcomeMalformed
	}
	r.BreachCount = 0
	r.ProviderValidUntil = time.Time{}
	return r, &CheckError{Outcome: r.Outcome, Cause: cause, Events: r.Events}
}

func (c *Client) Check(ctx context.Context, request CheckRequest) (CheckResult, error) {
	r := resultFor(request)
	if c == nil || c.http == nil {
		return failure(r, ErrInvalidConfiguration)
	}
	if ctx == nil || !request.valid(c.config.PolicyVersion) {
		return failure(r, ErrInvalidRequest)
	}
	if e := ctx.Err(); e != nil {
		return failure(r, e)
	}
	now, valid := c.observe()
	if !valid {
		return failure(r, ErrProviderUnavailable)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return failure(r, ErrClosed)
	}
	if c.callers == c.config.MaxWaiters {
		c.mu.Unlock()
		return failure(r, ErrOverloaded)
	}
	c.callers++
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.callers--; c.mu.Unlock() }()
	r.CheckedAt = now
	derived, e := deriveCandidate(ctx, request.Candidate, c.config.MaxCandidateBytes)
	if e != nil {
		if !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
			e = ErrInvalidRequest
		}
		return failure(r, e)
	}
	defer derived.clear()
	// Borrowing must not extend a cache entry's lifetime.
	now, valid = c.observe()
	if !valid {
		return failure(r, ErrProviderUnavailable)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return failure(r, ErrClosed)
	}
	if element := c.cache[derived.prefix]; element != nil {
		cached := element.Value.(cachedRange)
		if c.lastNow.Before(cached.at.Add(c.config.CacheTTL)) && !now.Before(cached.at) {
			c.lru.MoveToFront(element)
			c.mu.Unlock()
			if e := ctx.Err(); e != nil {
				return failure(r, e)
			}
			r.CheckedAt = cached.at
			r.ProviderValidUntil = cached.at.Add(c.config.CacheTTL)
			return matched(r, cached.data, derived.suffix), nil
		}
		c.evict(element)
	}
	f := c.flights[derived.prefix]
	if f == nil {
		// Departed callers can leave cancellation-draining work behind. Count that
		// work too, so rapid cancellation cannot bypass the goroutine bound.
		if c.running >= int(c.config.MaxWaiters) {
			c.mu.Unlock()
			return failure(r, ErrOverloaded)
		}
		shared, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
		f = &flight{done: make(chan struct{}), cancel: cancel, at: now}
		c.flights[derived.prefix] = f
		c.running++
		go c.fetch(shared, derived.prefix, f)
	}
	f.waiters++
	c.mu.Unlock()
	defer c.leave(derived.prefix, f)
	select {
	case <-ctx.Done():
		return failure(r, ctx.Err())
	case <-f.done:
		if e := ctx.Err(); e != nil {
			return failure(r, e)
		}
		if f.err != nil {
			return failure(r, f.err)
		}
		now, valid = c.observe()
		c.mu.Lock()
		fresh := valid && !now.Before(f.at) && c.lastNow.Before(f.at.Add(c.config.CacheTTL))
		c.mu.Unlock()
		if e := ctx.Err(); e != nil {
			return failure(r, e)
		}
		if !fresh {
			return failure(r, ErrProviderUnavailable)
		}
		r.CheckedAt = f.at
		r.ProviderValidUntil = f.at.Add(c.config.CacheTTL)
		return matched(r, f.data, derived.suffix), nil
	}
}

// A concurrent later sample may acquire mu first. Compare a sample against the
// state that preceded its callback, not against another overlapping callback's
// later observation. The greatest observed timestamp governs cache expiry; an
// isolated backwards clock still fails closed. No caller callback runs under mu.
func (c *Client) observe() (time.Time, bool) {
	c.mu.Lock()
	before := c.lastNow
	c.mu.Unlock()
	now := c.clock.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.IsZero() || now.Before(before) {
		return time.Time{}, false
	}
	if now.After(c.lastNow) {
		c.lastNow = now
	}
	return now, true
}

func matched(r CheckResult, data rangeData, suffix [35]byte) CheckResult {
	r.BreachCount = uint64(data.match(suffix))
	r.Outcome = OutcomeNoMatch
	if r.BreachCount > 0 {
		r.Outcome = OutcomeMatch
	}
	return r
}

func (c *Client) leave(prefix [5]byte, f *flight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f.waiters--
	if f.waiters == 0 && c.flights[prefix] == f {
		delete(c.flights, prefix)
		f.cancel()
	}
}

func (c *Client) fetch(ctx context.Context, prefix [5]byte, f *flight) {
	var data rangeData
	err := ErrProviderUnavailable
	select {
	case c.slots <- struct{}{}:
		if ctx.Err() == nil {
			data, err = c.read(ctx, prefix)
		}
		<-c.slots
	case <-ctx.Done():
	}
	clockValid := false
	if err == nil {
		// TTL starts at the original observation, not response completion. A
		// clock change during IO must not publish or cache already-stale facts.
		now, valid := c.observe()
		clockValid = valid && !now.Before(f.at)
	}
	c.mu.Lock()
	// Overlapping callbacks may complete out of order. Expiry uses the greatest
	// trusted observation under the publication lock, not an older valid sample.
	if err == nil && (!clockValid || !c.lastNow.Before(f.at.Add(c.config.CacheTTL))) {
		data, err = rangeData{}, ErrProviderUnavailable
	}
	// read includes deferred body cleanup; expiry there or while awaiting mu
	// must not publish or cache success after the bounded provider operation.
	// Compare the monotonic deadline too: its cancellation timer may run later.
	deadline, bounded := ctx.Deadline()
	if err == nil && (ctx.Err() != nil || (bounded && !time.Now().Before(deadline))) {
		data, err = rangeData{}, ErrProviderUnavailable
	}
	f.cancel()
	// Abandoned work cannot populate a cache or absorb a later caller.
	if c.flights[prefix] == f {
		delete(c.flights, prefix)
		if !c.closed && err == nil && f.waiters > 0 && !c.config.DisableCache {
			c.store(prefix, data, f.at)
		}
	}
	if c.closed {
		data = rangeData{}
		err = ErrClosed
	}
	f.data, f.err = data, err
	close(f.done)
	c.running--
	if c.closed && c.running == 0 {
		close(c.drained)
	}
	c.mu.Unlock()
}

func (c *Client) read(ctx context.Context, prefix [5]byte) (rangeData, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+string(prefix[:]), nil)
	if e != nil {
		return rangeData{}, ErrProviderUnavailable
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.config.AddPadding {
		req.Header.Set("Add-Padding", "true")
	}
	response, e := c.http.Do(req)
	if e != nil {
		return rangeData{}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != req.URL.String() {
		return rangeData{}, ErrProviderUnavailable
	}
	data, e := parseRange(ctx, response.Body, rangeLimits{bytes: int(c.config.ResponseBytes), count: uint32(c.config.MaxBreachCount)})
	if errors.Is(e, errMalformedRange) {
		return rangeData{}, ErrMalformedRange
	}
	if e != nil || ctx.Err() != nil {
		return rangeData{}, ErrProviderUnavailable
	}
	return data, nil
}

// Immutable entries may still be in use by waiters. Eviction releases the cache
// reference, never overwrites shared suffix memory concurrently with matching.
func (c *Client) evict(e *list.Element) {
	entry := e.Value.(cachedRange)
	delete(c.cache, entry.prefix)
	c.cacheBytes -= entry.bytes
	c.lru.Remove(e)
}

func (c *Client) store(prefix [5]byte, data rangeData, at time.Time) {
	bytes := int64(cap(data.entries)) * 48
	if bytes > c.config.CacheBytes {
		return
	}
	for c.lru.Len() > 0 && (c.lru.Len() >= int(c.config.CacheEntries) || c.cacheBytes+bytes > c.config.CacheBytes) {
		c.evict(c.lru.Back())
	}
	c.cache[prefix] = c.lru.PushFront(cachedRange{prefix: prefix, data: data, at: at, bytes: bytes})
	c.cacheBytes += bytes
}

// Close is idempotent. It rejects new calls immediately, cancels active/queued
// flights, releases cache data, and waits for owned work. If ctx expires, shutdown
// continues; call Close again to await it. The borrowed transport is not closed.
func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.http == nil {
		return ErrInvalidConfiguration
	}
	if ctx == nil {
		return ErrInvalidRequest
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		for _, f := range c.flights {
			f.cancel()
		}
		clear(c.cache)
		c.lru.Init()
		c.cacheBytes = 0
		if c.running == 0 {
			close(c.drained)
		}
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.drained:
		return c.http.Close()
	}
}
