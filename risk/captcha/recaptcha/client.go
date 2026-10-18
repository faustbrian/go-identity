// Package recaptcha implements the fixed Google classic Siteverify v3/standard profile.
// Verification yields provider facts, not identity authority or risk decisions.
package recaptcha

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"time"

	clock "github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
)

const endpoint = "https://www.google.com/recaptcha/api/siteverify"

// Observation contains only a closed outcome, transport class and duration. Host
// observers must be bounded/nonblocking and concurrency-safe; nil disables them.
// No token, secret, remote address, site, scope or raw error is supplied.
// It describes provider exchange completion before neutral binding normalization,
// not usable screening evidence or an identity-policy decision.
type Observation struct {
	Outcome   captcha.Outcome
	Transport captcha.TransportOutcome
	Duration  time.Duration
}

// Config selects the explicit endpoint and neutral profile. Secret (1..4096
// visible ASCII bytes) is copied; caller ownership is unchanged. ResponseBytes
// is 1KiB..64KiB before parsing; UserAgent is non-secret visible ASCII 1..256.
// Endpoint overrides, remote-IP disclosure, v2 and Enterprise are unsupported.
// The wall parameter of New supplies the profile clock. Observe is optional host
// telemetry only, never canonical security-event delivery or policy authority.
type Config struct {
	Profile             captcha.Config
	Secret              []byte
	Endpoint, UserAgent string
	ResponseBytes       int64
	Observe             func(context.Context, Observation)
}

// Client owns copied secret custody and its isolated HTTP primitive, borrowing
// only the supplied RoundTripper and wall clock. Close cancels/drains exchanges
// and clears retained secret bytes. Host transports must verify HTTPS, honor
// cancellation, support concurrency and never log or retain request bodies.
type Client struct {
	neutral *captcha.Client
	wire    *wireVerifier
}
type wireVerifier struct {
	config  Config
	http    *httpclient.Client
	wall    clock.Clock
	mu      sync.Mutex
	secret  []byte
	closed  bool
	active  int
	life    context.Context
	cancel  context.CancelFunc
	drained chan struct{}
}

// New constructs only the classic Siteverify v3/standard profile; no endpoint/credential is
// inferred. Borrowed middleware, headers, cookies and redirect behavior are not
// inherited. It starts no goroutine and makes no provider request.
func New(config Config, transport *httpclient.Client, wall clock.Clock) (*Client, error) {
	if config.Endpoint != endpoint || !userAgent(config.UserAgent) || len(config.Secret) < 1 || len(config.Secret) > 4096 || !safeASCII(string(config.Secret), 4096, false) || config.ResponseBytes < 1024 || config.ResponseBytes > 64<<10 || transport == nil || transport.HTTPClient() == nil || missing(transport.HTTPClient().Transport) || config.Profile.Provider != "recaptcha" {
		return nil, captcha.ErrInvalidConfiguration
	}
	config.Profile.Clock = wall
	w := &wireVerifier{config: config, wall: wall, drained: make(chan struct{})}
	n, err := captcha.New(config.Profile, w)
	if err != nil {
		return nil, err
	}
	w.config.Profile.Hostnames = slices.Clone(config.Profile.Hostnames)
	h, err := httpclient.New(httpclient.Config{Transport: transport.HTTPClient().Transport, Timeout: config.Profile.Timeout})
	if err != nil {
		return nil, captcha.ErrInvalidConfiguration
	}
	h.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	w.http = h
	w.secret = bytes.Clone(config.Secret)
	w.config.Secret = nil
	w.life, w.cancel = context.WithCancel(context.Background())
	return &Client{neutral: n, wire: w}, nil
}

// Verify returns the neutral bounded snapshot. No automatic retry or result
// caching occurs, even after an ambiguous exchange or provider configuration error.
func (c *Client) Verify(ctx context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
	if c == nil || c.neutral == nil {
		return captcha.ProviderResult{}, captcha.ErrInvalidConfiguration
	}
	return c.neutral.Verify(ctx, r)
}

// Observe is directly assignable to the existing risk issuer's Verify callback;
// native fields stay in Verify's envelope and replay custody remains upstream.
func (c *Client) Observe(ctx context.Context, r risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
	if c == nil || c.neutral == nil {
		return risk.CaptchaObservation{}, captcha.ErrInvalidConfiguration
	}
	return c.neutral.Observe(ctx, r)
}

func (w *wireVerifier) begin(ctx context.Context) (context.Context, []byte, func(), bool) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil, nil, nil, false
	}
	w.active++
	secret := bytes.Clone(w.secret)
	w.mu.Unlock()
	bounded, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(w.life, cancel)
	return bounded, secret, func() {
		stop()
		cancel()
		clear(secret)
		w.mu.Lock()
		defer w.mu.Unlock()
		w.active--
		if w.closed && w.active == 0 {
			clear(w.secret)
			w.secret = nil
			close(w.drained)
		}
	}, true
}

func (w *wireVerifier) Verify(ctx context.Context, r captcha.VerifyRequest) (result captcha.ProviderResult, err error) {
	result = captcha.ProviderResult{Flow: r.Flow, CommandID: r.CommandID, Evidence: profileEvidence(w.config.Profile)}
	bounded, secret, done, ok := w.begin(ctx)
	if !ok {
		return failure(result, captcha.OutcomeUnavailable, captcha.TransportNotSent, captcha.RetryNever, captcha.ErrProviderUnavailable)
	}
	defer done()
	result.ObservedAt = w.wall.Now().UTC()
	started := time.Now()
	defer func() {
		if w.config.Observe != nil {
			func() {
				defer func() { _ = recover() }()
				w.config.Observe(bounded, Observation{Outcome: result.Outcome, Transport: result.Failure.Transport, Duration: time.Since(started)})
			}()
		}
	}()
	// Google classic Siteverify has no documented idempotency field. Never send
	// a transport UUID or automatically repeat possibly consumed tokens.
	form := url.Values{"secret": {string(secret)}, "response": {string(r.Token)}}
	payload := []byte(form.Encode())
	defer clear(payload)
	req, buildErr := http.NewRequestWithContext(bounded, http.MethodPost, endpoint, bytes.NewReader(payload))
	if buildErr != nil {
		return failure(result, captcha.OutcomeUnavailable, captcha.TransportNotSent, captcha.RetryNever, captcha.ErrProviderUnavailable)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", w.config.UserAgent)
	response, readErr := w.http.Do(req)
	if readErr != nil {
		return failure(result, captcha.OutcomeAmbiguous, captcha.TransportUnknown, captcha.RetryNever, captcha.ErrAmbiguousTransport)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != endpoint {
		return failure(result, captcha.OutcomeUnavailable, captcha.TransportResponded, captcha.RetryNever, captcha.ErrProviderUnavailable)
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return failure(result, captcha.OutcomeThrottled, captcha.TransportResponded, captcha.RetryNever, captcha.ErrThrottled)
	}
	if response.StatusCode != http.StatusOK {
		return failure(result, captcha.OutcomeUnavailable, captcha.TransportResponded, captcha.RetryNever, captcha.ErrProviderUnavailable)
	}
	if response.ContentLength > w.config.ResponseBytes {
		return failure(result, captcha.OutcomeMalformed, captcha.TransportResponded, captcha.RetryNever, captcha.ErrMalformedResponse)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, w.config.ResponseBytes+1))
	defer clear(body)
	if readErr != nil {
		return failure(result, captcha.OutcomeAmbiguous, captcha.TransportUnknown, captcha.RetryNever, captcha.ErrAmbiguousTransport)
	}
	if int64(len(body)) > w.config.ResponseBytes {
		return failure(result, captcha.OutcomeMalformed, captcha.TransportResponded, captcha.RetryNever, captcha.ErrMalformedResponse)
	}
	evidence, parseErr := parseBody(body, w.config.Profile)
	result.Evidence = evidence
	if parseErr != nil {
		return failure(result, captcha.OutcomeMalformed, captcha.TransportResponded, captcha.RetryNever, captcha.ErrMalformedResponse)
	}
	for _, code := range evidence.Recaptcha.ErrorCodes {
		if !knownCode(code) {
			return failure(result, captcha.OutcomeMalformed, captcha.TransportResponded, captcha.RetryNever, captcha.ErrMalformedResponse)
		}
	}
	if !evidence.Success {
		for _, code := range evidence.Recaptcha.ErrorCodes {
			if code == "missing-input-secret" || code == "invalid-input-secret" || code == "bad-request" {
				return failure(result, captcha.OutcomeUnavailable, captcha.TransportResponded, captcha.RetryNever, captcha.ErrProviderUnavailable)
			}
		}
		return failure(result, captcha.OutcomeRejected, captcha.TransportResponded, captcha.RetryNewChallenge, captcha.ErrInvalidToken)
	}
	result.Outcome = captcha.OutcomeSolved
	result.ExpiresAt = result.ObservedAt.Add(w.config.Profile.Lifetime)
	result.Failure = captcha.Failure{Transport: captcha.TransportResponded, Retry: captcha.RetryNever}
	return result, nil
}

func failure(r captcha.ProviderResult, outcome captcha.Outcome, transport captcha.TransportOutcome, retry captcha.RetryClass, cause error) (captcha.ProviderResult, error) {
	r.Outcome = outcome
	r.ExpiresAt = time.Time{}
	r.Failure = captcha.Failure{Outcome: outcome, Transport: transport, Retry: retry}
	return r, &captcha.VerifyError{Failure: r.Failure, Cause: cause}
}

// Close is idempotent. It rejects new exchanges, cancels existing ones and
// drains secret custody within ctx. On timeout shutdown continues; call again
// to await completion. It never closes the caller's borrowed HTTP client.
func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.wire == nil {
		return captcha.ErrInvalidConfiguration
	}
	if ctx == nil {
		return captcha.ErrInvalidRequest
	}
	w := c.wire
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		w.cancel()
		if w.active == 0 {
			clear(w.secret)
			w.secret = nil
			close(w.drained)
		}
	}
	w.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.drained:
		return w.http.Close()
	}
}

func safeASCII(value string, maximum int, empty bool) bool {
	if len(value) > maximum || !empty && value == "" {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func userAgent(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
func (Config) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "recaptcha.Config(redacted)") }
func (Config) MarshalJSON() ([]byte, error) { return nil, captcha.ErrInvalidRequest }
func (Config) MarshalText() ([]byte, error) { return nil, captcha.ErrInvalidRequest }

var _ captcha.Verifier = (*Client)(nil)
