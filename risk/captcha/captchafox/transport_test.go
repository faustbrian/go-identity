package captchafox_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/captchafox"
)

func TestCaptchaFoxStatusAndAmbiguousIOAreBoundedWithoutRetry(t *testing.T) {
	for _, status := range []int{302, 429, 503} {
		var calls atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			out := response(r, validBody)
			out.StatusCode = status
			out.Header.Set("Location", "https://attacker.invalid/collect")
			return out, nil
		})
		got, err := p.Verify(context.Background(), input(t))
		want := captcha.OutcomeUnavailable
		if status == 429 {
			want = captcha.OutcomeThrottled
		}
		if err == nil || got.Outcome != want || !got.ExpiresAt.IsZero() || calls.Load() != 1 || got.Failure.Retry != captcha.RetryNever {
			t.Fatal("status followed redirect/retry or became usable", err)
		}
	}
	var calls atomic.Int32
	p := client(t, config(), func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("synthetic-sensitive-provider-diagnostic")
	})
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, captcha.ErrAmbiguousTransport) || got.Outcome != captcha.OutcomeAmbiguous || got.Failure.Transport != captcha.TransportUnknown || got.Failure.Retry != captcha.RetryNever || calls.Load() != 1 || strings.Contains(fmt.Sprintf("%+v", err), "synthetic-sensitive") {
		t.Fatal("ambiguous exchange was retried or exposed diagnostics", err)
	}
}

type countingBody struct {
	reads, closed atomic.Int32
	partial       bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(int32(len(p)))
	for i := range p {
		p[i] = ' '
	}
	if b.partial {
		return 1, errors.New("synthetic-sensitive-read-error")
	}
	return len(p), nil
}
func (b *countingBody) Close() error { b.closed.Add(1); return nil }

func TestCaptchaFoxClosesAndBoundsInfinitePartialAndOversizedBodies(t *testing.T) {
	for _, kind := range []string{"infinite", "partial", "known-oversize"} {
		body := &countingBody{partial: kind == "partial"}
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			out := response(r, "")
			out.Body = body
			if kind == "known-oversize" {
				out.ContentLength = 4097
			}
			return out, nil
		})
		got, err := p.Verify(context.Background(), input(t))
		want := captcha.OutcomeMalformed
		if kind == "partial" {
			want = captcha.OutcomeAmbiguous
		}
		if err == nil || got.Outcome != want || !got.ExpiresAt.IsZero() || body.closed.Load() != 1 || body.reads.Load() > 4097 {
			t.Fatal("body budget/cleanup or ambiguity wrong", err, body.reads.Load(), body.closed.Load())
		}
		if kind == "known-oversize" && body.reads.Load() != 0 {
			t.Fatal("known oversized body read")
		}
	}
}

func TestCaptchaFoxVerifiedTLSDoesNotInheritCookiesHeadersOrRedirects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Host != "api.captchafox.com" {
			t.Error("inherited transport policy or endpoint escaped")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, validBody)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	ambient, err := httpclient.NewRequestEditorMiddleware(httpclient.MiddlewareOptions{Name: "synthetic-ambient-header", Scope: httpclient.ScopeAttempt, Layer: httpclient.MiddlewareEndpoint}, httpclient.RequestEditorFunc(func(r *http.Request) error { r.Header.Set("Authorization", "synthetic-inherited-header"); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := httpclient.New(httpclient.Config{Transport: transport, Middleware: []httpclient.Middleware{ambient}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://api.captchafox.com")
	jar.SetCookies(u, []*http.Cookie{{Name: "synthetic", Value: "custody"}})
	owner.HTTPClient().Jar = jar
	owner.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { t.Error("borrowed redirect callback invoked"); return nil }
	p, err := captchafox.New(config(), owner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	got, err := p.Verify(context.Background(), input(t))
	if err != nil || got.Outcome != captcha.OutcomeSolved || calls.Load() != 1 {
		t.Fatal("verified TLS path failed", err)
	}
}

func TestCaptchaFoxCloseCancelsDrainsAndRejectsSaturatedCalls(t *testing.T) {
	entered := make(chan struct{})
	exited := make(chan struct{})
	cfg := config()
	cfg.Profile.MaxConcurrent = 1
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		close(exited)
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	go func() { _, err := p.Verify(context.Background(), input(t)); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("exchange never entered")
	}
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, captcha.ErrOverloaded) || got.Failure.Transport != captcha.TransportNotSent {
		t.Fatal("saturation queued or sent", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal("Close did not drain", err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("Close returned before exchange stopped")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed exchange returned success")
		}
	case <-ctx.Done():
		t.Fatal("Verify goroutine did not drain")
	}
	got, err = p.Verify(context.Background(), input(t))
	if err == nil || got.Failure.Transport != captcha.TransportNotSent {
		t.Fatal("closed client sent request")
	}
}

func TestCaptchaFoxCancellationInputBoundsAndSecretOwnership(t *testing.T) {
	var calls atomic.Int32
	cfg := config()
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.PostForm.Get("secret") != "synthetic-provider-secret" {
			t.Error("caller mutation changed owned secret")
		}
		return response(r, validBody), nil
	})
	for i := range cfg.Secret {
		cfg.Secret[i] = 'x'
	}
	if _, err := p.Verify(context.Background(), input(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Verify(ctx, input(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancellation ignored", err)
	}
	r := input(t)
	r.Token = make([]byte, 2049)
	if _, err := p.Verify(context.Background(), r); !errors.Is(err, captcha.ErrInvalidToken) {
		t.Fatal("oversized token sent", err)
	}
	if calls.Load() != 1 {
		t.Fatal("invalid or cancelled request reached network")
	}
	owner, err := httpclient.New(httpclient.Config{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid construction performed IO")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	for _, mutate := range []func(*captchafox.Config){func(c *captchafox.Config) { c.Secret = make([]byte, 4097) }, func(c *captchafox.Config) { c.Endpoint = "https://attacker.invalid/siteverify" }, func(c *captchafox.Config) { c.Profile.Version = "v2" }, func(c *captchafox.Config) { c.Profile.Tier = "enterprise" }, func(c *captchafox.Config) { c.Profile.Provider = "turnstile" }, func(c *captchafox.Config) { c.Profile.RemoteIPDisclosure = true }} {
		bad := config()
		mutate(&bad)
		if _, err := captchafox.New(bad, owner, wallClock{time.Now().UTC()}); !errors.Is(err, captcha.ErrInvalidConfiguration) {
			t.Fatal("unsupported or unbounded config admitted", err)
		}
	}
}

type deadlineCloseBody struct {
	io.Reader
	deadline time.Time
	closed   atomic.Bool
}

func (b *deadlineCloseBody) Close() error {
	timer := time.NewTimer(time.Until(b.deadline))
	defer timer.Stop()
	<-timer.C
	b.closed.Store(true)
	return nil
}

func TestCaptchaFoxDeadlineDuringResponseCleanupCannotPublishSolved(t *testing.T) {
	var body *deadlineCloseBody
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("provider request unbounded")
		}
		body = &deadlineCloseBody{Reader: strings.NewReader(validBody), deadline: deadline}
		out := response(r, "")
		out.Body = body
		return out, nil
	})
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, context.DeadlineExceeded) || got.Outcome != captcha.OutcomeCancelled || !got.ExpiresAt.IsZero() || body == nil || !body.closed.Load() {
		t.Fatal("late cleanup published usable evidence or leaked body", err)
	}
}

func TestCaptchaFoxProviderTimeoutAndTelemetryDoNotRetainRawErrors(t *testing.T) {
	var observations atomic.Int32
	cfg := config()
	cfg.Observe = func(ctx context.Context, o captchafox.Observation) {
		observations.Add(1)
		if o.Duration < 0 || o.Transport != captcha.TransportUnknown {
			t.Error("incorrect bounded telemetry")
		}
		panic("synthetic-sensitive-observer-diagnostic")
	}
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, errors.New("synthetic-sensitive-timeout-diagnostic")
	})
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, context.DeadlineExceeded) || got.Outcome != captcha.OutcomeCancelled || !got.ExpiresAt.IsZero() || observations.Load() != 1 || strings.Contains(fmt.Sprintf("%+v", err), "synthetic-sensitive") {
		t.Fatal("timeout/observer failure leaked diagnostics or success", err)
	}
}

func TestCaptchaFoxRejectsExplicitUnexpectedContentTypesBeforeReading(t *testing.T) {
	for _, value := range []string{"text/html", "application/problem+json", "application/json; charset=iso-8859-1", "invalid; ="} {
		body := &countingBody{}
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			out := response(r, "")
			out.Body = body
			out.Header.Set("Content-Type", value)
			return out, nil
		})
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, captcha.ErrMalformedResponse) || got.Outcome != captcha.OutcomeMalformed || body.reads.Load() != 0 || body.closed.Load() != 1 {
			t.Fatal("explicit non-JSON type read or accepted", err)
		}
	}
	for _, value := range []string{"", "application/json", "application/json; charset=UTF-8", "application/json; charset=Utf-8"} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			out := response(r, validBody)
			out.Header.Set("Content-Type", value)
			return out, nil
		})
		if _, err := p.Verify(context.Background(), input(t)); err != nil {
			t.Fatal("JSON response contract rejected", err)
		}
	}
}
