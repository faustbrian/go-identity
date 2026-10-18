package recaptcha_test

import (
	"context"
	"encoding/json"
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
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/recaptcha"
)

type wallClock struct{ now time.Time }

func (c wallClock) Now() time.Time { return c.now }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func config() recaptcha.Config {
	return recaptcha.Config{Endpoint: "https://www.google.com/recaptcha/api/siteverify", UserAgent: "golib synthetic test", Secret: []byte("synthetic-provider-secret"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "recaptcha", API: "classic_siteverify", Version: "v3", Tier: "standard", APIProfile: "classic_siteverify/v3", SiteKey: "synthetic-configured-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, ExpectedAction: "account/signup", MaxTokenBytes: 2048, MaxConcurrent: 4, Timeout: time.Second, Lifetime: 2 * time.Minute, ChallengeMaxAge: 2 * time.Minute}}
}
func input(t *testing.T) captcha.VerifyRequest {
	t.Helper()
	f, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	return captcha.VerifyRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: f, Token: []byte("synthetic-provider-token")}
}

const validBody = `{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com","action":"account/signup","score":0.01,"error-codes":[]}`

func response(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func client(t *testing.T, cfg recaptcha.Config, h roundTripFunc) *recaptcha.Client {
	t.Helper()
	owner, err := httpclient.New(httpclient.Config{Transport: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	p, err := recaptcha.New(cfg, owner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestPublicRecaptchaPostsPrivateFormAndPreservesLowScoreRiskCallback(t *testing.T) {
	var calls atomic.Int32
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.String() != "https://www.google.com/recaptcha/api/siteverify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("request escaped private endpoint/form")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if len(r.PostForm) != 2 || r.PostForm.Get("secret") != "synthetic-provider-secret" || r.PostForm.Get("response") != "synthetic-provider-token" || r.PostForm.Has("remoteip") || r.PostForm.Has("idempotency_key") || r.PostForm.Has("sitekey") {
			t.Error("provider request changed custody or invented protocol fields")
		}
		return response(r, validBody), nil
	})
	r := input(t)
	got, err := p.Verify(context.Background(), r)
	if err != nil || got.Outcome != captcha.OutcomeSolved || !got.Evidence.Success || !got.Evidence.ScoreAvailable || got.Evidence.Score != 0.01 || !got.Evidence.HostnameMatched || !got.Evidence.ActionMatched || got.Evidence.Recaptcha == nil || !got.Evidence.Recaptcha.ErrorCodesAvailable || got.Evidence.Turnstile != nil || got.Evidence.Origin.Available || got.Evidence.SiteKey != "synthetic-configured-site" {
		t.Fatal("native v3 facts lost or score became policy decision", err)
	}
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: p.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Provider != "recaptcha" || fact.API != "classic_siteverify" || fact.Version != "v3" || fact.Tier != "standard" || !fact.ScoreAvailable || fact.Score != 0.01 || fact.Action.Value != "account/signup" || !fact.ExpiresAt.Equal(time.Date(2026, 10, 18, 12, 1, 30, 0, time.UTC)) || calls.Load() != 2 {
		t.Fatal("public callback lost original binding/validity/score", err)
	}
	for _, v := range []any{got, got.Evidence, got.Evidence.Recaptcha, config()} {
		if strings.Contains(fmt.Sprintf("%#v", v), "synthetic-provider-") {
			t.Fatal("automatic diagnostics disclosed custody")
		}
	}
	if string(r.Token) != "synthetic-provider-token" {
		t.Fatal("borrowed token changed")
	}
}

func TestRecaptchaFailsClosedWithoutV3ScoreOrActionAndRetainsMismatchFacts(t *testing.T) {
	for _, tc := range []struct {
		body  string
		cause error
	}{
		{strings.Replace(validBody, `"score":0.01,`, "", 1), captcha.ErrMalformedResponse},
		{strings.Replace(validBody, `"action":"account/signup",`, "", 1), captcha.ErrBindingMismatch},
		{strings.Replace(validBody, "account/signup", "other/action", 1), captcha.ErrBindingMismatch},
		{strings.Replace(validBody, "example.com", "foreign.example.com", 1), captcha.ErrBindingMismatch},
		{strings.Replace(validBody, "11:59:30", "11:58:00", 1), captcha.ErrInvalidToken},
		{strings.Replace(validBody, "11:59:30", "12:00:01", 1), captcha.ErrInvalidToken},
	} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, tc.body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || got.Evidence.Recaptcha == nil {
			t.Fatal("missing/mismatched/expired v3 facts usable or discarded", err)
		}
	}
}

func TestRecaptchaHostileResponseCannotBecomeUsableOrRetry(t *testing.T) {
	for _, body := range []string{
		strings.Replace(validBody, `"score":0.01`, `"score":-0.01`, 1),
		strings.Replace(validBody, `"score":0.01`, `"score":1.01`, 1),
		strings.Replace(validBody, `"score":0.01`, `"score":1e999`, 1),
		strings.Replace(validBody, `"score":0.01`, `"score":null`, 1),
		strings.Replace(validBody, `"score":0.01`, `"score":"0.1"`, 1),
		strings.Replace(validBody, `"score":0.01`, `"score":NaN`, 1),
		strings.Replace(validBody, `"error-codes":[]`, `"error-codes":["timeout-or-duplicate"]`, 1),
		strings.Replace(validBody, `"success":true`, `"success":true,"succe\u0073s":false`, 1),
		strings.Replace(validBody, `"action":"account/signup"`, `"action":[]`, 1),
		strings.Replace(validBody, `"hostname":"example.com"`, `"hostname":null`, 1),
		`{"success":true,"apk_package_name":"synthetic.android"}`,
		`{"success":true,"tokenProperties":{}}`,
		`{"success":true,"score":0.1,"score":0.2}`,
		`{"success":null}`, `{"success":true`, validBody + `{}`, strings.Repeat(" ", 4097),
		`{"success":false,"error-codes":["provider message with sensitive data"]}`,
	} {
		var calls atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, captcha.ErrMalformedResponse) || got.Outcome != captcha.OutcomeMalformed || !got.ExpiresAt.IsZero() || calls.Load() != 1 {
			t.Fatal("hostile response usable/retried", err)
		}
	}
}

func TestRecaptchaPreservesCodeAvailabilityAndSafeUnknownWithoutGuessing(t *testing.T) {
	for _, tc := range []struct {
		code    string
		outcome captcha.Outcome
		cause   error
	}{
		{"missing-input-secret", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
		{"invalid-input-secret", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
		{"missing-input-response", captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{"invalid-input-response", captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{"bad-request", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
		{"timeout-or-duplicate", captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{"future-safe-code", captcha.OutcomeMalformed, captcha.ErrMalformedResponse},
	} {
		body := `{"success":false,"error-codes":["` + tc.code + `"]}`
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome != tc.outcome || !got.ExpiresAt.IsZero() || got.Evidence.Recaptcha == nil || !got.Evidence.Recaptcha.ErrorCodesAvailable || len(got.Evidence.Recaptcha.ErrorCodes) != 1 || got.Evidence.Recaptcha.ErrorCodes[0] != tc.code {
			t.Fatal("provider code distinction or custody lost", err)
		}
		if tc.code == "future-safe-code" && (len(got.Evidence.ReasonCodes) != 1 || got.Evidence.ReasonCodes[0] != "unknown-provider-code") {
			t.Fatal("unknown code escaped safe normalization")
		}
		if got.Evidence.ScoreAvailable || got.Evidence.Action.Available {
			t.Fatal("v2-shaped failure fabricated v3 fields")
		}
	}
	for _, body := range []string{strings.Replace(validBody, `,"error-codes":[]`, "", 1), validBody} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Evidence.Recaptcha.ErrorCodesAvailable != strings.Contains(body, "error-codes") {
			t.Fatal("absent/empty code list collapsed")
		}
		if _, err := json.Marshal(got.Evidence.Recaptcha); err == nil {
			t.Fatal("native evidence serialized")
		}
	}
}

func TestRecaptchaStatusAndAmbiguousIOAreBoundedWithoutRetry(t *testing.T) {
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

func TestRecaptchaClosesAndBoundsInfinitePartialAndOversizedBodies(t *testing.T) {
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

func TestRecaptchaVerifiedTLSDoesNotInheritCookiesHeadersOrRedirects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Host != "www.google.com" {
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
	u, _ := url.Parse("https://www.google.com")
	jar.SetCookies(u, []*http.Cookie{{Name: "synthetic", Value: "custody"}})
	owner.HTTPClient().Jar = jar
	owner.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { t.Error("borrowed redirect callback invoked"); return nil }
	p, err := recaptcha.New(config(), owner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	got, err := p.Verify(context.Background(), input(t))
	if err != nil || got.Outcome != captcha.OutcomeSolved || calls.Load() != 1 {
		t.Fatal("verified TLS path failed", err)
	}
}

func TestRecaptchaCloseCancelsDrainsAndRejectsSaturatedCalls(t *testing.T) {
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

func TestRecaptchaCancellationInputBoundsAndSecretOwnership(t *testing.T) {
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
	for _, mutate := range []func(*recaptcha.Config){func(c *recaptcha.Config) { c.Secret = make([]byte, 4097) }, func(c *recaptcha.Config) { c.Endpoint = "https://attacker.invalid/siteverify" }, func(c *recaptcha.Config) { c.Profile.Version = "v2" }, func(c *recaptcha.Config) { c.Profile.Tier = "enterprise" }, func(c *recaptcha.Config) { c.Profile.Provider = "turnstile" }, func(c *recaptcha.Config) { c.Profile.RemoteIPDisclosure = true }} {
		bad := config()
		mutate(&bad)
		if _, err := recaptcha.New(bad, owner, wallClock{time.Now().UTC()}); !errors.Is(err, captcha.ErrInvalidConfiguration) {
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

func TestRecaptchaDeadlineDuringResponseCleanupCannotPublishSolved(t *testing.T) {
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

func TestRecaptchaProviderTimeoutAndTelemetryDoNotRetainRawErrors(t *testing.T) {
	var observations atomic.Int32
	cfg := config()
	cfg.Observe = func(ctx context.Context, o recaptcha.Observation) {
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
