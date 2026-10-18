package turnstile_test

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
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/turnstile"
)

type wallClock struct{ now time.Time }

func (c wallClock) Now() time.Time { return c.now }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func config() turnstile.Config {
	return turnstile.Config{Endpoint: "https://challenges.cloudflare.com/turnstile/v0/siteverify", UserAgent: "golib-identity-synthetic-test", Secret: []byte("synthetic-provider-secret"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "turnstile", API: "siteverify", Version: "v0", Tier: "free", APIProfile: "siteverify/v0", SiteKey: "synthetic-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, ExpectedAction: "signup", ExpectedCData: captcha.OptionalString{Available: true, Value: "synthetic-cdata"}, MaxTokenBytes: 2048, MaxConcurrent: 4, Timeout: time.Second, Lifetime: 2 * time.Minute, ChallengeMaxAge: 5 * time.Minute}}
}

func input(t *testing.T) captcha.VerifyRequest {
	t.Helper()
	flow, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	return captcha.VerifyRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow, Token: []byte("synthetic-provider-token")}
}

const validBody = `{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com","action":"signup","cdata":"synthetic-cdata","error-codes":[]}`

func client(t *testing.T, cfg turnstile.Config, handler roundTripFunc) *turnstile.Client {
	t.Helper()
	httpOwner, err := httpclient.New(httpclient.Config{Transport: handler})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = httpOwner.Close() })
	provider, err := turnstile.New(cfg, httpOwner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := provider.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return provider
}

func response(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestPublicTurnstilePathPostsBoundedPrivateFormAndProjectsRiskFacts(t *testing.T) {
	var requests atomic.Int32
	var firstKey string
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		if r.Method != "POST" || r.URL.String() != "https://challenges.cloudflare.com/turnstile/v0/siteverify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("provider request escaped private form boundary")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal("bounded form malformed")
		}
		if len(r.PostForm) != 3 || r.PostForm.Get("secret") != "synthetic-provider-secret" || r.PostForm.Get("response") != "synthetic-provider-token" || r.PostForm.Has("remoteip") {
			t.Error("wrong provider custody or remote address disclosure")
		}
		key := r.PostForm.Get("idempotency_key")
		if len(key) != 36 || key[8] != '-' || key[13] != '-' || key[18] != '-' || key[23] != '-' {
			t.Error("provider key is not a UUID")
		}
		if firstKey == "" {
			firstKey = key
		} else if firstKey != key {
			t.Error("same logical request changed provider idempotency")
		}
		return response(r, validBody), nil
	})
	r := input(t)
	got, err := p.Verify(context.Background(), r)
	if err != nil || got.Outcome != captcha.OutcomeSolved || !got.Evidence.Success || !got.Evidence.HostnameMatched || !got.Evidence.ActionMatched || got.Evidence.Origin.Available || got.Evidence.ScoreAvailable || got.Evidence.Turnstile == nil || got.Evidence.Turnstile.CData.Value != "synthetic-cdata" || got.Flow != r.Flow || got.CommandID != r.CommandID {
		t.Fatal("public Turnstile result lost binding or native facts", err)
	}
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: p.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Provider != "turnstile" || fact.Site != "synthetic-site" || fact.Action.Value != "signup" || requests.Load() != 2 {
		t.Fatal("real provider path did not produce risk-owned facts", err)
	}
	if string(r.Token) != "synthetic-provider-token" {
		t.Fatal("borrowed token changed")
	}
	for _, rendered := range []string{fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got.Evidence), fmt.Sprintf("%v", config())} {
		if strings.Contains(rendered, "synthetic-provider-secret") || strings.Contains(rendered, "synthetic-provider-token") || strings.Contains(rendered, "synthetic-cdata") {
			t.Fatal("provider diagnostics leaked secret data")
		}
	}
}

func TestTurnstileRejectsMalformedCompleteResponsesWithoutRetry(t *testing.T) {
	for _, body := range []string{
		`{"success":true,"success":false}`, validBody + `{}`, `{"success":true,"unknown":"value"}`, `{"success":null}`, `{"success":false,"error-codes":["new-unknown-error"]}`, `{"success":true,"metadata":{"ephemeral_id":"synthetic-enterprise-only"}}`, strings.Repeat(" ", 4097), `{"success":true`,
	} {
		var requests atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { requests.Add(1); return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || requests.Load() != 1 {
			t.Fatal("malformed/unsupported response became usable or retried", err)
		}
	}
}

func TestTurnstileTransportFailureClassesAreNotSuccessOrAutomaticRetries(t *testing.T) {
	for _, tc := range []struct {
		status  int
		outcome captcha.Outcome
		cause   error
	}{
		{302, captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
		{429, captcha.OutcomeThrottled, captcha.ErrThrottled},
		{503, captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
	} {
		var requests atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			result := response(r, validBody)
			result.StatusCode = tc.status
			result.Header.Set("Location", "https://attacker.invalid/collect")
			return result, nil
		})
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome != tc.outcome || !got.ExpiresAt.IsZero() || requests.Load() != 1 {
			t.Fatal("HTTP failure became success or redirect/retry", err)
		}
	}
	var requests atomic.Int32
	p := client(t, config(), func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("synthetic-sensitive-secret-token-transport-diagnostic")
	})
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, captcha.ErrAmbiguousTransport) || got.Outcome != captcha.OutcomeAmbiguous || requests.Load() != 1 || strings.Contains(fmt.Sprintf("%+v", err), "synthetic-sensitive") {
		t.Fatal("ambiguous exchange lost classification or redaction", err)
	}
}

func TestTurnstilePreCancellationOversizeAndClosePerformNoProviderWork(t *testing.T) {
	var requests atomic.Int32
	p := client(t, config(), func(r *http.Request) (*http.Response, error) { requests.Add(1); return response(r, validBody), nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Verify(ctx, input(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancellation was lost", err)
	}
	r := input(t)
	r.Token = []byte(strings.Repeat("x", 2049))
	if _, err := p.Verify(context.Background(), r); !errors.Is(err, captcha.ErrInvalidToken) {
		t.Fatal("provider character limit not enforced before I/O", err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(context.Background(), input(t)); err == nil {
		t.Fatal("closed verifier accepted work")
	}
	if requests.Load() != 0 {
		t.Fatal("denied input performed provider work")
	}
}

func TestTurnstileAcceptsNonsecretHTTPUserAgentWithSpaces(t *testing.T) {
	cfg := config()
	cfg.UserAgent = "golib-identity-reference/example (+https://example.com/security)"
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("User-Agent") != cfg.UserAgent {
			t.Error("user-agent changed")
		}
		return response(r, validBody), nil
	})
	if _, err := p.Verify(context.Background(), input(t)); err != nil {
		t.Fatal("safe HTTP user-agent rejected", err)
	}
}

func TestTurnstileRealTLSFixtureDoesNotInheritCookiesOrRedirectPolicy(t *testing.T) {
	var calls, redirects atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host != "challenges.cloudflare.com" || r.URL.Path != "/turnstile/v0/siteverify" || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("TLS provider boundary inherited ambient state")
		}
		if err := r.ParseForm(); err != nil || len(r.PostForm) != 3 || r.PostForm.Has("remoteip") {
			t.Error("TLS request did not contain only the selected bounded fields")
		}
		w.Header().Set("Location", "https://attacker.invalid/collect")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	// Only dialing and the fixture certificate identity are rerouted. HTTPS,
	// certificate verification and the actual provider Host/URL remain in use.
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	httpOwner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	defer httpOwner.Close()
	jar, _ := cookiejar.New(nil)
	target, _ := url.Parse("https://challenges.cloudflare.com/")
	jar.SetCookies(target, []*http.Cookie{{Name: "synthetic-cookie", Value: "synthetic-cookie-value"}})
	httpOwner.HTTPClient().Jar = jar
	httpOwner.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { redirects.Add(1); return http.ErrUseLastResponse }
	p, err := turnstile.New(config(), httpOwner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	got, err := p.Verify(context.Background(), input(t))
	if !errors.Is(err, captcha.ErrProviderUnavailable) || got.Outcome != captcha.OutcomeUnavailable || calls.Load() != 1 || redirects.Load() != 0 {
		t.Fatal("redirect was followed or borrowed redirect callback inherited", err)
	}
}

func TestTurnstileCancellationDrainsOwnedExchangeAndCloseRejectsNewWork(t *testing.T) {
	entered := make(chan struct{})
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	r := input(t)
	go func() { _, err := p.Verify(context.Background(), r); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider exchange did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal("shutdown did not drain cooperative exchange", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled exchange became success")
		}
	case <-ctx.Done():
		t.Fatal("owned exchange leaked")
	}
	if _, err := p.Verify(context.Background(), r); err == nil {
		t.Fatal("shutdown accepted another exchange")
	}
}

type failingBody struct{ closed *atomic.Bool }

func (b failingBody) Read(p []byte) (int, error) { return copy(p, validBody), io.ErrUnexpectedEOF }
func (b failingBody) Close() error               { b.closed.Store(true); return nil }

type infiniteBody struct {
	count  *atomic.Int32
	closed *atomic.Bool
}

func (b infiniteBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	b.count.Add(int32(len(p)))
	return len(p), nil
}
func (b infiniteBody) Close() error { b.closed.Store(true); return nil }

func TestTurnstilePartialAndInfiniteBodiesStayBoundedAndClose(t *testing.T) {
	for _, partial := range []bool{true, false} {
		var read atomic.Int32
		var closed atomic.Bool
		p := client(t, config(), func(r *http.Request) (*http.Response, error) {
			resp := response(r, "")
			if partial {
				resp.Body = failingBody{&closed}
			} else {
				resp.Body = infiniteBody{&read, &closed}
			}
			return resp, nil
		})
		got, err := p.Verify(context.Background(), input(t))
		want := captcha.ErrMalformedResponse
		if partial {
			want = captcha.ErrAmbiguousTransport
		}
		if !errors.Is(err, want) || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || !closed.Load() {
			t.Fatal("incomplete body became usable or leaked cleanup", err)
		}
		if !partial && read.Load() != 4097 {
			t.Fatal("infinite response exceeded configured byte budget")
		}
	}
}

func TestTurnstileTransportIdempotencyScopesCommandTokenSiteAndConfiguration(t *testing.T) {
	seen := make(map[string]bool)
	for _, change := range []string{"base", "command", "token", "site", "configuration", "action", "cdata", "hostname"} {
		cfg := config()
		r := input(t)
		body := validBody
		switch change {
		case "command":
			r.CommandID = "AgICAgICAgICAgICAgICAg"
		case "token":
			r.Token = []byte("different-synthetic-token")
		case "site":
			cfg.Profile.SiteKey = "other-synthetic-site"
		case "configuration":
			cfg.Profile.ConfigurationVersion = "synthetic-v2"
		case "action":
			cfg.Profile.ExpectedAction = "reset"
			body = strings.Replace(body, `"signup"`, `"reset"`, 1)
		case "cdata":
			cfg.Profile.ExpectedCData.Value = "other-cdata"
			body = strings.Replace(body, `"synthetic-cdata"`, `"other-cdata"`, 1)
		case "hostname":
			cfg.Profile.Hostnames = []string{"other.example.com"}
			body = strings.Replace(body, `"example.com"`, `"other.example.com"`, 1)
		}
		p := client(t, cfg, func(req *http.Request) (*http.Response, error) {
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			key := req.PostForm.Get("idempotency_key")
			if key == "" || seen[key] {
				t.Error("distinct trusted provider scope reused a transport identity")
			}
			seen[key] = true
			return response(req, body), nil
		})
		if _, err := p.Verify(context.Background(), r); err != nil {
			t.Fatal("scoped provider request failed", err)
		}
	}
}

func TestTurnstileTransportIdempotencyBindsOriginalTrustedFlow(t *testing.T) {
	base := risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	authenticated := base
	authenticated.Kind, authenticated.Subject, authenticated.AnonymousFlow = risk.FlowAuthenticated, "synthetic-subject", ""
	authenticated.PreAuthTransaction, authenticated.Session = "", "synthetic-session"
	administrator := authenticated
	administrator.Kind, administrator.Actor = risk.FlowAdministrator, "synthetic-administrator"
	seen := make(map[string]string)
	for _, tc := range []struct {
		name   string
		base   risk.FlowContextInput
		change func(*risk.FlowContextInput)
	}{
		{"preauth", base, func(*risk.FlowContextInput) {}},
		{"tenant", base, func(f *risk.FlowContextInput) { f.Tenant = "other-tenant" }},
		{"operation", base, func(f *risk.FlowContextInput) { f.Operation = "identity.password.signin" }},
		{"anonymous", base, func(f *risk.FlowContextInput) { f.AnonymousFlow = "other-flow" }},
		{"transaction", base, func(f *risk.FlowContextInput) { f.PreAuthTransaction = "other-preauth" }},
		{"challenge", base, func(f *risk.FlowContextInput) { f.ChallengeID = "other-challenge" }},
		{"intent", base, func(f *risk.FlowContextInput) { f.RequestFingerprint = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" }},
		{"authenticated", authenticated, func(*risk.FlowContextInput) {}},
		{"subject", authenticated, func(f *risk.FlowContextInput) { f.Subject = "other-subject" }},
		{"session", authenticated, func(f *risk.FlowContextInput) { f.Session = "other-session" }},
		{"administrator", administrator, func(*risk.FlowContextInput) {}},
		{"actor", administrator, func(f *risk.FlowContextInput) { f.Actor = "other-administrator" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.base
			tc.change(&in)
			flow, err := risk.NewFlowContext(in)
			if err != nil {
				t.Fatal(err)
			}
			r := input(t)
			r.Flow = flow // Command, provider profile and token stay identical.
			var original string
			p := client(t, config(), func(req *http.Request) (*http.Response, error) {
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				key := req.PostForm.Get("idempotency_key")
				if other, exists := seen[key]; exists && other != tc.name {
					t.Errorf("changed trusted flow reused transport identity from %s", other)
				}
				if original != "" && original != key {
					t.Error("same original flow changed transport identity")
				}
				original, seen[key] = key, tc.name
				return response(req, validBody), nil
			})
			for range 2 {
				if _, err := p.Verify(context.Background(), r); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestTurnstileAdmissionIsBoundedAndCallerCancellationDoesNotQueue(t *testing.T) {
	cfg := config()
	cfg.Profile.MaxConcurrent = 1
	entered := make(chan struct{})
	var calls atomic.Int32
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := input(t)
	done := make(chan error, 1)
	go func() { _, err := p.Verify(ctx, first); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first verification did not start")
	}
	if _, err := p.Verify(context.Background(), input(t)); !errors.Is(err, captcha.ErrOverloaded) {
		t.Fatal("saturated verifier accepted another request", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("caller cancellation lost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled verification leaked")
	}
	if calls.Load() != 1 {
		t.Fatal("saturation queued or bypassed provider admission")
	}
}

func TestTurnstileSecretByteBoundAndBorrowedCopy(t *testing.T) {
	httpOwner, err := httpclient.New(httpclient.Config{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid construction performed provider work")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer httpOwner.Close()
	cfg := config()
	cfg.Secret = []byte(strings.Repeat("x", 4097))
	if _, err := turnstile.New(cfg, httpOwner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}); !errors.Is(err, captcha.ErrInvalidConfiguration) {
		t.Fatal("unbounded provider secret accepted", err)
	}
	cfg = config()
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("secret") != "synthetic-provider-secret" {
			t.Error("caller mutation changed owned secret custody")
		}
		return response(r, validBody), nil
	})
	clear(cfg.Secret)
	if _, err := p.Verify(context.Background(), input(t)); err != nil {
		t.Fatal("owned secret copy was not retained", err)
	}
}

func TestTurnstileMismatchExpiryAndProviderRejectionPreserveBoundedNativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		body    string
		outcome captcha.Outcome
		cause   error
	}{
		{strings.Replace(validBody, `"example.com"`, `"example.com.attacker.invalid"`, 1), captcha.OutcomeBindingMismatch, captcha.ErrBindingMismatch},
		{strings.Replace(validBody, `"signup"`, `"reset"`, 1), captcha.OutcomeBindingMismatch, captcha.ErrBindingMismatch},
		{strings.Replace(validBody, `"synthetic-cdata"`, `"foreign-cdata"`, 1), captcha.OutcomeBindingMismatch, captcha.ErrBindingMismatch},
		{strings.Replace(validBody, "11:59:30Z", "11:55:00Z", 1), captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{strings.Replace(validBody, "11:59:30Z", "12:00:01Z", 1), captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{`{"success":false,"error-codes":["timeout-or-duplicate"]}`, captcha.OutcomeRejected, captcha.ErrInvalidToken},
		{`{"success":false,"error-codes":["internal-error"]}`, captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable},
	} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, tc.body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome != tc.outcome || got.Evidence.Turnstile == nil || !got.ExpiresAt.IsZero() {
			t.Fatal("provider failure lost its classified native evidence", err)
		}
	}
}
