package captchafox_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/captchafox"
)

type wallClock struct{ now time.Time }

func (c wallClock) Now() time.Time { return c.now }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func config() captchafox.Config {
	return captchafox.Config{Endpoint: "https://api.captchafox.com/siteverify", UserAgent: "golib synthetic test", Secret: []byte("synthetic-provider-secret"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "captchafox", API: "siteverify", Version: "2026-08-11", Tier: "free", APIProfile: "siteverify/free", SiteKey: "synthetic-configured-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, MaxTokenBytes: 2048, MaxConcurrent: 4, Timeout: time.Second, Lifetime: 2 * time.Minute, ChallengeMaxAge: 2 * time.Minute}}
}
func input(t *testing.T) captcha.VerifyRequest {
	t.Helper()
	flow, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	return captcha.VerifyRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow, Token: []byte("synthetic-provider-token")}
}

const validBody = `{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com"}`

func response(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func client(t *testing.T, cfg captchafox.Config, h roundTripFunc) *captchafox.Client {
	t.Helper()
	owner, err := httpclient.New(httpclient.Config{Transport: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	p, err := captchafox.New(cfg, owner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
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

func TestPublicCaptchaFoxPostsExpectedSiteAndProjectsOriginalRiskFacts(t *testing.T) {
	var calls atomic.Int32
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.String() != "https://api.captchafox.com/siteverify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("provider endpoint/form privacy wrong")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if len(r.PostForm) != 3 || r.PostForm.Get("secret") != "synthetic-provider-secret" || r.PostForm.Get("response") != "synthetic-provider-token" || r.PostForm.Get("sitekey") != "synthetic-configured-site" || r.PostForm.Has("remoteIp") || r.PostForm.Has("remoteip") || r.PostForm.Has("idempotency_key") || r.PostForm.Has("action") {
			t.Error("configured site binding or privacy lost")
		}
		return response(r, validBody), nil
	})
	r := input(t)
	got, err := p.Verify(context.Background(), r)
	if err != nil || got.Outcome != captcha.OutcomeSolved || !got.Evidence.Success || !got.Evidence.HostnameMatched || got.Evidence.ActionMatched || got.Evidence.Action.Available || got.Evidence.ScoreAvailable || got.Evidence.Origin.Available || got.Evidence.CaptchaFox == nil {
		t.Fatal("free provider facts lost or unsupported bindings fabricated", err)
	}
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: p.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Provider != "captchafox" || fact.Site != "synthetic-configured-site" || fact.API != "siteverify" || fact.Version != "2026-08-11" || fact.Tier != "free" || fact.Action.Available || fact.ScoreAvailable || !fact.ExpiresAt.Equal(time.Date(2026, 10, 18, 12, 1, 30, 0, time.UTC)) || calls.Load() != 2 {
		t.Fatal("actual callback lost original binding/profile/expiry", err)
	}
	if string(r.Token) != "synthetic-provider-token" {
		t.Fatal("borrowed token changed")
	}
}

func TestCaptchaFoxDocumentedErrorsAndUnknownCodesAreUnusable(t *testing.T) {
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
		{"invalid-ip-match", captcha.OutcomeBindingMismatch, captcha.ErrBindingMismatch},
		{"future-safe-code", captcha.OutcomeMalformed, captcha.ErrMalformedResponse},
	} {
		body := `{"success":false,"error-codes":["` + tc.code + `"]}`
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome != tc.outcome || !got.ExpiresAt.IsZero() || got.Evidence.CaptchaFox == nil || len(got.Evidence.CaptchaFox.ErrorCodes) != 1 || got.Evidence.CaptchaFox.ErrorCodes[0] != tc.code || got.Evidence.Action.Available || got.Evidence.ScoreAvailable {
			t.Fatal("documented error attribution/classification lost", err)
		}
	}
}

func TestCaptchaFoxOptionalAvailabilityAndUnsupportedFields(t *testing.T) {
	for _, body := range []string{`{"success":false}`, `{"success":false,"hostname":"","error-codes":[]}`} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, captcha.ErrInvalidToken) || got.Outcome != captcha.OutcomeRejected || got.Evidence.CaptchaFox == nil || got.Evidence.CaptchaFox.ErrorCodesAvailable != strings.Contains(body, "error-codes") || got.Evidence.Hostname.Available != strings.Contains(body, "hostname") || got.Evidence.ChallengeTime.Available {
			t.Fatal("optional native fields collapsed or negative became usable", err)
		}
	}
	for _, body := range []string{`{"success":null}`, `{"success":true,"success":false}`, `{"success":true,"succe\u0073s":false}`, `{"success":true`, validBody + `{}`, strings.Repeat(" ", 4097), strings.TrimSuffix(validBody, "}") + `,"error-codes":[]}`, strings.TrimSuffix(validBody, "}") + `,"error-codes":["timeout-or-duplicate"]}`, `{"success":false,"challenge_ts":"2026-10-18T11:59:30Z"}`, `{"success":false,"error-codes":["unsafe diagnostic text"]}`, `{"success":true,"sitekey":"synthetic-configured-site"}`, `{"success":true,"action":"signup"}`, `{"success":true,"score":0.9}`, `{"success":true,"insights":{}}`, `{"success":true,"origin":"https://example.com"}`, `{"success":true,"credit":true}`, `{"success":true,"unknown":{}}`} {
		var calls atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err == nil || got.Outcome != captcha.OutcomeMalformed || !got.ExpiresAt.IsZero() || calls.Load() != 1 {
			t.Fatal("unsupported or inconsistent free response accepted/retried", err)
		}
	}
}

func TestCaptchaFoxChallengeBudgetIsExplicitLocalPolicyNotBorrowedProviderTTL(t *testing.T) {
	cfg := config()
	cfg.Profile.ChallengeMaxAge = 5 * time.Minute
	p := client(t, cfg, func(r *http.Request) (*http.Response, error) {
		return response(r, strings.Replace(validBody, "11:59:30", "11:57:00", 1)), nil
	})
	got, err := p.Verify(context.Background(), input(t))
	if err != nil || got.Outcome != captcha.OutcomeSolved || !got.ExpiresAt.Equal(time.Date(2026, 10, 18, 12, 2, 0, 0, time.UTC)) {
		t.Fatal("configured local challenge/lifetime budget changed", err)
	}
}

func TestCaptchaFoxExactHostAndOriginalChallengeTimeAreRequiredLocally(t *testing.T) {
	for _, body := range []string{strings.Replace(validBody, "example.com", "example.com.attacker.invalid", 1), strings.Replace(validBody, "example.com", "EXAMPLE.COM", 1), strings.Replace(validBody, "example.com", "example.com:443", 1), strings.Replace(validBody, "example.com", "éxample.com", 1), strings.Replace(validBody, "11:59:30", "11:58:00", 1), strings.Replace(validBody, "11:59:30", "12:00:01", 1), strings.Replace(validBody, `,"hostname":"example.com"`, "", 1), strings.Replace(validBody, `"challenge_ts":"2026-10-18T11:59:30Z",`, "", 1)} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || got.Evidence.CaptchaFox == nil {
			t.Fatal("missing or invalid binding/time usable or attribution lost", err)
		}
	}
}

func TestCaptchaFoxResultConfigAndNativeDiagnosticsAreRedacted(t *testing.T) {
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		return response(r, `{"success":false,"error-codes":["future-safe-code"]}`), nil
	})
	got, err := p.Verify(context.Background(), input(t))
	for _, v := range []any{got, got.Evidence, got.Evidence.CaptchaFox, config(), err} {
		text := fmt.Sprintf("%#v", v)
		if strings.Contains(text, "future-safe-code") || strings.Contains(text, "synthetic-provider-") {
			t.Fatal("automatic diagnostics disclosed provider custody")
		}
	}
	if _, err := json.Marshal(got.Evidence.CaptchaFox); err == nil {
		t.Fatal("native evidence automatically serialized")
	}
}
