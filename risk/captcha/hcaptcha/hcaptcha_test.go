package hcaptcha_test

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
	"github.com/faustbrian/go-identity/risk/captcha/hcaptcha"
)

type wallClock struct{ now time.Time }

func (c wallClock) Now() time.Time { return c.now }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func config() hcaptcha.Config {
	return hcaptcha.Config{Endpoint: "https://api.hcaptcha.com/siteverify", UserAgent: "golib synthetic test", Secret: []byte("synthetic-provider-secret"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "hcaptcha", API: "siteverify", Version: "2026-08-11", Tier: "publisher_pro", APIProfile: "siteverify/publisher_pro", SiteKey: "synthetic-configured-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, MaxTokenBytes: 2048, MaxConcurrent: 4, Timeout: time.Second, Lifetime: 2 * time.Minute, ChallengeMaxAge: 2 * time.Minute}}
}
func input(t *testing.T) captcha.VerifyRequest {
	t.Helper()
	flow, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	return captcha.VerifyRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow, Token: []byte("synthetic-provider-token")}
}

const validBody = `{"success":true,"challenge_ts":"2026-10-18T11:59:30Z","hostname":"example.com","credit":false,"error-codes":[]}`

func response(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func client(t *testing.T, cfg hcaptcha.Config, h roundTripFunc) *hcaptcha.Client {
	t.Helper()
	owner, err := httpclient.New(httpclient.Config{Transport: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	p, err := hcaptcha.New(cfg, owner, wallClock{time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)})
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

func TestPublicHCaptchaPostsExpectedSiteAndProjectsNoActionRiskFacts(t *testing.T) {
	var calls atomic.Int32
	p := client(t, config(), func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.String() != "https://api.hcaptcha.com/siteverify" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("provider request escaped fixed private form")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if len(r.PostForm) != 3 || r.PostForm.Get("secret") != "synthetic-provider-secret" || r.PostForm.Get("response") != "synthetic-provider-token" || r.PostForm.Get("sitekey") != "synthetic-configured-site" || r.PostForm.Has("remoteip") || r.PostForm.Has("idempotency_key") || r.PostForm.Has("action") {
			t.Error("expected-site binding/custody or privacy wrong")
		}
		return response(r, validBody), nil
	})
	r := input(t)
	got, err := p.Verify(context.Background(), r)
	if err != nil || got.Outcome != captcha.OutcomeSolved || !got.Evidence.Success || !got.Evidence.HostnameMatched || got.Evidence.ActionMatched || got.Evidence.Action.Available || got.Evidence.ScoreAvailable || got.Evidence.Origin.Available || got.Evidence.HCaptcha == nil || !got.Evidence.HCaptcha.CreditAvailable || got.Evidence.HCaptcha.Credit || got.Evidence.HCaptcha.ReturnedSiteKey.Available || !got.Evidence.HCaptcha.ErrorCodesAvailable || got.Evidence.HCaptcha.ScoreReasonsAvailable {
		t.Fatal("publisher facts lost or unsupported fields fabricated", err)
	}
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: p.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Provider != "hcaptcha" || fact.Site != "synthetic-configured-site" || fact.API != "siteverify" || fact.Version != "2026-08-11" || fact.Tier != "publisher_pro" || fact.Action.Available || fact.ScoreAvailable || !fact.ExpiresAt.Equal(time.Date(2026, 10, 18, 12, 1, 30, 0, time.UTC)) || calls.Load() != 2 {
		t.Fatal("actual callback lost original profile/flow/validity", err)
	}
	for _, v := range []any{got, got.Evidence, got.Evidence.HCaptcha, config()} {
		if strings.Contains(fmt.Sprintf("%#v", v), "synthetic-provider-") {
			t.Fatal("automatic custody diagnostics disclosed")
		}
	}
	if _, err := json.Marshal(got.Evidence.HCaptcha); err == nil {
		t.Fatal("native custody serialized")
	}
	if string(r.Token) != "synthetic-provider-token" {
		t.Fatal("borrowed token changed")
	}
}

func TestHCaptchaOptionalCreditAndCodesRemainAbsentVersusPresent(t *testing.T) {
	for _, body := range []string{validBody, strings.Replace(validBody, `,"credit":false`, "", 1), strings.Replace(validBody, `"credit":false`, `"credit":true`, 1), strings.Replace(validBody, `,"error-codes":[]`, "", 1)} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err != nil {
			t.Fatal(err)
		}
		e := got.Evidence.HCaptcha
		if e == nil || e.CreditAvailable != strings.Contains(body, "credit") || e.Credit != strings.Contains(body, `"credit":true`) || e.ErrorCodesAvailable != strings.Contains(body, "error-codes") || e.ReturnedSiteKey.Available || e.ReturnedSiteKey.Value != "" {
			t.Fatal("optional evidence collapsed or configured site fabricated returned proof")
		}
	}
}

func TestHCaptchaHostAndOriginalChallengeBindingsFailClosed(t *testing.T) {
	for _, body := range []string{strings.Replace(validBody, "example.com", "example.com.attacker.invalid", 1), strings.Replace(validBody, "example.com", "not-provided", 1), strings.Replace(validBody, "example.com", "EXAMPLE.COM", 1), strings.Replace(validBody, "example.com", "example.com:443", 1), strings.Replace(validBody, "example.com", "éxample.com", 1), strings.Replace(validBody, "11:59:30", "11:58:00", 1), strings.Replace(validBody, "11:59:30", "12:00:01", 1), strings.Replace(validBody, `"challenge_ts":"2026-10-18T11:59:30Z",`, "", 1)} {
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || got.Evidence.HCaptcha == nil {
			t.Fatal("invalid binding/challenge usable or attribution discarded", err)
		}
	}
}

func TestHCaptchaPreservesDocumentedNegativeClassesAndUnknownSafeCodes(t *testing.T) {
	for _, tc := range []struct {
		code    string
		outcome captcha.Outcome
		cause   error
	}{
		{"missing-input-secret", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable}, {"invalid-input-secret", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable}, {"missing-input-response", captcha.OutcomeRejected, captcha.ErrInvalidToken}, {"invalid-input-response", captcha.OutcomeRejected, captcha.ErrInvalidToken}, {"expired-input-response", captcha.OutcomeRejected, captcha.ErrInvalidToken}, {"already-seen-response", captcha.OutcomeRejected, captcha.ErrInvalidToken}, {"bad-request", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable}, {"missing-remoteip", captcha.OutcomeUnsupported, captcha.ErrUnsupported}, {"invalid-remoteip", captcha.OutcomeUnsupported, captcha.ErrUnsupported}, {"not-using-dummy-passcode", captcha.OutcomeUnavailable, captcha.ErrProviderUnavailable}, {"sitekey-secret-mismatch", captcha.OutcomeBindingMismatch, captcha.ErrBindingMismatch}, {"future-safe-code", captcha.OutcomeMalformed, captcha.ErrMalformedResponse},
	} {
		body := `{"success":false,"error-codes":["` + tc.code + `"]}`
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if !errors.Is(err, tc.cause) || got.Outcome != tc.outcome || !got.ExpiresAt.IsZero() || got.Evidence.HCaptcha == nil || len(got.Evidence.HCaptcha.ErrorCodes) != 1 || got.Evidence.HCaptcha.ErrorCodes[0] != tc.code || got.Evidence.Action.Available || got.Evidence.ScoreAvailable {
			t.Fatal("provider code classification/availability lost", err)
		}
		if tc.code == "future-safe-code" && (len(got.Evidence.ReasonCodes) != 1 || got.Evidence.ReasonCodes[0] != "unknown-provider-code") {
			t.Fatal("unknown code escaped normalized classification")
		}
	}
}

func TestHCaptchaRejectsHostileAndUndocumentedFieldsWithoutRetry(t *testing.T) {
	for _, body := range []string{`{"success":null}`, `{"success":true,"success":false}`, `{"success":true,"succe\u0073s":false}`, `{"success":true`, validBody + `{}`, strings.Repeat(" ", 4097), strings.Replace(validBody, `"credit":false`, `"credit":null`, 1), strings.Replace(validBody, `"credit":false`, `"credit":"false"`, 1), strings.Replace(validBody, `"error-codes":[]`, `"error-codes":["already-seen-response"]`, 1), `{"success":false,"error-codes":["unsafe diagnostic text"]}`, `{"success":true,"sitekey":"synthetic-configured-site"}`, `{"success":true,"action":"signup"}`, `{"success":true,"score":0.9}`, `{"success":true,"score_reason":["safe"]}`, `{"success":true,"origin":"https://example.com"}`, `{"success":true,"unknown":{}}`} {
		var calls atomic.Int32
		p := client(t, config(), func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(r, body), nil })
		got, err := p.Verify(context.Background(), input(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() || calls.Load() != 1 {
			t.Fatal("unsupported/hostile publisher response accepted/retried", err)
		}
	}
}
