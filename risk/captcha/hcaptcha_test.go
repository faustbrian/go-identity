package captcha_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
)

func hcaptchaProfile() captcha.Config {
	c := profile()
	c.Provider, c.API, c.Version, c.Tier, c.APIProfile = "hcaptcha", "siteverify", "2026-08-11", "publisher_pro", "siteverify/publisher_pro"
	c.ExpectedAction, c.ChallengeMaxAge = "", 2*time.Minute
	return c
}

func hcaptchaSolved(c captcha.Config, r captcha.VerifyRequest) captcha.ProviderResult {
	got := solved(c, r)
	got.Evidence.Kind, got.Evidence.Turnstile, got.Evidence.HCaptcha = captcha.EvidenceHCaptcha, nil, &captcha.HCaptchaEvidence{}
	got.Evidence.Action = captcha.OptionalString{}
	return got
}

func TestNeutralHCaptchaPublisherProWithoutInventedActionOrScore(t *testing.T) {
	c := hcaptchaProfile()
	n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
		return hcaptchaSolved(c, r), nil
	}))
	if err != nil {
		t.Fatal("documented publisher profile rejected", err)
	}
	capabilities := c.Capabilities()
	if !capabilities.Hostname || !capabilities.ChallengeTime || capabilities.Action || capabilities.Score || capabilities.Origin || capabilities.ProviderIdempotency || capabilities.RemoteAddressDisclosure {
		t.Fatal("publisher capability fabricated")
	}
	r := request(t)
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: n.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Action.Available || fact.ScoreAvailable || fact.Origin.Available || fact.Site != c.SiteKey || !fact.ExpiresAt.Equal(c.Clock.Now().Add(time.Minute)) {
		t.Fatal("publisher facts lost or unsupported action/score required", err)
	}
	result, err := n.Verify(context.Background(), r)
	if err != nil || result.Evidence.ActionMatched || !result.Evidence.HostnameMatched || result.Evidence.HCaptcha == nil {
		t.Fatal("missing action fabricated a match", err)
	}
}

func TestNeutralHCaptchaRejectsUnsupportedPublisherFieldsAndProfiles(t *testing.T) {
	for _, mutate := range []func(*captcha.Config){func(c *captcha.Config) { c.ExpectedAction = "signup" }, func(c *captcha.Config) { c.Tier = "enterprise" }, func(c *captcha.Config) { c.Version = "unselected" }, func(c *captcha.Config) { c.ExpectedCData = captcha.OptionalString{Available: true} }, func(c *captcha.Config) { c.RemoteIPDisclosure = true }, func(c *captcha.Config) { c.ChallengeMaxAge = 2*time.Minute + time.Nanosecond }} {
		c := hcaptchaProfile()
		mutate(&c)
		if _, err := captcha.New(c, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
			t.Fatal("invalid profile invoked provider")
			return captcha.ProviderResult{}, nil
		})); !errors.Is(err, captcha.ErrInvalidConfiguration) {
			t.Fatal("unsupported publisher config accepted", err)
		}
	}
	for _, mutate := range []func(*captcha.ProviderResult){func(r *captcha.ProviderResult) {
		r.Evidence.Action = captcha.OptionalString{Available: true, Value: "signup"}
	}, func(r *captcha.ProviderResult) { r.Evidence.ScoreAvailable = true; r.Evidence.Score = 0.9 }, func(r *captcha.ProviderResult) {
		r.Evidence.Origin = captcha.OptionalString{Available: true, Value: "https://example.com"}
	}, func(r *captcha.ProviderResult) { r.Evidence.Turnstile = &captcha.TurnstileEvidence{} }, func(r *captcha.ProviderResult) { r.Evidence.Hostname.Value = "example.com.attacker.invalid" }} {
		c := hcaptchaProfile()
		n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
			got := hcaptchaSolved(c, r)
			mutate(&got)
			return got, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		got, err := n.Verify(context.Background(), request(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() {
			t.Fatal("foreign publisher facts usable", err)
		}
	}
}

func TestNeutralHCaptchaCannotBindMissingHostnameSentinel(t *testing.T) {
	c := hcaptchaProfile()
	c.Hostnames = []string{"not-provided"}
	if _, err := captcha.New(c, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
		t.Fatal("missing-hostname sentinel reached provider")
		return captcha.ProviderResult{}, nil
	})); !errors.Is(err, captcha.ErrInvalidConfiguration) {
		t.Fatal("provider missing-hostname sentinel accepted as a configured binding", err)
	}
}
