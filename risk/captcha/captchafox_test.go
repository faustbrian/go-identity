package captcha_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
)

func captchafoxProfile() captcha.Config {
	c := profile()
	c.Provider, c.API, c.Version, c.Tier, c.APIProfile = "captchafox", "siteverify", "2026-08-11", "free", "siteverify/free"
	c.ExpectedAction, c.ChallengeMaxAge = "", 5*time.Minute
	return c
}

func captchafoxSolved(c captcha.Config, r captcha.VerifyRequest) captcha.ProviderResult {
	got := solved(c, r)
	got.Evidence.Kind, got.Evidence.Turnstile, got.Evidence.CaptchaFox = captcha.EvidenceCaptchaFox, nil, &captcha.CaptchaFoxEvidence{}
	got.Evidence.Action = captcha.OptionalString{}
	return got
}

func TestNeutralCaptchaFoxFreeProjectsFactsWithoutInventedBindings(t *testing.T) {
	c := captchafoxProfile()
	n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
		return captchafoxSolved(c, r), nil
	}))
	if err != nil {
		t.Fatal("documented free profile rejected", err)
	}
	capabilities := c.Capabilities()
	if !capabilities.Hostname || !capabilities.ChallengeTime || capabilities.Action || capabilities.Score || capabilities.Origin || capabilities.ProviderIdempotency || capabilities.RemoteAddressDisclosure {
		t.Fatal("free profile capability fabricated")
	}
	r := request(t)
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: n.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Action.Available || fact.ScoreAvailable || fact.Origin.Available || fact.Site != c.SiteKey || !fact.ExpiresAt.Equal(c.Clock.Now().Add(c.Lifetime)) {
		t.Fatal("free profile callback lost original facts or invented bindings", err)
	}
	result, err := n.Verify(context.Background(), r)
	if err != nil || result.Evidence.ActionMatched || !result.Evidence.HostnameMatched || result.Evidence.CaptchaFox == nil {
		t.Fatal("unsupported action fabricated a match", err)
	}
}

func TestNeutralCaptchaFoxRejectsUnsupportedConfigurationAndEvidence(t *testing.T) {
	for _, mutate := range []func(*captcha.Config){func(c *captcha.Config) { c.ExpectedAction = "signup" }, func(c *captcha.Config) { c.Tier = "enterprise" }, func(c *captcha.Config) { c.Version = "unselected" }, func(c *captcha.Config) { c.APIProfile = "siteverify/enterprise" }, func(c *captcha.Config) { c.ExpectedCData = captcha.OptionalString{Available: true} }, func(c *captcha.Config) { c.RemoteIPDisclosure = true }} {
		c := captchafoxProfile()
		mutate(&c)
		if _, err := captcha.New(c, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
			t.Fatal("unsupported profile invoked provider")
			return captcha.ProviderResult{}, nil
		})); !errors.Is(err, captcha.ErrInvalidConfiguration) {
			t.Fatal("unsupported free configuration accepted", err)
		}
	}
	for _, mutate := range []func(*captcha.ProviderResult){func(r *captcha.ProviderResult) {
		r.Evidence.Action = captcha.OptionalString{Available: true, Value: "signup"}
	}, func(r *captcha.ProviderResult) { r.Evidence.ScoreAvailable = true; r.Evidence.Score = 0.9 }, func(r *captcha.ProviderResult) {
		r.Evidence.Origin = captcha.OptionalString{Available: true, Value: "https://example.com"}
	}, func(r *captcha.ProviderResult) { r.Evidence.HCaptcha = &captcha.HCaptchaEvidence{} }, func(r *captcha.ProviderResult) { r.Evidence.Hostname.Value = "example.com.attacker.invalid" }, func(r *captcha.ProviderResult) { r.Evidence.CaptchaFox.ErrorCodesAvailable = true }, func(r *captcha.ProviderResult) { r.Evidence.CaptchaFox.ErrorCodes = []string{"timeout-or-duplicate"} }} {
		c := captchafoxProfile()
		n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
			got := captchafoxSolved(c, r)
			mutate(&got)
			return got, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		got, err := n.Verify(context.Background(), request(t))
		if err == nil || got.Outcome == captcha.OutcomeSolved || !got.ExpiresAt.IsZero() {
			t.Fatal("unsupported free fields became usable", err)
		}
	}
}
