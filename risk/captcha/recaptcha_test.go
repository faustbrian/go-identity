package captcha_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
)

func recaptchaProfile() captcha.Config {
	c := profile()
	c.Provider, c.API, c.Version, c.Tier, c.APIProfile = "recaptcha", "classic_siteverify", "v3", "standard", "classic_siteverify/v3"
	c.ExpectedAction, c.ChallengeMaxAge = "account/signup", 2*time.Minute
	return c
}

func recaptchaSolved(c captcha.Config, r captcha.VerifyRequest) captcha.ProviderResult {
	got := solved(c, r)
	got.Evidence.Kind, got.Evidence.Turnstile, got.Evidence.Recaptcha = captcha.EvidenceRecaptcha, nil, &captcha.RecaptchaEvidence{}
	got.Evidence.Action.Value = c.ExpectedAction
	got.Evidence.ScoreAvailable, got.Evidence.Score = true, 0.01
	return got
}

func TestNeutralRecaptchaV3PreservesLowScoreWithoutPolicyDecision(t *testing.T) {
	c := recaptchaProfile()
	n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
		return recaptchaSolved(c, r), nil
	}))
	if err != nil {
		t.Fatal("documented v3 profile rejected", err)
	}
	capabilities := c.Capabilities()
	if !capabilities.Score || !capabilities.Hostname || !capabilities.Action || !capabilities.ChallengeTime || capabilities.ProviderIdempotency || capabilities.RemoteAddressDisclosure || capabilities.Origin {
		t.Fatal("wrong selected v3 capabilities")
	}
	r := request(t)
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: n.Observe}
	fact, err := issuer.Verify(context.Background(), r)
	if err != nil || fact.Outcome != risk.CaptchaSolved || !fact.ScoreAvailable || fact.Score != 0.01 || fact.Action.Value != "account/signup" || fact.Flow != r.Flow || fact.CommandID != r.CommandID || fact.Origin.Available || !fact.ExpiresAt.Equal(c.Clock.Now().Add(time.Minute)) {
		t.Fatal("v3 callback lost score/binding or renewed challenge validity", err)
	}
}

func TestNeutralRecaptchaV3RejectsMissingOrInvalidScoreAndForeignEnvelope(t *testing.T) {
	for _, mutate := range []func(*captcha.ProviderResult){
		func(r *captcha.ProviderResult) { r.Evidence.ScoreAvailable, r.Evidence.Score = false, 0 },
		func(r *captcha.ProviderResult) { r.Evidence.Score = math.NaN() },
		func(r *captcha.ProviderResult) { r.Evidence.Score = math.Inf(1) },
		func(r *captcha.ProviderResult) { r.Evidence.Score = -0.01 },
		func(r *captcha.ProviderResult) { r.Evidence.Score = 1.01 },
		func(r *captcha.ProviderResult) {
			r.Evidence.Recaptcha = nil
			r.Evidence.Turnstile = &captcha.TurnstileEvidence{}
			r.Evidence.Kind = captcha.EvidenceTurnstile
		},
	} {
		c := recaptchaProfile()
		n, err := captcha.New(c, providerFunc(func(_ context.Context, r captcha.VerifyRequest) (captcha.ProviderResult, error) {
			got := recaptchaSolved(c, r)
			mutate(&got)
			return got, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		r, err := n.Verify(context.Background(), request(t))
		if err == nil || r.Outcome == captcha.OutcomeSolved || !r.ExpiresAt.IsZero() {
			t.Fatal("invalid v3 envelope usable", err)
		}
	}
}

func TestNeutralRecaptchaRejectsUnimplementedProfilesAndProviderLifetime(t *testing.T) {
	for _, mutate := range []func(*captcha.Config){
		func(c *captcha.Config) { c.Version = "v2" },
		func(c *captcha.Config) { c.Tier = "enterprise" },
		func(c *captcha.Config) { c.API = "enterprise_assessment" },
		func(c *captcha.Config) {
			c.ExpectedCData = captcha.OptionalString{Available: true, Value: "unsupported"}
		},
		func(c *captcha.Config) { c.ExpectedAction = "unsupported-action" },
		func(c *captcha.Config) { c.ChallengeMaxAge = 2*time.Minute + time.Nanosecond },
		func(c *captcha.Config) { c.RemoteIPDisclosure = true },
	} {
		c := recaptchaProfile()
		mutate(&c)
		_, err := captcha.New(c, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
			t.Fatal("invalid profile invoked provider")
			return captcha.ProviderResult{}, nil
		}))
		if !errors.Is(err, captcha.ErrInvalidConfiguration) {
			t.Fatal("unsupported profile admitted", err)
		}
	}
}
