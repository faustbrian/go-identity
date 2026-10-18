package captcha_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type cancellingClock struct {
	fixedClock
	cancel context.CancelFunc
}

func (c cancellingClock) Now() time.Time { c.cancel(); return c.at }

type providerFunc func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error)

func (f providerFunc) Verify(ctx context.Context, request captcha.VerifyRequest) (captcha.ProviderResult, error) {
	return f(ctx, request)
}

func profile() captcha.Config {
	return captcha.Config{Provider: "turnstile", API: "siteverify", Version: "v0", Tier: "free", APIProfile: "siteverify/v0", SiteKey: "synthetic-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, ExpectedAction: "signup", MaxTokenBytes: 2048, MaxConcurrent: 4, Timeout: 5 * time.Second, Lifetime: 2 * time.Minute, ChallengeMaxAge: 5 * time.Minute, Clock: fixedClock{time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}}
}

func request(t *testing.T) captcha.VerifyRequest {
	t.Helper()
	flow, err := risk.NewFlowContext(risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "synthetic-tenant", Operation: "identity.password.signup", AnonymousFlow: "synthetic-flow", PreAuthTransaction: "synthetic-preauth", ChallengeID: "synthetic-challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	return captcha.VerifyRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: flow, Token: []byte("synthetic-token")}
}

func solved(config captcha.Config, request captcha.VerifyRequest) captcha.ProviderResult {
	at := config.Clock.Now()
	return captcha.ProviderResult{CommandID: request.CommandID, Flow: request.Flow, Outcome: captcha.OutcomeSolved, ObservedAt: at, ExpiresAt: at.Add(config.Lifetime), Evidence: captcha.ProviderEvidence{Provider: config.Provider, API: config.API, Version: config.Version, Tier: config.Tier, APIProfile: config.APIProfile, SiteKey: config.SiteKey, ConfigurationVersion: config.ConfigurationVersion, Kind: captcha.EvidenceTurnstile, Success: true, Hostname: captcha.OptionalString{Available: true, Value: "example.com"}, Action: captcha.OptionalString{Available: true, Value: "signup"}, ChallengeTime: captcha.OptionalTime{Available: true, Value: at.Add(-time.Minute)}, Turnstile: &captcha.TurnstileEvidence{}}}
}

func TestPublicNeutralCallbackPreservesOriginalRiskBindingAndValidity(t *testing.T) {
	config := profile()
	input := request(t)
	verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
		if actual.Flow != input.Flow || actual.CommandID != input.CommandID || string(actual.Token) != "synthetic-token" {
			t.Fatal("neutral verifier changed trusted custody")
		}
		return solved(config, actual), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	// This assignment proves compatibility with the actual committed issuer seam.
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: verifier.Observe}
	fact, err := issuer.Verify(context.Background(), input)
	if err != nil || fact.Flow != input.Flow || fact.CommandID != input.CommandID || fact.Outcome != risk.CaptchaSolved || fact.Provider != config.Provider || fact.Site != config.SiteKey || fact.APIProfile != config.APIProfile || fact.ConfigurationVersion != config.ConfigurationVersion || !fact.Hostname.Available || fact.Hostname.Value != "example.com" || fact.Origin.Available || fact.ScoreAvailable || !fact.ExpiresAt.Equal(config.Clock.Now().Add(config.Lifetime)) {
		t.Fatal("neutral callback lost provider facts or original binding", err)
	}
	if string(input.Token) != "synthetic-token" {
		t.Fatal("borrowed token changed")
	}
}

func TestNeutralRejectsIncompatibleProviderAndBindingWithoutDiscardingNativeFacts(t *testing.T) {
	for _, change := range []func(*captcha.ProviderResult){
		func(r *captcha.ProviderResult) { r.Evidence.Provider = "hcaptcha" },
		func(r *captcha.ProviderResult) { r.Evidence.SiteKey = "foreign-site" },
		func(r *captcha.ProviderResult) { r.Evidence.ConfigurationVersion = "foreign-version" },
		func(r *captcha.ProviderResult) { r.Evidence.Hostname.Value = "example.com.attacker.invalid" },
		func(r *captcha.ProviderResult) { r.Evidence.Action.Value = "reset" },
		func(r *captcha.ProviderResult) { r.CommandID = "AgICAgICAgICAgICAgICAg" },
	} {
		config := profile()
		verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
			result := solved(config, actual)
			change(&result)
			return result, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := verifier.Verify(context.Background(), request(t))
		if !errors.Is(err, captcha.ErrBindingMismatch) || result.Outcome != captcha.OutcomeBindingMismatch || result.Evidence.Turnstile == nil {
			t.Fatal("incompatible solved evidence was accepted or its bounded native facts lost", err)
		}
		fact, err := verifier.Observe(context.Background(), request(t))
		if err == nil || fact.Outcome == risk.CaptchaSolved || !fact.ExpiresAt.IsZero() {
			t.Fatal("mismatch became usable risk evidence")
		}
	}
}

func TestNeutralCancellationAndProviderErrorCannotYieldSolvedFacts(t *testing.T) {
	config := profile()
	ctx, cancel := context.WithCancel(context.Background())
	verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
		cancel()
		return solved(config, actual), errors.New("synthetic-sensitive-provider-diagnostic")
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(ctx, request(t))
	if !errors.Is(err, context.Canceled) || result.Outcome != captcha.OutcomeCancelled || !result.ExpiresAt.IsZero() {
		t.Fatal("cancelled success was usable", err)
	}
}

func TestNeutralNeverRetainsContradictoryNativeUnionOnFailurePaths(t *testing.T) {
	for _, path := range []string{"success", "provider-error", "cancelled", "binding-mismatch"} {
		for _, shape := range []string{"multiple", "missing", "wrong-discriminator", "unknown-discriminator"} {
			t.Run(path+"/"+shape, func(t *testing.T) {
				config := profile()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
					r := solved(config, actual)
					switch shape {
					case "multiple":
						r.Evidence.HCaptcha = &captcha.HCaptchaEvidence{}
					case "missing":
						r.Evidence.Turnstile = nil
					case "wrong-discriminator":
						r.Evidence.Kind = captcha.EvidenceHCaptcha
					case "unknown-discriminator":
						r.Evidence.Kind = 255
					}
					switch path {
					case "provider-error":
						return r, &captcha.VerifyError{Failure: captcha.Failure{Outcome: captcha.OutcomeUnavailable}, Cause: captcha.ErrProviderUnavailable}
					case "cancelled":
						cancel()
					case "binding-mismatch":
						r.Evidence.SiteKey = "other-site"
					}
					return r, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				r, err := verifier.Verify(ctx, request(t))
				want := captcha.ErrMalformedResponse
				if path == "cancelled" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || !r.ExpiresAt.IsZero() || r.Evidence.Kind != 0 || r.Evidence.Turnstile != nil || r.Evidence.HCaptcha != nil || r.Evidence.Recaptcha != nil || r.Evidence.CaptchaFox != nil {
					t.Fatal("structurally invalid native evidence escaped on failure", err)
				}
			})
		}
	}
}

func TestNeutralRejectsContradictoryAndUnknownOutcomes(t *testing.T) {
	for _, change := range []func(*captcha.ProviderResult){
		func(r *captcha.ProviderResult) { r.Outcome = 0 },
		func(r *captcha.ProviderResult) { r.Outcome = 255 },
		func(r *captcha.ProviderResult) { r.Evidence.Success = false },
		func(r *captcha.ProviderResult) { r.Outcome = captcha.OutcomeRejected },
	} {
		config := profile()
		verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
			result := solved(config, actual)
			change(&result)
			return result, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := verifier.Verify(context.Background(), request(t))
		if !errors.Is(err, captcha.ErrMalformedResponse) || result.Outcome != captcha.OutcomeMalformed || !result.ExpiresAt.IsZero() {
			t.Fatal("contradictory provider outcome escaped neutral validation", err)
		}
	}
}

func TestNeutralConstructionRejectsTypedNilBorrowedDependencies(t *testing.T) {
	var nilProvider providerFunc
	if _, err := captcha.New(profile(), nilProvider); !errors.Is(err, captcha.ErrInvalidConfiguration) {
		t.Fatal("typed-nil provider became callable")
	}
	config := profile()
	var nilClock *fixedClock
	config.Clock = nilClock
	if _, err := captcha.New(config, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
		t.Fatal("invalid construction invoked provider")
		return captcha.ProviderResult{}, nil
	})); !errors.Is(err, captcha.ErrInvalidConfiguration) {
		t.Fatal("typed-nil clock became callable")
	}
}

func TestNeutralCancellationDuringTrustedClockNeverInvokesProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := profile()
	config.Clock = cancellingClock{fixedClock{config.Clock.Now()}, cancel}
	called := false
	verifier, err := captcha.New(config, providerFunc(func(context.Context, captcha.VerifyRequest) (captcha.ProviderResult, error) {
		called = true
		return captcha.ProviderResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(ctx, request(t))
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("clock cancellation performed provider work", err)
	}
}

func TestNeutralRejectionNeverRetainsProviderClaimedBindingMatches(t *testing.T) {
	config := profile()
	verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
		r := solved(config, actual)
		r.Outcome = captcha.OutcomeRejected
		r.Evidence.Success = false
		r.Evidence.Hostname.Value = "foreign.invalid"
		r.Evidence.Action.Value = "reset"
		r.Evidence.HostnameMatched = true
		r.Evidence.ActionMatched = true
		r.Evidence.OriginMatched = true
		return r, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := verifier.Verify(context.Background(), request(t))
	if err == nil || r.Evidence.HostnameMatched || r.Evidence.ActionMatched || r.Evidence.OriginMatched {
		t.Fatal("provider supplied trusted binding status", err)
	}
}

func TestNeutralProviderErrorConservesUnknownConsumptionWithoutRawDiagnostics(t *testing.T) {
	for _, providerError := range []error{errors.New("synthetic-sensitive-provider-token-diagnostic"), (*captcha.VerifyError)(nil)} {
		config := profile()
		verifier, err := captcha.New(config, providerFunc(func(_ context.Context, actual captcha.VerifyRequest) (captcha.ProviderResult, error) {
			return solved(config, actual), providerError
		}))
		if err != nil {
			t.Fatal(err)
		}
		r, err := verifier.Verify(context.Background(), request(t))
		if !errors.Is(err, captcha.ErrAmbiguousTransport) || r.Outcome != captcha.OutcomeAmbiguous || r.Failure.Transport != captcha.TransportUnknown || !r.ExpiresAt.IsZero() || strings.Contains(fmt.Sprintf("%+v", err), "synthetic-sensitive") {
			t.Fatal("provider failure claimed no consumption or retained unsafe diagnostics", err)
		}
	}
}
