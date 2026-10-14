package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func phoneBinding() PhoneRecoveryScope {
	return PhoneRecoveryScope{Tenant: "tenant", Subject: "subject", RecoveryOperation: "identity.phone.password-reset-request", CanonicalNumber: "+358401234567", PreAuthTransaction: "preauth-transaction", Attempt: "attempt-identifier", PolicyVersion: 3}
}

func carrierConfig(t *testing.T, now *time.Time) CarrierEvaluatorConfig {
	t.Helper()
	c := CarrierEvaluatorConfig{Enabled: true, PolicyVersion: 3, Lifetime: 2 * time.Minute, Clock: func() time.Time { return *now }, Timeout: time.Second}
	for _, kind := range []CarrierKind{SIMSwap, NumberRecycling, Carrier} {
		c.Sources = append(c.Sources, CarrierSource{Kind: kind, Version: "v1", Timeout: time.Second, Read: func(_ context.Context, r CarrierRequest) (CarrierObservation, error) {
			return CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: kind, State: CarrierNegative, ProviderVersion: "v1", ObservedAt: *now, ExpiresAt: now.Add(2 * time.Minute)}, nil
		}})
	}
	return c
}

func TestCarrierAssessmentRequiresThreeFreshNegativeOwnedFacts(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	calls := 0
	for i := range config.Sources {
		original := config.Sources[i].Read
		config.Sources[i].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
			calls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded carrier read")
			}
			return original(ctx, r)
		}
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	request := CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation}
	assessment, err := e.Assess(context.Background(), request)
	if err != nil || calls != 3 {
		t.Fatal("mandatory evaluation", err)
	}
	metadata := assessment.Metadata()
	if metadata.Decision != Allow || metadata.Purpose != "phone-password-reset-initiate" || !metadata.ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatal("invalid negative assessment")
	}
	if err := assessment.Validate(e, request, now); err != nil {
		t.Fatal(err)
	}
	other, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Validate(other, request, now); !errors.Is(err, ErrInvalidCarrierAssessment) {
		t.Fatal("foreign evaluator accepted")
	}
}

func TestCarrierPhasesAndBindingsRejectBeforeReaders(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	for i := range config.Sources {
		config.Sources[i].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
			t.Fatal("invalid request reached provider")
			return CarrierObservation{}, nil
		}
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []IssuancePhase{"", NonIssuing, "unknown", PhoneResetCompletion} {
		if _, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: phase}); !errors.Is(err, ErrInvalidCarrierRequest) {
			t.Fatal("invalid phase admitted", err)
		}
	}
	for _, mutate := range []func(*PhoneRecoveryScope){
		func(b *PhoneRecoveryScope) { b.Tenant = "" }, func(b *PhoneRecoveryScope) { b.Subject = "" },
		func(b *PhoneRecoveryScope) { b.CanonicalNumber = "358401234567" }, func(b *PhoneRecoveryScope) { b.CanonicalNumber = "+0001234567" },
		func(b *PhoneRecoveryScope) { b.PreAuthTransaction = "short" }, func(b *PhoneRecoveryScope) { b.Attempt = "short" },
		func(b *PhoneRecoveryScope) { b.PolicyVersion = 4 }, func(b *PhoneRecoveryScope) { b.RecoveryOperation = "identity.password.reset" },
	} {
		binding := phoneBinding()
		mutate(&binding)
		if _, err := e.Assess(context.Background(), CarrierRequest{Binding: binding, Phase: PhoneResetInitiation}); !errors.Is(err, ErrInvalidCarrierRequest) {
			t.Fatal("invalid binding admitted", err)
		}
	}
}

func TestCarrierPositiveUnknownUnavailableAndReaderErrorsDeny(t *testing.T) {
	for _, state := range []CarrierState{CarrierPositive, CarrierUnknown, CarrierUnavailable, 0} {
		now := testContext().Now
		config := carrierConfig(t, &now)
		read := config.Sources[0].Read
		config.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
			fact, err := read(ctx, r)
			fact.State = state
			return fact, err
		}
		e, err := NewCarrierEvaluator(config)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
		if err != nil || got.Metadata().Decision != Deny {
			t.Fatal("adverse carrier fact allowed", err)
		}
	}
	now := testContext().Now
	config := carrierConfig(t, &now)
	config.Sources[0].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
		return CarrierObservation{}, errors.New("private provider failure")
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
	if err != nil || got.Metadata().Decision != Deny {
		t.Fatal("provider error allowed", err)
	}
}

func TestCarrierOriginalFreshnessExpiresAcrossLaterReads(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	config.Timeout = 10 * time.Second
	for i := range config.Sources {
		config.Sources[i].Timeout = time.Second
	}
	first := config.Sources[0].Read
	config.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
		f, err := first(ctx, r)
		f.ObservedAt = now.Add(-2*time.Minute + time.Millisecond)
		f.ExpiresAt = now.Add(time.Millisecond)
		return f, err
	}
	last := config.Sources[2].Read
	config.Sources[2].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
		now = now.Add(time.Millisecond)
		return last(ctx, r)
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
	if err != nil || got.Metadata().Decision != Deny || !got.Metadata().ExpiresAt.IsZero() {
		t.Fatal("earlier fact freshness renewed", err)
	}
}

func TestCarrierCompletionAndValidationPreserveOriginalScopeAndExpiry(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	config.Lifetime = 30 * time.Second
	for i := range config.Sources {
		read := config.Sources[i].Read
		config.Sources[i].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
			fact, err := read(ctx, r)
			fact.ObservedAt = now.Add(-time.Second)
			fact.ExpiresAt = fact.ObservedAt.Add(2 * time.Minute)
			return fact, err
		}
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	r := CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetCompletion}
	r.Binding.RecoveryOperation = "identity.phone.password-reset-complete"
	a, err := e.Assess(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	m := a.Metadata()
	if m.Purpose != "phone-password-reset-complete" || !m.ObservedAt.Equal(now.Add(-time.Second)) || !m.ExpiresAt.Equal(now.Add(29*time.Second)) {
		t.Fatal("incorrect derived completion lifetime")
	}
	for _, mutate := range []func(*CarrierRequest){
		func(r *CarrierRequest) { r.Binding.Tenant = "other" }, func(r *CarrierRequest) { r.Binding.Subject = "other" },
		func(r *CarrierRequest) { r.Binding.CanonicalNumber = "+358401234568" }, func(r *CarrierRequest) { r.Binding.PreAuthTransaction = "other-transaction" },
		func(r *CarrierRequest) { r.Binding.Attempt = "other-attempt-id" }, func(r *CarrierRequest) { r.Binding.PolicyVersion++ },
		func(r *CarrierRequest) { r.Phase = PhoneResetInitiation }, func(r *CarrierRequest) { r.Binding.RecoveryOperation = "identity.phone.password-reset-request" },
	} {
		foreign := r
		mutate(&foreign)
		if err := a.Validate(e, foreign, now); !errors.Is(err, ErrInvalidCarrierAssessment) {
			t.Fatal("foreign recovery binding admitted")
		}
	}
	for _, instant := range []time.Time{{}, now.Add(-time.Nanosecond), m.ExpiresAt, m.ExpiresAt.Add(time.Second)} {
		if err := a.Validate(e, r, instant); !errors.Is(err, ErrInvalidCarrierAssessment) {
			t.Fatal("invalid/exclusive expiry admitted")
		}
	}
	m.ExpiresAt = now.Add(time.Hour)
	if a.Metadata().ExpiresAt.Equal(m.ExpiresAt) {
		t.Fatal("metadata mutation renewed lifetime")
	}
}

func TestCarrierMalformedOrForeignFactsNeverAllow(t *testing.T) {
	for _, mutate := range []func(*CarrierObservation){
		func(f *CarrierObservation) { f.Binding.Tenant = "other" }, func(f *CarrierObservation) { f.Phase = PhoneResetCompletion },
		func(f *CarrierObservation) { f.Kind = Carrier }, func(f *CarrierObservation) { f.ProviderVersion = "v2" },
		func(f *CarrierObservation) { f.ObservedAt = time.Time{} }, func(f *CarrierObservation) { f.ExpiresAt = f.ObservedAt },
		func(f *CarrierObservation) { f.ObservedAt = f.ObservedAt.Add(time.Second) }, func(f *CarrierObservation) { f.ExpiresAt = f.ExpiresAt.Add(time.Second) },
	} {
		now := testContext().Now
		config := carrierConfig(t, &now)
		read := config.Sources[0].Read
		config.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
			fact, err := read(ctx, r)
			mutate(&fact)
			return fact, err
		}
		e, err := NewCarrierEvaluator(config)
		if err != nil {
			t.Fatal(err)
		}
		a, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
		if err != nil || a.Metadata().Decision != Deny {
			t.Fatal("foreign/malformed fact allowed", err)
		}
	}
}

func TestCarrierConfigurationDisabledOwnershipAndCopying(t *testing.T) {
	disabled, err := NewCarrierEvaluator(CarrierEvaluatorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.Assess(context.Background(), CarrierRequest{}); !errors.Is(err, ErrCarrierRecoveryDisabled) {
		t.Fatal("disabled enabled")
	}
	if _, err := (CarrierEvaluator{}).Assess(context.Background(), CarrierRequest{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero evaluator enabled")
	}
	for _, mutate := range []func(*CarrierEvaluatorConfig){
		func(c *CarrierEvaluatorConfig) { c.Enabled = false }, func(c *CarrierEvaluatorConfig) { c.PolicyVersion = 0 },
		func(c *CarrierEvaluatorConfig) { c.Lifetime = 0 }, func(c *CarrierEvaluatorConfig) { c.Lifetime = 2*time.Minute + time.Nanosecond },
		func(c *CarrierEvaluatorConfig) { c.Clock = nil }, func(c *CarrierEvaluatorConfig) { c.Timeout = 0 }, func(c *CarrierEvaluatorConfig) { c.Timeout = time.Minute + time.Nanosecond },
		func(c *CarrierEvaluatorConfig) { c.Sources = c.Sources[:2] }, func(c *CarrierEvaluatorConfig) { c.Sources[1].Kind = SIMSwap },
		func(c *CarrierEvaluatorConfig) { c.Sources[0].Kind = "alias" }, func(c *CarrierEvaluatorConfig) { c.Sources[0].Version = "" },
		func(c *CarrierEvaluatorConfig) { c.Sources[0].Read = nil }, func(c *CarrierEvaluatorConfig) { c.Sources[0].Timeout = 2 * time.Second },
	} {
		now := testContext().Now
		c := carrierConfig(t, &now)
		mutate(&c)
		if _, err := NewCarrierEvaluator(c); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid ownership configuration accepted")
		}
	}
	now := testContext().Now
	config := carrierConfig(t, &now)
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Sources[0].Read = func(context.Context, CarrierRequest) (CarrierObservation, error) {
		t.Fatal("caller changed reader")
		return CarrierObservation{}, nil
	}
	a, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
	if err != nil || a.Metadata().Decision != Allow {
		t.Fatal("configuration not frozen", err)
	}
}

func TestCarrierRiskOwnerAcceptsCanonicalTagInActualEvaluation(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	config.Sources[2].Kind = CarrierKind("carrier-risk")
	config.Sources[2].Read = func(_ context.Context, r CarrierRequest) (CarrierObservation, error) {
		return CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: CarrierKind("carrier-risk"), State: CarrierNegative, ProviderVersion: "v1", ObservedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, nil
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal("canonical carrier-risk owner rejected", err)
	}
	a, err := e.Assess(context.Background(), CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
	if err != nil || a.Metadata().Decision != Allow {
		t.Fatal("canonical carrier-risk fact rejected", err)
	}
}

func TestCarrierCancellationAndLateOrBackwardClocksReturnNoAssessment(t *testing.T) {
	for _, mode := range []string{"cancel", "backward", "total-timeout", "invalid-clock"} {
		t.Run(mode, func(t *testing.T) {
			now := testContext().Now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := carrierConfig(t, &now)
			read := config.Sources[0].Read
			config.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
				fact, err := read(ctx, r)
				switch mode {
				case "cancel":
					cancel()
				case "backward":
					now = now.Add(-time.Nanosecond)
				case "total-timeout":
					now = now.Add(time.Second)
				case "invalid-clock":
					now = time.Time{}
				}
				return fact, err
			}
			e, err := NewCarrierEvaluator(config)
			if err != nil {
				t.Fatal(err)
			}
			a, err := e.Assess(ctx, CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation})
			if err == nil || a.state != nil {
				t.Fatal("late/cancelled evaluation admitted")
			}
		})
	}
}

func TestCarrierPrivacyAndDeniedAssessmentCannotAuthorize(t *testing.T) {
	now := testContext().Now
	config := carrierConfig(t, &now)
	read := config.Sources[0].Read
	config.Sources[0].Read = func(ctx context.Context, r CarrierRequest) (CarrierObservation, error) {
		fact, err := read(ctx, r)
		fact.State = CarrierPositive
		return fact, err
	}
	e, err := NewCarrierEvaluator(config)
	if err != nil {
		t.Fatal(err)
	}
	r := CarrierRequest{Binding: phoneBinding(), Phase: PhoneResetInitiation}
	a, err := e.Assess(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(e, r, now); !errors.Is(err, ErrInvalidCarrierAssessment) {
		t.Fatal("denied assessment authorized")
	}
	for _, value := range []any{r, r.Binding, a, CarrierObservation{Binding: r.Binding}} {
		for _, verb := range []string{"%v", "%#v", "%s", "%q", "%x"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "358401234567") || strings.Contains(out, "preauth-transaction") {
				t.Fatal("sensitive diagnostic")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("sensitive serialization permitted")
		}
	}
}

func FuzzCarrierRequestBounds(f *testing.F) {
	f.Add("+358401234567", "tenant", "subject", "preauth-transaction", "attempt-identifier")
	f.Add("bad", "", "", "", "")
	now := testContext().Now
	sources := make([]CarrierSource, 0, 3)
	for _, kind := range []CarrierKind{SIMSwap, NumberRecycling, Carrier} {
		sources = append(sources, CarrierSource{Kind: kind, Version: "v1", Timeout: time.Second, Read: func(_ context.Context, r CarrierRequest) (CarrierObservation, error) {
			return CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: kind, State: CarrierNegative, ProviderVersion: "v1", ObservedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, nil
		}})
	}
	e, err := NewCarrierEvaluator(CarrierEvaluatorConfig{Enabled: true, PolicyVersion: 3, Lifetime: 2 * time.Minute, Clock: func() time.Time { return now }, Timeout: time.Second, Sources: sources})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, number, tenant, subject, transaction, attempt string) {
		r := CarrierRequest{Binding: PhoneRecoveryScope{Tenant: tenant, Subject: subject, CanonicalNumber: number, PreAuthTransaction: transaction, Attempt: attempt, PolicyVersion: 3, RecoveryOperation: "identity.phone.password-reset-request"}, Phase: PhoneResetInitiation}
		a, err := e.Assess(context.Background(), r)
		if err != nil {
			if a.state != nil {
				t.Fatal("invalid input retained assessment")
			}
			return
		}
		if a.Metadata().Decision != Allow || len(number) < 8 || len(number) > 16 || len(tenant) > 128 || len(subject) > 128 || len(transaction) > 128 || len(attempt) > 128 {
			t.Fatal("unbounded input assessment")
		}
		if err := a.Validate(e, r, now); err != nil {
			t.Fatal("assessed input cannot be used", err)
		}
	})
}
