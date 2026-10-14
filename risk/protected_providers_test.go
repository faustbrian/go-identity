package risk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProtectedProviderAssessmentDefersOnlyOwnedVelocity(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[1].RequiredSignals = []string{"velocity", "status", "captcha"}
	p, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.password.change"
	facts := []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)}
	full, err := p.Assess(context.Background(), c, facts)
	if err != nil || full.Decision.Action != Deny {
		t.Fatal("ordinary assessment must still require velocity", err)
	}
	providers, err := p.AssessProtectedProviders(context.Background(), c, facts)
	if err != nil || providers.Decision.Action != Allow || len(providers.Signals) != 2 || providers.PolicyVersion != config.Version {
		t.Fatal("provider preparation cannot defer transaction-owned velocity", err)
	}
	for _, state := range []SignalState{SignalDeny, SignalUnavailable, SignalUnknown, SignalStepUp} {
		facts[0].State = state
		got, err := p.AssessProtectedProviders(context.Background(), c, facts)
		if err != nil || got.Decision.Action == Allow {
			t.Fatal("mandatory provider failure admitted", state, err)
		}
	}
	facts[0].State = SignalClean
	got, err := p.AssessProtectedProviders(context.Background(), c, facts[:1])
	if err != nil || got.Decision.Action != Deny {
		t.Fatal("omitted provider admitted", err)
	}
	if _, err := p.AssessProtectedProviders(context.Background(), c, append(facts, testSignal(c, "velocity", SignalClean))); !errors.Is(err, ErrInvalidSignal) {
		t.Fatal("caller velocity accepted", err)
	}
	c.Operation = "identity.password.signin"
	if _, err := p.AssessProtectedProviders(context.Background(), c, nil); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("authentication bypass admitted", err)
	}
	if _, err := (Policy{}).AssessProtectedProviders(context.Background(), c, nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero policy admitted", err)
	}
}

func TestProtectedProvidersKeepHIBPAndOriginalFreshness(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[1].RequiredSignals = []string{"velocity"}
	config.HIBP = HIBPPolicy{CacheTTL: time.Hour, Operations: []Action{"identity.password.change"}}
	p, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.password.change"
	for _, observation := range []PasswordObservation{
		{ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour)},
		{ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour), BreachCount: 1},
		{Failure: ProviderUnavailable},
	} {
		fact, err := p.PasswordSignal(context.Background(), c, observation)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.AssessProtectedProviders(context.Background(), c, []Signal{fact})
		want := Deny
		if observation.BreachCount == 0 && observation.Failure == 0 {
			want = Allow
		}
		if err != nil || got.Decision.Action != want {
			t.Fatal("HIBP decision lost", err)
		}
		if want == Allow {
			expired := c
			expired.Now = fact.ExpiresAt
			if _, err := p.AssessProtectedProviders(context.Background(), expired, []Signal{fact}); !errors.Is(err, ErrInvalidSignal) {
				t.Fatal("original fact expiry renewed", err)
			}
			foreign := fact
			foreign.Tenant = "other"
			if _, err := p.AssessProtectedProviders(context.Background(), c, []Signal{foreign}); !errors.Is(err, ErrInvalidSignal) {
				t.Fatal("foreign fact admitted", err)
			}
		}
	}
	missing, err := p.AssessProtectedProviders(context.Background(), c, nil)
	if err != nil || missing.Decision.Action != Deny {
		t.Fatal("HIBP omission admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.AssessProtectedProviders(ctx, c, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := p.AssessProtectedProviders(nil, c, nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil context admitted", err)
	}
	if _, err := testPolicy(t).AssessProtectedProviders(context.Background(), c, nil); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("policy without owned velocity admitted", err)
	}
}
