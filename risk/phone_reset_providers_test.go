package risk

import (
	"context"
	"errors"
	"testing"
	"time"
)

// This proves provider-only preparation, not current counter allowance or phone
// recovery permission. The existing evidence participant owns those checks.
func TestPhoneResetProviderPreparationKeepsHIBPWithoutSecondVelocity(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[0].RequiredSignals = []string{"velocity", "status"}
	config.HIBP = HIBPPolicy{CacheTTL: time.Hour, Operations: []Action{"identity.phone.password-reset-complete"}}
	p, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.phone.password-reset-complete"
	clean, err := p.PasswordSignal(context.Background(), c, PasswordObservation{ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	facts := []Signal{testSignal(c, "status", SignalClean), clean}
	providers, err := p.AssessProtectedProviders(context.Background(), c, facts)
	if err != nil || providers.Decision.Action != Allow || providers.PolicyVersion != config.Version || len(providers.Signals) != 2 {
		t.Fatal("phone recovery cannot screen providers without inventing another velocity allowance", err)
	}
	full, err := p.Assess(context.Background(), c, facts)
	if err != nil || full.Decision.Action != Deny {
		t.Fatal("provider-only preparation weakened complete authentication assessment", err)
	}
	if _, err := p.AssessProtectedProviders(context.Background(), c, append(facts, testSignal(c, "velocity", SignalClean))); !errors.Is(err, ErrInvalidSignal) {
		t.Fatal("caller velocity substituted for native evidence authority", err)
	}
	for _, observation := range []PasswordObservation{{BreachCount: 1, ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour)}, {Failure: ProviderUnavailable}} {
		fact, err := p.PasswordSignal(context.Background(), c, observation)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.AssessProtectedProviders(context.Background(), c, []Signal{facts[0], fact})
		if err != nil || got.Decision.Action != Deny {
			t.Fatal("phone recovery bypassed HIBP failure", err)
		}
	}
	for _, missing := range [][]Signal{nil, facts[:1], facts[1:]} {
		got, err := p.AssessProtectedProviders(context.Background(), c, missing)
		if err != nil || got.Decision.Action != Deny {
			t.Fatal("missing mandatory provider accepted", err)
		}
	}
	expired := c
	expired.Now = clean.ExpiresAt
	if _, err := p.AssessProtectedProviders(context.Background(), expired, facts); !errors.Is(err, ErrInvalidSignal) {
		t.Fatal("original provider expiry renewed", err)
	}
	foreign := clean
	foreign.Attempt = "another-attempt"
	if _, err := p.AssessProtectedProviders(context.Background(), c, []Signal{facts[0], foreign}); !errors.Is(err, ErrInvalidSignal) {
		t.Fatal("foreign HIBP fact admitted", err)
	}
}

func TestPhoneProviderPreparationDoesNotOpenOtherAuthenticationProfiles(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[0].RequiredSignals = []string{"velocity"}
	config.HIBP = HIBPPolicy{CacheTTL: time.Hour, Operations: []Action{"identity.phone.password-reset-complete"}}
	p, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{"identity.phone.password-reset-request", "identity.phone.password-signin", "identity.password.reset-complete", "identity.password.signup", "identity.password.signin", "identity.phone.password-reset-complete-alias"} {
		c := testContext()
		c.Operation = action
		if _, err := p.AssessProtectedProviders(context.Background(), c, nil); !errors.Is(err, ErrInvalidAction) {
			t.Fatal("unselected authentication acquired provider-only preparation", action, err)
		}
	}
	for _, without := range []string{"hibp", "velocity"} {
		config := testPolicyConfig()
		config.HIBP = HIBPPolicy{CacheTTL: time.Hour, Operations: []Action{"identity.phone.password-reset-complete"}}
		config.Profiles[0].RequiredSignals = []string{"velocity"}
		if without == "hibp" {
			config.HIBP = HIBPPolicy{}
		} else {
			config.Profiles[0].RequiredSignals = []string{"status"}
		}
		p, err := NewPolicy(config)
		if err != nil {
			t.Fatal(err)
		}
		c := testContext()
		c.Operation = "identity.phone.password-reset-complete"
		if _, err := p.AssessProtectedProviders(context.Background(), c, nil); !errors.Is(err, ErrInvalidAction) {
			t.Fatal("phone preparation accepted incomplete mandatory policy", without, err)
		}
	}
}
