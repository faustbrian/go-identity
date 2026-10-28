package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

type counterOnlyOperationValidator interface {
	ValidateCounterOnlyOperation(risk.Action) error
}

func TestCounterOnlyCompositionRejectsUnenforcedSignals(t *testing.T) {
	for _, signals := range [][]string{{"velocity"}, {"status", "velocity"}, {"captcha", "velocity"}, {"status"}} {
		config := protectedConfig(t)
		var profiles []risk.Profile
		for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.health"} {
			admission, err := config.CommandCounters.Policy.Admit(action)
			if err != nil {
				t.Fatal(err)
			}
			profile := admission.Profile
			if profile.Class == risk.Privileged {
				profile.RequiredSignals = signals
			}
			profiles = append(profiles, profile)
		}
		policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
		if err != nil {
			t.Fatal("valid explicit signal profile rejected", err)
		}
		config.CommandCounters.Policy = policy
		repository, err := NewRepository(config)
		if err != nil {
			t.Fatal(err)
		}
		validator, ok := any(repository).(counterOnlyOperationValidator)
		if !ok {
			t.Fatal("native counter owner cannot validate counter-only composition")
		}
		err = validator.ValidateCounterOnlyOperation("identity.organization.create")
		if len(signals) == 1 && signals[0] == "velocity" {
			if err != nil {
				t.Fatal("counter-only operation rejected its actual sole signal", err)
			}
		} else if !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("counter-only composition accepted an unenforced provider", err)
		}
		for _, action := range []risk.Action{"identity.password.signin", "identity.health", "identity.organization.get", "identity.organization.Create", "identity.unknown"} {
			if err := validator.ValidateCounterOnlyOperation(action); !errors.Is(err, risk.ErrInvalidPolicy) {
				t.Fatal("counter-only composition accepted unsupported operation", action, err)
			}
		}
	}
	for _, repository := range []*Repository{nil, {}, {counters: &risk.CommandCounterPolicyConfig{}}} {
		validator, ok := any(repository).(counterOnlyOperationValidator)
		if !ok {
			t.Fatal("counter-only validation contract missing")
		}
		if err := validator.ValidateCounterOnlyOperation("identity.organization.create"); !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("counter-only validation accepted missing owned policy", err)
		}
	}
}
