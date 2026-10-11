package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
)

func protectedScreeningPolicy(t *testing.T) risk.Policy {
	t.Helper()
	base := screeningPolicy(t, nil)
	var profiles []risk.Profile
	for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.session.get"} {
		a, err := base.Admit(action)
		if err != nil {
			t.Fatal(err)
		}
		p := a.Profile
		if p.Class == risk.CredentialMutation {
			p.RequiredSignals = []string{"velocity", "status"}
		}
		profiles = append(profiles, p)
	}
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.change", "identity.password.signup"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Trigger a real cancellation at the second policy owner's Err observation,
// without introducing production hooks or racing the scheduler. This exercises
// the shared pre-provider phase directly; public preparation supplies its own
// bounded child context to the same phase.
type cancelAtPolicyGate struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAtPolicyGate) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestProtectedHashPreflightPreservesCancellationBetweenOwners(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAtPolicyGate{Context: base, cancel: cancel}
	screen := passwordScreening{policy: protectedScreeningPolicy(t), protectedProviders: true}
	_, err := screen.admit(ctx, risk.Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt", Now: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)})
	if !errors.Is(err, context.Canceled) || ctx.checks < 2 {
		t.Fatal("protected preflight lost cancellation", err)
	}
}

func TestProtectedHashPreparationKeepsProvidersAndDefersVelocity(t *testing.T) {
	w := testPasswordWork(t)
	p := protectedScreeningPolicy(t)
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	for _, scenario := range []string{"clean", "breached", "unavailable", "missing", "velocity", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			calls, clocks := 0, 0
			prepared, err := NewHashPreparer(HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: p, Now: func() time.Time {
				clocks++
				if scenario == "expired" && clocks >= 3 {
					return now.Add(time.Minute)
				}
				return now
			}, Collect: func(ctx context.Context, c risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
				calls++
				observation := risk.PasswordObservation{ObservedAt: now, CheckedAt: now, ValidUntil: now.Add(time.Hour)}
				if scenario == "breached" {
					observation.BreachCount = 1
				}
				if scenario == "unavailable" {
					observation = risk.PasswordObservation{Failure: risk.ProviderUnavailable}
				}
				facts := screeningFacts(t, p, c, observation)
				if scenario == "missing" {
					facts = facts[:1]
				}
				if scenario == "velocity" {
					f := facts[0]
					f.Name = "velocity"
					facts = append(facts, f)
				}
				return facts, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			hash, assessment, err := prepared.PrepareProtected(context.Background(), secret, risk.Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"})
			if scenario == "clean" {
				if err != nil || hash.String() == "" || assessment.Decision.Action != risk.Allow {
					t.Fatal("protected preparation denied", err)
				}
				match, err := w.primitive.Verify(context.Background(), []byte("public-test-only"), hash.String())
				if err != nil || !match.Match() {
					t.Fatal("candidate bytes changed", err)
				}
			} else if hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
				t.Fatal("incomplete provider check disclosed hash", err)
			}
			if calls != 1 {
				t.Fatal("original providers recollected")
			}
		})
	}
}

func TestProtectedHashPreparationDoesNotWeakenOrdinaryPreparation(t *testing.T) {
	w := testPasswordWork(t)
	p := protectedScreeningPolicy(t)
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	calls := 0
	prepared, err := NewHashPreparer(HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: p, Now: func() time.Time { return now }, Collect: func(ctx context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		calls++
		return screeningFacts(t, p, c, risk.PasswordObservation{ObservedAt: now, CheckedAt: now, ValidUntil: now.Add(time.Hour)}), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	binding := risk.Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}
	if hash, _, err := prepared.Prepare(context.Background(), secret, binding); hash.String() != "" || !errors.Is(err, ErrPasswordWork) || calls != 1 {
		t.Fatal("ordinary path bypassed missing velocity", err)
	}
	calls = 0
	binding.Operation = "identity.password.signup"
	if hash, _, err := prepared.PrepareProtected(context.Background(), secret, binding); hash.String() != "" || !errors.Is(err, ErrPasswordWork) || calls != 0 {
		t.Fatal("authentication borrowed protected lane", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	binding.Operation = "identity.password.change"
	if hash, _, err := prepared.PrepareProtected(ctx, secret, binding); hash.String() != "" || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancellation accessed providers", err)
	}
	for _, owner := range []*HashPreparer{nil, {}} {
		if hash, _, err := owner.PrepareProtected(context.Background(), secret, binding); hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("zero owner admitted", err)
		}
	}
}
