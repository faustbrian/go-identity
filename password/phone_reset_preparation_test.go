package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

func phoneResetScreeningPolicy(t *testing.T) risk.Policy {
	t.Helper()
	base := screeningPolicy(t, nil)
	var profiles []risk.Profile
	for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.session.get"} {
		a, err := base.Admit(action)
		if err != nil {
			t.Fatal(err)
		}
		if a.Profile.Class == risk.Authentication {
			a.Profile.RequiredSignals = []string{"velocity", "status"}
		}
		profiles = append(profiles, a.Profile)
	}
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.phone.password-reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Hashing is preparation only. Native completion must still consume the original
// risk evidence, capability and independent factors with the protected mutation.
func TestPhoneResetHashUsesExistingProviderScreeningWithoutVelocityFabrication(t *testing.T) {
	w := testPasswordWork(t)
	p := phoneResetScreeningPolicy(t)
	now := time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC)
	secret, err := primitive.NewSecret([]byte("public-test-only"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	for _, scenario := range []string{"clean", "breached", "unavailable", "missing", "velocity", "expired", "ordinary"} {
		t.Run(scenario, func(t *testing.T) {
			calls, clocks := 0, 0
			preparer, err := NewHashPreparer(HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: p, Now: func() time.Time {
				clocks++
				if scenario == "expired" && clocks >= 3 {
					return now.Add(time.Minute)
				}
				return now
			}, Collect: func(ctx context.Context, c risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
				calls++
				if _, bounded := ctx.Deadline(); !bounded || borrowed.Len() != secret.Len() {
					t.Fatal("provider collection lost original secret or bounded context")
				}
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
					velocity := facts[0]
					velocity.Name = "velocity"
					facts = append(facts, velocity)
				}
				return facts, nil
			}})
			if err != nil || calls != 0 {
				t.Fatal("constructor performed provider work", err)
			}
			scope := risk.Context{Tenant: "tenant", Operation: "identity.phone.password-reset-complete", Attempt: "attempt"}
			var hash primitive.EncodedHash
			if scenario == "ordinary" {
				hash, _, err = preparer.Prepare(context.Background(), secret, scope)
			} else {
				var assessment risk.ProtectedProviderAssessment
				hash, assessment, err = preparer.PrepareProtected(context.Background(), secret, scope)
				if scenario == "clean" && (assessment.Decision.Action != risk.Allow || assessment.PolicyVersion != 3) {
					t.Fatal("provider-only policy identity lost", err)
				}
			}
			if scenario == "clean" {
				if err != nil || hash.String() == "" {
					t.Fatal("phone recovery cannot prepare a screened password", err)
				}
				matched, err := w.primitive.Verify(context.Background(), []byte("public-test-only"), hash.String())
				if err != nil || !matched.Match() {
					t.Fatal("prepared hash changed original bytes", err)
				}
			} else if hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
				t.Fatal("incomplete or expired screening disclosed a verifier", err)
			}
			if calls != 1 {
				t.Fatal("phone screening did not preserve one original provider observation")
			}
		})
	}
}
