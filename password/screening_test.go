package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
)

var creatingActions = []risk.Action{"identity.password.signup", "identity.username.signup", "identity.password.set", "identity.password.change", "identity.password.reset-complete", "identity.otp.password-reset", "identity.phone.password-reset-complete", "identity.admin.user-password-set"}

func screeningPolicy(t *testing.T, operations []risk.Action) risk.Policy {
	t.Helper()
	providerPolicy := risk.HIBPPolicy{}
	if len(operations) > 0 {
		providerPolicy = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: operations}
	}
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, HIBP: providerPolicy, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func screeningFacts(t *testing.T, p risk.Policy, c risk.Context, observation risk.PasswordObservation) []risk.Signal {
	t.Helper()
	hibp, err := p.PasswordSignal(context.Background(), c, observation)
	if err != nil {
		t.Fatal(err)
	}
	return []risk.Signal{{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, hibp}
}

func TestEveryPasswordCreatingPathRequiresRiskOwnedHIBPDecision(t *testing.T) {
	p := screeningPolicy(t, creatingActions)
	w := testPasswordWork(t)
	now := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	for _, action := range creatingActions {
		for _, scenario := range []string{"clean", "breached", "unavailable", "missing"} {
			t.Run(string(action)+"/"+scenario, func(t *testing.T) {
				s := passwordScreening{policy: p, now: func() time.Time { return now }, collect: func(ctx context.Context, c risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("unbounded provider collection")
					}
					if candidate.Len() != secret.Len() {
						t.Fatal("candidate custody changed")
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
					return facts, nil
				}}
				hash, assessment, err := w.newScreenedHash(context.Background(), secret, s, risk.Context{Tenant: "tenant", Operation: action, Attempt: "attempt"})
				if scenario == "clean" {
					if err != nil || hash.String() == "" || assessment.Decision.Action != risk.Allow {
						t.Fatal("complete clean assessment denied", err)
					}
				} else if hash.String() != "" || !errors.Is(err, ErrPasswordWork) || assessment.Decision.Action != risk.Deny {
					t.Fatal("mandatory HIBP decision bypassed")
				}
			})
		}
	}
}

func TestPasswordScreeningRejectsUnselectedAndForeignFacts(t *testing.T) {
	p := screeningPolicy(t, []risk.Action{"identity.password.signup"})
	w := testPasswordWork(t)
	now := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	for _, action := range []risk.Action{"identity.password.signin", "identity.admin.user-password-set", "alias.signup"} {
		s := passwordScreening{policy: p, now: func() time.Time { return now }, collect: func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
			t.Fatal("unselected action reached provider")
			return nil, nil
		}}
		if hash, _, err := w.newScreenedHash(context.Background(), secret, s, risk.Context{Tenant: "tenant", Operation: action, Attempt: "attempt"}); hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("unselected action hashed password")
		}
	}
	for _, mutate := range []func([]risk.Signal){
		func(f []risk.Signal) { f[1].Tenant = "foreign" },
		func(f []risk.Signal) { f[1].Operation = "identity.password.change" },
		func(f []risk.Signal) { f[1].Attempt = "foreign" },
		func(f []risk.Signal) { f[1].Trust = risk.RequestHint },
		func(f []risk.Signal) { f[0].State = risk.SignalStepUp },
	} {
		s := passwordScreening{policy: p, now: func() time.Time { return now }, collect: func(_ context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
			facts := screeningFacts(t, p, c, risk.PasswordObservation{ObservedAt: now, CheckedAt: now, ValidUntil: now.Add(time.Hour)})
			mutate(facts)
			return facts, nil
		}}
		if hash, _, err := w.newScreenedHash(context.Background(), secret, s, risk.Context{Tenant: "tenant", Operation: "identity.password.signup", Attempt: "attempt", IndependentFactor: true}); hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("foreign or non-allow facts authorized hashing")
		}
	}
}

func TestPasswordScreeningKeepsOriginalFactsAfterHashWork(t *testing.T) {
	p := screeningPolicy(t, creatingActions)
	w := testPasswordWork(t)
	started := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	now := started
	var original []risk.Signal
	service, err := primitive.New(w.primitive.Policy(), primitive.WithObserver(workObservation(func(_ context.Context, event primitive.Observation) {
		if event.Operation == primitive.OperationHash {
			now = started.Add(time.Minute)
			// A supplier retaining its returned slice cannot rewrite the workflow's
			// frozen facts to promote them into renewed positive evidence.
			original[0].ObservedAt = now
			original[0].ExpiresAt = now.Add(time.Minute)
		}
	})))
	if err != nil {
		t.Fatal(err)
	}
	w.primitive = service
	calls := 0
	s := passwordScreening{policy: p, now: func() time.Time { return now }, collect: func(_ context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		calls++
		original = screeningFacts(t, p, c, risk.PasswordObservation{ObservedAt: started, CheckedAt: started, ValidUntil: started.Add(time.Hour)})
		return original, nil
	}}
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	hash, _, err := w.newScreenedHash(context.Background(), secret, s, risk.Context{Tenant: "tenant", Operation: "identity.password.signup", Attempt: "attempt"})
	if hash.String() != "" || !errors.Is(err, ErrPasswordWork) || calls != 1 {
		t.Fatal("expired original facts renewed or hash disclosed")
	}
}

func TestPasswordScreeningRejectsFailuresBeforeHashing(t *testing.T) {
	p := screeningPolicy(t, creatingActions)
	w := testPasswordWork(t)
	now := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	binding := risk.Context{Tenant: "tenant", Operation: "identity.password.signup", Attempt: "attempt"}
	for _, scenario := range []string{"disabled", "invalid-policy", "provider-error", "provider-panic", "too-many-facts", "backward-clock", "zero-clock", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := now
			entropy := &failingEntropy{}
			service, err := primitive.NewTestService(w.primitive.Policy(), entropy)
			if err != nil {
				t.Fatal(err)
			}
			work := w
			work.primitive = service
			s := passwordScreening{policy: p, now: func() time.Time { return clock }, collect: func(_ context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
				if scenario == "disabled" || scenario == "invalid-policy" || scenario == "zero-clock" || scenario == "canceled" {
					t.Fatal("invalid admission called provider")
				}
				if scenario == "provider-panic" {
					panic("private provider message")
				}
				facts := screeningFacts(t, p, c, risk.PasswordObservation{ObservedAt: now, CheckedAt: now, ValidUntil: now.Add(time.Hour)})
				if scenario == "provider-error" {
					return facts, errors.New("private provider message")
				}
				if scenario == "too-many-facts" {
					facts = append(facts, facts...)
				}
				if scenario == "backward-clock" {
					clock = now.Add(-time.Second)
				}
				return facts, nil
			}}
			if scenario == "disabled" {
				s.policy = screeningPolicy(t, nil)
			}
			if scenario == "invalid-policy" {
				s.policy = risk.Policy{}
			}
			if scenario == "zero-clock" {
				clock = time.Time{}
			}
			if scenario == "canceled" {
				cancel()
			}
			hash, _, err := work.newScreenedHash(ctx, secret, s, binding)
			if hash.String() != "" || err == nil || entropy.reads != 0 {
				t.Fatal("invalid screening reached hashing")
			}
			if scenario == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("screening lost cancellation")
			}
			if scenario != "canceled" && !errors.Is(err, ErrPasswordWork) {
				t.Fatal("private provider classification leaked")
			}
		})
	}
}

func TestPasswordScreeningRejectsPostHashClockRollbackAfterStart(t *testing.T) {
	p := screeningPolicy(t, creatingActions)
	w := testPasswordWork(t)
	started := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	samples := []time.Time{started, started.Add(30 * time.Second), started.Add(time.Second)}
	index := 0
	s := passwordScreening{policy: p, now: func() time.Time {
		if index >= len(samples) {
			t.Fatal("unexpected extra clock read")
		}
		now := samples[index]
		index++
		return now
	}, collect: func(_ context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		return screeningFacts(t, p, c, risk.PasswordObservation{ObservedAt: started, CheckedAt: started, ValidUntil: started.Add(time.Hour)}), nil
	}}
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	hash, _, err := w.newScreenedHash(context.Background(), secret, s, risk.Context{Tenant: "tenant", Operation: "identity.password.signup", Attempt: "attempt"})
	if hash.String() != "" || !errors.Is(err, ErrPasswordWork) || index != 3 {
		t.Fatal("post-hash clock rollback disclosed hash")
	}
}
