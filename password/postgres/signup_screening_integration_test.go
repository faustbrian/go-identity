//go:build integration

package passwordpostgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

type signupHashOwner interface {
	prepareSignupHash(context.Context, password.HashPreparationConfig, risk.AuthenticationAdmission, risk.Context, primitive.Secret) (primitive.EncodedHash, []risk.Signal, error)
}

type resetHashOwner interface {
	prepareResetHash(context.Context, password.HashPreparationConfig, risk.AuthenticationAdmission, risk.Context, primitive.Secret) (primitive.EncodedHash, []risk.Signal, error)
	checkResetScreening(context.Context, risk.Policy, risk.Context, []risk.Signal, time.Time) error
}

type signupHashObservation func(primitive.Observation)

func (f signupHashObservation) Observe(_ context.Context, event primitive.Observation) { f(event) }

func signupScreeningPolicy(t *testing.T) risk.Policy {
	t.Helper()
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup", "identity.username.signup", "identity.password.reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// SU03/SU05: an original counted/audited authentication admission contributes
// its unchanged facts to HIBP-before-hash. The provider boundary cannot replace
// status/velocity or refresh a previous attempt. This test uses the real risk
// evaluator/custody and password primitive, with only external stores/provider
// replaced; it does not claim PostgreSQL or live HIBP interoperability.
func TestSignupScreeningPreservesOriginalRiskBeforeHash(t *testing.T) {
	cryptoPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(cryptoPolicy)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := crypto.Hash(context.Background(), []byte("signup-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	policy := signupScreeningPolicy(t)
	for _, action := range []string{"identity.password.signup", "identity.username.signup", "identity.password.reset-complete"} {
		t.Run(action, func(t *testing.T) {
			for _, mode := range []string{"clean", "breached", "unavailable", "missing", "foreign-hibp", "extra-status", "provider-error", "provider-panic", "expired-during-provider", "expired-during-hash", "backward-clock", "short-password", "destroyed-password", "foreign-attempt", "foreign-tenant", "foreign-action", "factor-override", "missing-admission", "cancelled"} {
				t.Run(mode, func(t *testing.T) {
					command, _ := identity.NewCommandID()
					binding := identity.CommandBinding{CommandID: command, TenantID: signinTestTenant, OperationID: action}
					admission := signinTestAdmission(t, context.Background(), binding)
					original := admission.Prepared()
					now := time.Now().UTC()
					scope := original.Scope
					candidate, _ := primitive.NewSecret([]byte(" synthetic-password "))
					defer candidate.Destroy()
					hashes := 0
					observed, e := primitive.New(cryptoPolicy, primitive.WithObserver(signupHashObservation(func(event primitive.Observation) {
						if event.Operation == primitive.OperationHash {
							hashes++
							if mode == "expired-during-hash" {
								now = original.Signals[0].ExpiresAt
							}
						}
					})))
					if e != nil {
						t.Fatal(e)
					}
					calls := 0
					c := password.HashPreparationConfig{Primitive: observed, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: policy, Now: func() time.Time { return now }, Collect: func(ctx context.Context, actual risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
						calls++
						if borrowed.Len() != candidate.Len() {
							t.Fatal("candidate custody changed")
						}
						if _, bounded := ctx.Deadline(); !bounded {
							t.Fatal("provider work is unbounded")
						}
						observation := risk.PasswordObservation{ObservedAt: actual.Now, CheckedAt: actual.Now, ValidUntil: actual.Now.Add(time.Hour)}
						switch mode {
						case "breached":
							observation.BreachCount = 1
						case "unavailable":
							observation = risk.PasswordObservation{Failure: risk.ProviderUnavailable}
						case "missing":
							return nil, nil
						case "provider-error":
							return nil, errors.New("synthetic private provider diagnostic")
						case "provider-panic":
							panic("synthetic private provider diagnostic")
						case "expired-during-provider":
							now = original.Signals[0].ExpiresAt
						}
						fact, e := policy.PasswordSignal(ctx, actual, observation)
						if mode == "foreign-hibp" {
							fact.Attempt = "foreign"
						}
						if mode == "extra-status" {
							return []risk.Signal{fact, original.Signals[0]}, e
						}
						return []risk.Signal{fact}, e
					}}
					ctx := context.Background()
					beforeProvider := false
					switch mode {
					case "foreign-attempt":
						scope.Attempt = "foreign"
						beforeProvider = true
					case "foreign-tenant":
						scope.Tenant = "foreign"
						beforeProvider = true
					case "foreign-action":
						scope.Operation = "identity.password.signin"
						beforeProvider = true
					case "factor-override":
						scope.IndependentFactor = true
						beforeProvider = true
					case "missing-admission":
						admission = risk.AuthenticationAdmission{}
						beforeProvider = true
					case "backward-clock":
						now = original.Scope.Now.Add(-time.Nanosecond)
						beforeProvider = true
					case "short-password":
						candidate.Destroy()
						candidate, _ = primitive.NewSecret([]byte("short"))
						defer candidate.Destroy()
						beforeProvider = true
					case "destroyed-password":
						candidate.Destroy()
						beforeProvider = true
					case "cancelled":
						var stop context.CancelFunc
						ctx, stop = context.WithCancel(ctx)
						stop()
						beforeProvider = true
					}
					owner, present := any(&Repository{}).(signupHashOwner)
					if !present {
						t.Fatal("native signup has no original-admission hashing path")
					}
					prepare := owner.prepareSignupHash
					check := checkSignupScreening
					if action == "identity.password.reset-complete" {
						reset, present := any(&Repository{}).(resetHashOwner)
						if !present {
							t.Fatal("native reset has no original-admission hashing path")
						}
						prepare = reset.prepareResetHash
						check = reset.checkResetScreening
					}
					hash, facts, err := prepare(ctx, c, admission, scope, candidate)
					if mode == "clean" {
						if err != nil || hash.String() == "" || len(facts) != len(original.Signals)+1 || !reflect.DeepEqual(facts[:len(original.Signals)], original.Signals) {
							t.Fatal("original counted facts lost before hashing", err)
						}
						match, e := crypto.Verify(context.Background(), []byte(" synthetic-password "), hash.String())
						if e != nil || !match.Match() {
							t.Fatal("native hashing changed raw candidate")
						}
						until := facts[0].ExpiresAt
						for _, fact := range facts {
							if fact.ExpiresAt.Before(until) {
								until = fact.ExpiresAt
							}
						}
						if check(ctx, policy, original.Scope, facts, until.Add(-time.Nanosecond)) != nil {
							t.Fatal("primary commit check denied before original expiry")
						}
						for _, at := range []time.Time{original.Scope.Now.Add(-time.Nanosecond), until, until.Add(time.Second)} {
							if check(ctx, policy, original.Scope, facts, at) == nil {
								t.Fatal("primary commit check renewed original evidence")
							}
						}
					} else if err == nil || hash.String() != "" || len(facts) != 0 {
						t.Fatal("invalid admission/provider disclosed retained verifier")
					}
					if beforeProvider && calls != 0 || !beforeProvider && calls != 1 {
						t.Fatal("provider work bypassed admission or was repeated")
					}
					if (mode == "clean" || mode == "expired-during-hash") && hashes != 1 || mode != "clean" && mode != "expired-during-hash" && hashes != 0 {
						t.Fatal("cryptographic work bypassed completed screening")
					}
					if err != nil && strings.Contains(err.Error(), "private") {
						t.Fatal("provider diagnostic escaped redaction")
					}
					if mode == "cancelled" && !errors.Is(err, context.Canceled) {
						t.Fatal("cancellation classification lost")
					}
					if mode != "destroyed-password" && candidate.Len() == 0 {
						t.Fatal("native preparation destroyed caller password")
					}
				})
			}
		})
	}
}
