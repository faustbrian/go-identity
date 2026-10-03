package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func adapterPolicy(t *testing.T, ttl time.Duration) risk.Policy {
	t.Helper()
	c := risk.PolicyConfig{Version: 3, HIBP: risk.HIBPPolicy{CacheTTL: ttl, Operations: []risk.Action{"identity.password.signup"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status"}},
	}}
	p, e := risk.NewPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

type checkFunc func(context.Context, CheckRequest) (CheckResult, error)

type cancellingClock struct {
	wall   *testClock
	cancel context.CancelFunc
}

func (c cancellingClock) Now() time.Time { c.cancel(); return c.wall.Now() }

func TestSignalProviderPreservesCancellationDuringPreflightClock(t *testing.T) {
	c, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("cancelled preflight reached network") })
	p, e := NewSignalProvider(c, adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := requestFor(t, "candidate")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.clock = cancellingClock{wall: wall, cancel: cancel}
	s, e := p.Assess(ctx, r)
	if !errors.Is(e, context.Canceled) || s.State != 0 {
		t.Fatal("preflight cancellation became invalid binding", e)
	}
}

func (f checkFunc) Check(ctx context.Context, r CheckRequest) (CheckResult, error) { return f(ctx, r) }

func TestSignalProviderRetainsNeutralCountBounds(t *testing.T) {
	c, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected network work") })
	p, e := NewSignalProvider(c, adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := requestFor(t, "candidate")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	for _, count := range []uint64{0, 1, 1000000000} {
		p.(*signalProvider).checker = checkFunc(func(_ context.Context, actual CheckRequest) (CheckResult, error) {
			s := resultFor(actual)
			s.Outcome = OutcomeNoMatch
			if count != 0 {
				s.Outcome = OutcomeMatch
			}
			s.BreachCount = count
			s.CheckedAt = wall.Now()
			s.ProviderValidUntil = wall.Now().Add(time.Hour)
			return s, nil
		})
		s, e := p.Assess(context.Background(), r)
		want := risk.SignalClean
		if count != 0 {
			want = risk.SignalPositive
		}
		if e != nil || s.State != want || s.BreachCount != count || s.Trust != risk.ServerVerified {
			t.Fatal("count normalization changed provider fact", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.(*signalProvider).checker = checkFunc(func(_ context.Context, actual CheckRequest) (CheckResult, error) {
		cancel()
		return resultFor(actual), nil
	})
	if s, e := p.Assess(ctx, r); !errors.Is(e, context.Canceled) || s.State != 0 {
		t.Fatal("in-flight caller cancellation admitted evidence", e)
	}
}

func TestSignalProviderRejectsEveryBindingAndContradictoryResult(t *testing.T) {
	c, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected network work") })
	p, e := NewSignalProvider(c, adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := requestFor(t, "unchanged")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*CheckResult){
		func(s *CheckResult) { s.OperationID = "identity.password.change" }, func(s *CheckResult) { s.TenantID = "foreign" }, func(s *CheckResult) { s.Action = "identity.password.change" }, func(s *CheckResult) { s.Purpose = "reset" }, func(s *CheckResult) { s.SubjectScope = "foreign" }, func(s *CheckResult) { s.PolicyVersion = "foreign" }, func(s *CheckResult) { s.ReplayID = id },
		func(s *CheckResult) { s.Outcome = 0 }, func(s *CheckResult) { s.Outcome = Outcome(255) }, func(s *CheckResult) { s.Outcome = OutcomeNoMatch }, func(s *CheckResult) { s.BreachCount = 0 }, func(s *CheckResult) { s.BreachCount = 1000000001 }, func(s *CheckResult) { s.CheckedAt = time.Time{} }, func(s *CheckResult) { s.CheckedAt = wall.Now().Add(time.Second) }, func(s *CheckResult) { s.ProviderValidUntil = s.ProviderValidUntil.Add(time.Second) },
	} {
		p.(*signalProvider).checker = checkFunc(func(_ context.Context, actual CheckRequest) (CheckResult, error) {
			s := resultFor(actual)
			s.Outcome = OutcomeMatch
			s.BreachCount = 1
			s.CheckedAt = wall.Now()
			s.ProviderValidUntil = wall.Now().Add(time.Hour)
			change(&s)
			return s, nil
		})
		s, e := p.Assess(context.Background(), r)
		if e == nil || s.State != risk.SignalUnavailable || s.Failure != risk.ProviderInvalidBinding || s.BreachCount != 0 || !s.ObservedAt.IsZero() || !s.ExpiresAt.IsZero() {
			t.Fatal("unbound or contradictory success accepted", e)
		}
	}
}

func TestSignalProviderFailuresCancellationAndBorrowOwnership(t *testing.T) {
	c, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected network work") })
	p, e := NewSignalProvider(c, adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := requestFor(t, " unchanged \x00\xff")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	for _, test := range []struct {
		err  error
		want risk.ProviderFailure
	}{
		{ErrMalformedRange, risk.ProviderMalformed}, {ErrInvalidConfiguration, risk.ProviderInvalidConfiguration}, {ErrInvalidRequest, risk.ProviderInvalidBinding}, {ErrOverloaded, risk.ProviderOverloaded}, {ErrClosed, risk.ProviderClosed}, {context.Canceled, risk.ProviderCancelled}, {context.DeadlineExceeded, risk.ProviderCancelled}, {errors.New("sensitive upstream payload"), risk.ProviderUnavailable},
	} {
		p.(*signalProvider).checker = checkFunc(func(_ context.Context, actual CheckRequest) (CheckResult, error) {
			if e := actual.Candidate.Use(func(raw []byte) error {
				if string(raw) != " unchanged \x00\xff" {
					t.Fatal("candidate changed")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			s := resultFor(actual)
			s.Outcome = OutcomeMatch
			s.BreachCount = 1
			s.CheckedAt = wall.Now()
			s.ProviderValidUntil = wall.Now().Add(time.Hour)
			return s, test.err
		})
		s, e := p.Assess(context.Background(), r)
		if e == nil || s.State != risk.SignalUnavailable || s.Failure != test.want || s.BreachCount != 0 || !s.ObservedAt.IsZero() || strings.Contains(fmt.Sprint(e), "sensitive") {
			t.Fatal("failure became usable or disclosed upstream diagnostics", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, e := p.Assess(ctx, r); !errors.Is(e, context.Canceled) || s.State != 0 {
		t.Fatal("caller cancellation swallowed", e)
	}
	if e := r.Candidate.Use(func(raw []byte) error {
		if string(raw) != " unchanged \x00\xff" {
			t.Fatal("borrowed owner mutated")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	r.Action = "identity.password.signin"
	r.OperationID = string(r.Action)
	if _, e := p.Assess(context.Background(), r); !errors.Is(e, ErrInvalidRequest) {
		t.Fatal("unselected operation accepted", e)
	}
}

func TestSignalProviderPreservesCachedAgeAndCoreDecision(t *testing.T) {
	r := requestFor(t, " \x00password\xff ")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	candidate, e := deriveCandidate(context.Background(), r.Candidate, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer candidate.clear()
	c, wall := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintf(w, "%s:17\n", candidate.suffix[:]) })
	p := adapterPolicy(t, time.Hour)
	provider, e := NewSignalProvider(c, p)
	if e != nil {
		t.Fatal(e)
	}
	first, e := provider.Assess(context.Background(), r)
	if e != nil || first.State != risk.SignalPositive || first.BreachCount != 17 {
		t.Fatal("neutral positive fact missing", e)
	}
	original := wall.Now()
	wall.nanos.Add(int64(30 * time.Minute))
	second, e := provider.Assess(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if !second.ObservedAt.Equal(original) || !second.ProviderValidUntil.Equal(original.Add(time.Hour)) || !second.CheckedAt.Equal(wall.Now()) || !second.ExpiresAt.Equal(wall.Now().Add(5*time.Minute)) {
		t.Fatal("cache age or assessment freshness rewritten")
	}
	ctx := risk.Context{Tenant: string(r.TenantID), Operation: r.Action, Attempt: string(r.ReplayID), Now: wall.Now()}
	status := risk.Signal{Tenant: ctx.Tenant, Operation: ctx.Operation, Attempt: ctx.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: ctx.Now, ExpiresAt: ctx.Now.Add(time.Minute)}
	got, e := p.Assess(context.Background(), ctx, []risk.Signal{status, second})
	if e != nil || got.Decision.Action != risk.Deny {
		t.Fatal("core did not own breach denial", e)
	}
	if _, e := NewSignalProvider(c, adapterPolicy(t, 2*time.Hour)); e == nil {
		t.Fatal("inconsistent cache policy accepted")
	}
}
