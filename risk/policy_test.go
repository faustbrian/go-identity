package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := NewPolicy(testPolicyConfig())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testPolicyConfig() PolicyConfig {
	return PolicyConfig{Version: 3, Limits: VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []Profile{
		{Class: Authentication, Phase: BeforeCredential, Dimensions: []Dimension{TenantDimension, NetworkDimension, DeviceDimension, IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: Throttle, EvidenceTTL: 5 * time.Minute, Unknown: DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: CredentialMutation, Phase: ReserveWithCommand, Dimensions: []Dimension{TenantDimension, SubjectDimension, SessionDimension, NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: Deny, EvidenceTTL: 15 * time.Minute, Unknown: DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: Privileged, Phase: ReserveWithCommand, Dimensions: []Dimension{TenantDimension, ActorDimension, ResourceDimension, NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: Deny, EvidenceTTL: 15 * time.Minute, Unknown: DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "captcha"}},
		{Class: StateNeutralRead, Phase: BeforeReturn, Dimensions: []Dimension{TenantDimension, SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: Throttle, EvidenceTTL: time.Minute, Unknown: StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "captcha"}},
	}}
}

func TestPolicyRejectsMissingContradictoryAndExcessiveProfiles(t *testing.T) {
	for _, change := range []func(*PolicyConfig){
		func(c *PolicyConfig) { c.Version = 0 }, func(c *PolicyConfig) { c.Profiles = c.Profiles[:3] },
		func(c *PolicyConfig) { c.Profiles[0].Class = Privileged }, func(c *PolicyConfig) { c.Profiles[0].Phase = BeforeReturn },
		func(c *PolicyConfig) { c.Profiles[0].Dimensions[1] = SubjectDimension }, func(c *PolicyConfig) { c.Profiles[0].Unknown = StepUpWithIndependentFactor },
		func(c *PolicyConfig) { c.Profiles[0].ThresholdAction = Allow }, func(c *PolicyConfig) { c.Profiles[0].MaxCounters = 5 },
		func(c *PolicyConfig) { c.Profiles[0].RequiredSignals = []string{"status", "status"} }, func(c *PolicyConfig) { c.Profiles[0].RequiredSignals = []string{"private.name"} },
		func(c *PolicyConfig) { c.Profiles[0].Limit = 11 }, func(c *PolicyConfig) { c.Profiles[0].Window = 6 * time.Minute },
		func(c *PolicyConfig) { c.Profiles[2].EvidenceTTL = 16 * time.Minute }, func(c *PolicyConfig) { c.Limits.KeyBytes = 63 },
		func(c *PolicyConfig) { c.Limits.MaxWindow = 2 * time.Hour }, func(c *PolicyConfig) { c.Limits.MaxLimit = 121 },
	} {
		c := testPolicyConfig()
		change(&c)
		if p, err := NewPolicy(c); !errors.Is(err, ErrInvalidPolicy) || p.state != nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestPolicyAndAdmissionOwnTheirSlices(t *testing.T) {
	c := testPolicyConfig()
	p, err := NewPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Profiles[0].RequiredSignals[0] = "changed"
	c.Profiles[0].Dimensions[0] = ActorDimension
	a, err := p.Admit("identity.password.signin")
	if err != nil || a.Profile.RequiredSignals[0] != "status" || a.Profile.Dimensions[0] != TenantDimension {
		t.Fatal("configuration mutated policy")
	}
	a.Profile.RequiredSignals[0] = "changed"
	a.Profile.Dimensions[0] = ActorDimension
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, err := p.Admit("identity.password.signin")
			if err != nil || got.Profile.RequiredSignals[0] != "status" || got.Profile.Dimensions[0] != TenantDimension {
				t.Error("returned projection mutated policy")
			}
		})
	}
	wg.Wait()
}

func TestRetrySkippedCancellationAndRedaction(t *testing.T) {
	p, c := testPolicy(t), testContext()
	a, b := testSignal(c, "status", SignalThrottle), testSignal(c, "captcha", SignalThrottle)
	a.RetryAfter, b.RetryAfter = time.Second, 2*time.Second
	got, err := p.Assess(context.Background(), c, []Signal{a, b})
	if err != nil || got.Decision.Action != Throttle || got.Decision.RetryAfter != 2*time.Second {
		t.Fatal("attributable throttle", err)
	}
	b.State, b.RetryAfter = SignalDeny, 0
	got, err = p.Assess(context.Background(), c, []Signal{a, b})
	if err != nil || got.Decision.Action != Deny || got.Decision.RetryAfter != 0 {
		t.Fatal("stronger result retained throttle", err)
	}
	a.State, a.RetryAfter = SignalSkipped, 0
	got, err = p.Assess(context.Background(), c, []Signal{a, b})
	if err != nil || got.Decision.Action != Deny || got.Signals[0].State != SignalSkipped {
		t.Fatal("irreversible deny skip disappeared", err)
	}
	b.State = SignalClean
	if _, err := p.Assess(context.Background(), c, []Signal{a, b}); !errors.Is(err, ErrInvalidSignal) {
		t.Fatal("skip allowed before irreversible deny")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Assess(cancelled, c, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, err := p.Assess(nil, c, nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil context admitted")
	}
	for _, value := range []any{c, a} {
		for _, verb := range []string{"%v", "%#v", "%s", "%q", "%d"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "tenant") || strings.Contains(out, "attempt") || strings.Contains(out, "captcha") {
				t.Fatal("scope diagnostic disclosure")
			}
		}
	}
}

func TestClosedDefaultsDoNotInspectSignals(t *testing.T) {
	p, c := testPolicy(t), testContext()
	for _, test := range []struct {
		action Action
		want   DecisionAction
	}{{"identity.oauth-server.jwks", Allow}, {"identity.sso.discover", Deny}, {"identity.account.access-token", Deny}} {
		c.Operation = test.action
		got, err := p.Assess(context.Background(), c, []Signal{{State: 255}})
		if err != nil || got.Decision.Action != test.want || len(got.Signals) != 0 {
			t.Fatal("closed default accessed signals", err)
		}
	}
}

func testContext() Context {
	return Context{Tenant: "tenant", Operation: "identity.password.signin", Attempt: "attempt", Now: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
}
func testSignal(c Context, name string, state SignalState) Signal {
	return Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: name, State: state, Trust: ServerVerified, ObservedAt: c.Now.Add(-time.Second), ExpiresAt: c.Now.Add(time.Minute)}
}

func TestAssessmentPrecedenceAndUnknownFailClosed(t *testing.T) {
	p, c := testPolicy(t), testContext()
	for _, pair := range []struct {
		first, second SignalState
		want          DecisionAction
	}{
		{SignalClean, SignalClean, Allow}, {SignalThrottle, SignalStepUp, StepUp}, {SignalDeny, SignalStepUp, Deny}, {SignalDeny, SignalThrottle, Deny}, {SignalClean, SignalUnavailable, Deny}, {SignalClean, SignalUnknown, Deny},
	} {
		a := testSignal(c, "status", pair.first)
		b := testSignal(c, "captcha", pair.second)
		if a.State == SignalThrottle {
			a.RetryAfter = time.Second
		}
		if b.State == SignalThrottle {
			b.RetryAfter = time.Second
		}
		for _, signals := range [][]Signal{{a, b}, {b, a}} {
			got, err := p.Assess(context.Background(), c, signals)
			if err != nil || got.Decision.Action != pair.want || len(got.Signals) != 2 {
				t.Fatal("wrong deterministic decision", err)
			}
		}
	}
}

func TestAdmissionRejectsUnknownAndCrossScopeBeforeAssessment(t *testing.T) {
	p, c := testPolicy(t), testContext()
	for _, op := range []Action{"signin", "identity.password.signin ", "IDENTITY.PASSWORD.SIGNIN", "identity.future.signin"} {
		c.Operation = op
		if _, err := p.Admit(c.Operation); !errors.Is(err, ErrInvalidAction) {
			t.Fatal("unlisted/alias action admitted")
		}
	}
	c = testContext()
	for _, mutate := range []func(*Signal){func(s *Signal) { s.Tenant = "foreign" }, func(s *Signal) { s.Operation = "identity.password.signup" }, func(s *Signal) { s.Attempt = "foreign" }, func(s *Signal) { s.ExpiresAt = c.Now }, func(s *Signal) { s.ObservedAt = c.Now.Add(time.Second) }} {
		s := testSignal(c, "status", SignalClean)
		mutate(&s)
		if _, err := p.Assess(context.Background(), c, []Signal{s, testSignal(c, "captcha", SignalClean)}); err == nil {
			t.Fatal("foreign/stale signal accepted")
		}
	}
}

func TestMissingOrUntrustedMandatorySignalNeverAllows(t *testing.T) {
	p, c := testPolicy(t), testContext()
	s := testSignal(c, "status", SignalClean)
	got, err := p.Assess(context.Background(), c, []Signal{s})
	if err != nil || got.Decision.Action != Deny || got.Signals[1].State != SignalUnavailable {
		t.Fatal("missing mandatory signal treated as clean", err)
	}
	s.Trust = RequestHint
	got, err = p.Assess(context.Background(), c, []Signal{s, testSignal(c, "captcha", SignalClean)})
	if err != nil || got.Decision.Action != Deny {
		t.Fatal("spoofable hint established clean authority", err)
	}
	c.Operation = "identity.profile.get"
	for _, factor := range []bool{false, true} {
		c.IndependentFactor = factor
		got, err = p.Assess(context.Background(), c, nil)
		want := Deny
		if factor {
			want = StepUp
		}
		if err != nil || got.Decision.Action != want || got.Decision.RetryAfter != 0 {
			t.Fatal("unknown low-risk result", err)
		}
	}
}
