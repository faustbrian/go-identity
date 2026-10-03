package risk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHIBPConfigurationIsOwnedAndDisabledIsExplicit(t *testing.T) {
	p := passwordPolicy(t)
	c, err := p.HIBPConfiguration()
	if err != nil || c.CacheTTL != 24*time.Hour || len(c.Operations) != 3 {
		t.Fatal("selected provider policy missing", err)
	}
	c.Operations[0] = "identity.password.signin"
	copy, err := p.HIBPConfiguration()
	if err != nil || copy.Operations[0] == c.Operations[0] {
		t.Fatal("snapshot mutated policy")
	}
	if _, err := (Policy{}).HIBPConfiguration(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero policy accepted")
	}
	if _, err := testPolicy(t).HIBPConfiguration(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("disabled provider accepted")
	}
}

func passwordPolicy(t *testing.T) Policy {
	t.Helper()
	c := testPolicyConfig()
	c.HIBP = HIBPPolicy{CacheTTL: 24 * time.Hour, Operations: []Action{"identity.password.signup", "identity.password.change", "identity.password.reset-complete"}}
	p, e := NewPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestPasswordFactsAreDecidedByCoreAndKeepOriginalProviderAge(t *testing.T) {
	p := passwordPolicy(t)
	for _, action := range []Action{"identity.password.signup", "identity.password.change", "identity.password.reset-complete"} {
		for _, count := range []uint64{0, 1, 1000000000} {
			c := testContext()
			c.Operation = action
			c.IndependentFactor = true
			admitted, e := p.Admit(action)
			if e != nil {
				t.Fatal(e)
			}
			observed := c.Now.Add(-2 * time.Hour)
			fact := PasswordObservation{BreachCount: count, ObservedAt: observed, ValidUntil: observed.Add(24 * time.Hour), CheckedAt: c.Now}
			s, e := p.PasswordSignal(context.Background(), c, fact)
			if e != nil {
				t.Fatal(e)
			}
			state := SignalClean
			want := Allow
			if count > 0 {
				state = SignalPositive
				want = Deny
			}
			if s.State != state || s.BreachCount != count || !s.ObservedAt.Equal(observed) || !s.ProviderValidUntil.Equal(fact.ValidUntil) || !s.ExpiresAt.Equal(c.Now.Add(admitted.Profile.EvidenceTTL)) {
				t.Fatal("provider facts/age were rewritten")
			}
			got, e := p.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean), s})
			if e != nil || got.Decision.Action != want || got.Signals[2].BreachCount != count {
				t.Fatal("core did not own positive fact decision", e)
			}
		}
	}
}

func TestPasswordProviderExpiryCannotBeRenewedAndScopeIsOptIn(t *testing.T) {
	p := passwordPolicy(t)
	c := testContext()
	c.Operation = "identity.password.signup"
	observed := c.Now.Add(-24*time.Hour + time.Nanosecond)
	s, e := p.PasswordSignal(context.Background(), c, PasswordObservation{ObservedAt: observed, ValidUntil: observed.Add(24 * time.Hour), CheckedAt: c.Now})
	if e != nil || !s.ExpiresAt.Equal(c.Now.Add(time.Nanosecond)) {
		t.Fatal("original provider expiry not decisive", e)
	}
	c.Now = c.Now.Add(time.Nanosecond)
	if _, e := p.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean), s}); !errors.Is(e, ErrInvalidSignal) {
		t.Fatal("expiry boundary accepted")
	}
	c.Operation = "identity.password.signin"
	if _, e := p.PasswordSignal(context.Background(), c, PasswordObservation{}); !errors.Is(e, ErrInvalidSignal) {
		t.Fatal("non-creating operation accepted password fact")
	}
	a, e := p.Admit(c.Operation)
	if e != nil || len(a.Profile.RequiredSignals) != 2 {
		t.Fatal("signin inherited password screening", e)
	}
}

func TestPasswordProviderFailuresRetainClassificationAndDeny(t *testing.T) {
	p := passwordPolicy(t)
	c := testContext()
	c.Operation = "identity.password.signup"
	c.IndependentFactor = true
	for _, failure := range []ProviderFailure{ProviderUnavailable, ProviderMalformed, ProviderInvalidConfiguration, ProviderCancelled, ProviderInvalidBinding, ProviderOverloaded, ProviderClosed} {
		s, e := p.PasswordSignal(context.Background(), c, PasswordObservation{Failure: failure})
		if e != nil || s.State != SignalUnavailable || s.Failure != failure {
			t.Fatal("failure normalized into a decision/clean", e)
		}
		got, e := p.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean), s})
		if e != nil || got.Decision.Action != Deny || got.Signals[2].Failure != failure {
			t.Fatal("outage policy or safe classification lost", e)
		}
	}
}

func TestPasswordPolicyOwnsSelectionAndRejectsInvalidProfiles(t *testing.T) {
	for _, mutate := range []func(*HIBPPolicy){
		func(h *HIBPPolicy) { h.CacheTTL = 0 }, func(h *HIBPPolicy) { h.CacheTTL = time.Hour - time.Nanosecond },
		func(h *HIBPPolicy) { h.CacheTTL = 7*24*time.Hour + time.Nanosecond }, func(h *HIBPPolicy) { h.Operations = nil },
		func(h *HIBPPolicy) { h.Operations = []Action{"identity.password.signin"} },
		func(h *HIBPPolicy) { h.Operations = []Action{"identity.password.signup", "identity.password.signup"} },
		func(h *HIBPPolicy) { h.Operations = []Action{"identity.future.signup"} },
	} {
		c := testPolicyConfig()
		c.HIBP = HIBPPolicy{CacheTTL: time.Hour, Operations: []Action{"identity.password.signup"}}
		mutate(&c.HIBP)
		if _, e := NewPolicy(c); !errors.Is(e, ErrInvalidPolicy) {
			t.Fatal("invalid password source policy admitted", e)
		}
	}
	c := testPolicyConfig()
	c.HIBP = HIBPPolicy{CacheTTL: 24 * time.Hour, Operations: []Action{"identity.password.signup"}}
	p, e := NewPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	c.HIBP.Operations[0] = "identity.password.signin"
	a, e := p.Admit("identity.password.signup")
	if e != nil || a.Profile.RequiredSignals[2] != "hibp" {
		t.Fatal("borrowed configuration changed policy", e)
	}
	a.Profile.RequiredSignals[2] = "other"
	b, e := p.Admit("identity.password.signup")
	if e != nil || b.Profile.RequiredSignals[2] != "hibp" {
		t.Fatal("admission changed retained profile", e)
	}
}

func TestPasswordObservationsRejectInvalidAndCrossScopeFacts(t *testing.T) {
	p := passwordPolicy(t)
	c := testContext()
	c.Operation = "identity.password.signup"
	valid := PasswordObservation{ObservedAt: c.Now.Add(-time.Hour), ValidUntil: c.Now.Add(23 * time.Hour), CheckedAt: c.Now}
	for _, mutate := range []func(*PasswordObservation){
		func(o *PasswordObservation) { o.BreachCount = 1000000001 }, func(o *PasswordObservation) { o.ObservedAt = time.Time{} },
		func(o *PasswordObservation) { o.ValidUntil = o.ValidUntil.Add(time.Nanosecond) },
		func(o *PasswordObservation) { o.CheckedAt = c.Now.Add(time.Nanosecond) },
		func(o *PasswordObservation) { o.CheckedAt = o.ObservedAt.Add(-time.Nanosecond) },
		func(o *PasswordObservation) { o.Failure = ProviderMalformed },
		func(o *PasswordObservation) { *o = PasswordObservation{Failure: ProviderFailure(255)} },
	} {
		o := valid
		mutate(&o)
		if _, e := p.PasswordSignal(context.Background(), c, o); !errors.Is(e, ErrInvalidSignal) {
			t.Fatal("invalid provider observation became usable", e)
		}
	}
	s, e := p.PasswordSignal(context.Background(), c, valid)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Signal){
		func(s *Signal) { s.Tenant = "foreign" }, func(s *Signal) { s.Operation = "identity.password.change" },
		func(s *Signal) { s.Attempt = "other" }, func(s *Signal) { s.Name = "status" },
		func(s *Signal) { s.State = SignalPositive }, func(s *Signal) { s.ExpiresAt = s.CheckedAt.Add(6 * time.Minute) },
		func(s *Signal) { s.CheckedAt = s.CheckedAt.Add(time.Nanosecond) },
	} {
		changed := s
		mutate(&changed)
		if _, e := p.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean), changed}); !errors.Is(e, ErrInvalidSignal) {
			t.Fatal("foreign or inconsistent facts accepted", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := p.PasswordSignal(ctx, c, valid); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled normalization ran")
	}
}

func TestEvaluatorPreservesSafePasswordFailureAndNeverUsesPositiveWithError(t *testing.T) {
	for _, failure := range []ProviderFailure{ProviderMalformed, ProviderInvalidBinding, 0} {
		p := passwordPolicy(t)
		cfg := evaluatorConfig(t)
		cfg.Policy = p
		cfg.Sources = append(cfg.Sources, Source{Name: "hibp", Timeout: time.Second,
			Read: func(ctx context.Context, c Context) (Signal, error) {
				observation := PasswordObservation{Failure: failure}
				if failure == 0 {
					observation = PasswordObservation{BreachCount: 1, ObservedAt: c.Now, ValidUntil: c.Now.Add(24 * time.Hour), CheckedAt: c.Now}
				}
				s, e := p.PasswordSignal(ctx, c, observation)
				if e != nil {
					return s, e
				}
				return s, errors.New("private upstream diagnostics")
			}})
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		c := testContext()
		c.Operation = "identity.password.signup"
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing})
		want := failure
		if want == 0 {
			want = ProviderUnavailable
		}
		if err != nil || got.Decision.Action != Deny || got.assessment.Signals[2].Failure != want || got.assessment.Signals[2].State != SignalUnavailable {
			t.Fatal("error classification lost or positive-with-error accepted", err)
		}
	}
}

func TestUnselectedGenericHIBPSourceRetainsLegacyUnavailableBehavior(t *testing.T) {
	for _, late := range []bool{false, true} {
		policyConfig := testPolicyConfig()
		for i := range policyConfig.Profiles {
			policyConfig.Profiles[i].RequiredSignals = append(policyConfig.Profiles[i].RequiredSignals, "hibp")
		}
		policy, e := NewPolicy(policyConfig)
		if e != nil {
			t.Fatal(e)
		}
		cfg := evaluatorConfig(t)
		cfg.Policy = policy
		now := testContext().Now
		cfg.Clock = func() time.Time { return now }
		cfg.Sources = append(cfg.Sources, Source{Name: "hibp", Timeout: time.Second, Read: func(_ context.Context, c Context) (Signal, error) {
			if late {
				now = now.Add(2 * time.Second)
				return testSignal(c, "hibp", SignalClean), nil
			}
			return Signal{}, errors.New("private unavailable diagnostics")
		}})
		evaluator, e := NewEvaluator(cfg)
		if e != nil {
			t.Fatal(e)
		}
		got, e := evaluator.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		if e != nil || got.Decision.Action != Deny || got.assessment.Signals[2].State != SignalUnavailable || got.assessment.Signals[2].Failure != 0 {
			t.Fatal("legacy hibp source failure changed contract", e)
		}
	}
}

func TestPasswordMandatorySelectionAndSkippedFacts(t *testing.T) {
	p := passwordPolicy(t)
	c := testContext()
	c.Operation = "identity.password.signup"
	a, b := testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)
	got, e := p.Assess(context.Background(), c, []Signal{a, b})
	if e != nil || got.Decision.Action != Deny {
		t.Fatal("missing mandatory password facts allowed", e)
	}
	skipped := Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "hibp", State: SignalSkipped, Trust: ServerVerified}
	if _, e := p.Assess(context.Background(), c, []Signal{a, b, skipped}); !errors.Is(e, ErrInvalidSignal) {
		t.Fatal("password facts skipped without independent deny")
	}
	a.State = SignalDeny
	got, e = p.Assess(context.Background(), c, []Signal{a, b, skipped})
	if e != nil || got.Decision.Action != Deny || got.Signals[2].State != SignalSkipped {
		t.Fatal("skipped password facts changed irreversible deny", e)
	}
	cfg := evaluatorConfig(t)
	cfg.Policy = p
	cfg.Sources[0] = Source{Name: "status", Timeout: time.Second, Read: func(_ context.Context, c Context) (Signal, error) { return testSignal(c, "status", SignalDeny), nil }}
	cfg.Sources = append(cfg.Sources, Source{Name: "hibp", Timeout: time.Second, Expensive: true, Read: func(context.Context, Context) (Signal, error) {
		t.Fatal("expensive password query ran after deny")
		return Signal{}, nil
	}})
	evaluator, e := NewEvaluator(cfg)
	if e != nil {
		t.Fatal(e)
	}
	result, e := evaluator.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing})
	if e != nil || result.Decision.Action != Deny || result.assessment.Signals[2].State != SignalSkipped {
		t.Fatal("owned skip failed", e)
	}
}
