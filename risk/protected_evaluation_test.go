package risk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvaluatorProtectedProvidersDeferVelocityAndRetainOriginalExpiry(t *testing.T) {
	config := testPolicyConfig()
	config.Profiles[1].RequiredSignals = []string{"velocity", "status", "captcha"}
	policy, err := NewPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now
	calls := 0
	status := cleanSource("status")
	status.Read = func(_ context.Context, c Context) (Signal, error) {
		calls++
		s := testSignal(c, "status", SignalClean)
		s.ExpiresAt = c.Now.Add(time.Second)
		return s, nil
	}
	velocity := cleanSource("velocity")
	velocity.Read = func(context.Context, Context) (Signal, error) {
		t.Fatal("provider preparation accessed command-owned velocity")
		return Signal{}, nil
	}
	e, err := NewEvaluator(EvaluatorConfig{Policy: policy, Clock: func() time.Time { return now }, Timeout: 5 * time.Second, Sources: []Source{velocity, status, cleanSource("captcha")}})
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.mfa.totp-verify"
	r, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: NonIssuing})
	if err != nil || r.Decision.Action != Allow || calls != 1 || r.counter != nil || len(r.assessment.Signals) != 2 {
		t.Fatal("protected providers unavailable", err)
	}
	if err := e.RequireProtectedProviderAdmission(t.Context(), r, c); err != nil {
		t.Fatal("owned fresh providers denied", err)
	}
	forged := r
	forged.provenance = nil
	if err := e.RequireProtectedProviderAdmission(t.Context(), forged, c); err == nil {
		t.Fatal("public decision substituted for provider provenance")
	}
	foreign := c
	foreign.Attempt = "foreign"
	if err := e.RequireProtectedProviderAdmission(t.Context(), r, foreign); err == nil {
		t.Fatal("foreign attempt adopted observations")
	}
	if err := e.RequireAuthenticationAdmission(t.Context(), r, c, Subject{}); err == nil {
		t.Fatal("provider-only result granted authentication admission")
	}
	if _, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: NonIssuing, Subject: Subject{User: "caller"}}); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("caller dimensions substituted for native counters", err)
	}
	if _, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: PhoneResetCompletion}); !errors.Is(err, ErrUnsupportedIssuance) {
		t.Fatal("provider preparation issued evidence", err)
	}
	now = now.Add(time.Second)
	if err := e.RequireProtectedProviderAdmission(t.Context(), r, c); err == nil || calls != 1 {
		t.Fatal("original expiry renewed or sources rerun")
	}
	c.Operation = "identity.password.signin"
	if _, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: NonIssuing}); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("authentication bypass admitted", err)
	}
}

func TestProtectedEvaluatorRetainsDenialAndUnavailablePolicy(t *testing.T) {
	for _, failure := range []bool{false, true} {
		config := testPolicyConfig()
		config.Profiles[1].RequiredSignals = []string{"velocity", "status", "captcha"}
		policy, err := NewPolicy(config)
		if err != nil {
			t.Fatal(err)
		}
		now := testContext().Now
		status := cleanSource("status")
		status.Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalDeny)
			if failure {
				s.State = SignalClean
				return s, errors.New("private provider diagnostic")
			}
			return s, nil
		}
		e, err := NewEvaluator(EvaluatorConfig{Policy: policy, Clock: func() time.Time { return now }, Timeout: time.Second, Sources: []Source{cleanSource("velocity"), status, cleanSource("captcha")}})
		if err != nil {
			t.Fatal(err)
		}
		c := testContext()
		c.Operation = "identity.mfa.totp-verify"
		r, err := e.EvaluateProtectedProviders(t.Context(), EvaluateRequest{Context: c, Phase: NonIssuing})
		if err != nil || r.Decision.Action != Deny {
			t.Fatal("provider denial weakened", failure, err)
		}
		if err := e.RequireProtectedProviderAdmission(t.Context(), r, c); !errors.Is(err, ErrInvalidProtectedProviderAdmission) {
			t.Fatal("denied facts granted admission", err)
		}
	}
}
