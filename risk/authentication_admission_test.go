package risk

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func TestAuthenticationAdmissionBindsOriginalCountedAllowance(t *testing.T) {
	now := testContext().Now
	calls := 0
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		calls++
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	audited := auditedConfig(t, &now, decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
		return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
	}))
	cfg.DecisionAudit = audited.DecisionAudit
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := auditRequest(t)
	request.Context.Operation = "identity.otp.send"
	request.Subject = counterSubject()
	result, err := e.Evaluate(context.Background(), request)
	if err != nil || result.Decision.Action != Allow {
		t.Fatal("evaluation", err)
	}
	if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); err != nil {
		t.Fatal("genuine original allowance rejected", err)
	}
	foreign := request.Subject
	foreign.IdentifierDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, foreign); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("foreign identifier admitted", err)
	}
	if calls != 1 {
		t.Fatal("validation dispatched another mutation")
	}
	now = now.Add(5 * time.Minute)
	if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("expired original allowance renewed", err)
	}
}

func authenticationAdmissionFixture(t *testing.T, outcome CounterOutcome, value uint64, audited bool) (Evaluator, EvaluateRequest, EvaluateResult, *time.Time, *int) {
	t.Helper()
	now := testContext().Now
	calls := 0
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		calls++
		var snapshot []Counter
		if outcome == CounterCommitted {
			snapshot = snapshotFor(c, value)
		}
		return NewCounterResult(c, outcome, snapshot)
	}))
	if audited {
		auditCfg := auditedConfig(t, &now, decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
			return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
		}))
		cfg.DecisionAudit = auditCfg.DecisionAudit
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := auditRequest(t)
	request.Context.Operation = "identity.otp.send"
	request.Subject = counterSubject()
	if !audited {
		request.Attribution = nil
	}
	result, err := e.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return e, request, result, &now, &calls
}

func TestAuthenticationAdmissionRejectsSourceOnlyAndFailedAudit(t *testing.T) {
	for _, failAudit := range []bool{false, true} {
		now := testContext().Now
		cfg := auditedConfig(t, &now, decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
			if failAudit {
				return audit.AppendResult{}, errors.New("private audit failure")
			}
			return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
		}))
		if failAudit {
			counted := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
				return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
			}))
			counted.DecisionAudit = cfg.DecisionAudit
			cfg = counted
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		request := auditRequest(t)
		request.Context.Operation = "identity.otp.send"
		if failAudit {
			request.Subject = counterSubject()
		}
		result, err := e.Evaluate(context.Background(), request)
		if failAudit && !errors.Is(err, ErrDecisionAuditUnavailable) {
			t.Fatal("audit failure lost", err)
		}
		if !failAudit && (err != nil || result.Decision.Action != Allow) {
			t.Fatal("source-only fixture", err)
		}
		if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
			t.Fatal("unproven allowance admitted", err)
		}
	}
}

func TestAuthenticationAdmissionClockFailureAndLateCancellation(t *testing.T) {
	e, request, result, _, _ := authenticationAdmissionFixture(t, CounterCommitted, 1, true)
	// The clock is a server callback; no panic diagnostics cross this boundary.
	e.state.clock = func() time.Time { panic("private clock failure") }
	if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("clock failure admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.state.clock = func() time.Time { cancel(); return testContext().Now }
	if err := e.RequireAuthenticationAdmission(ctx, result, request.Context, request.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation lost", err)
	}
}

func TestAuthenticationAdmissionRejectsForeignOrFabricatedResults(t *testing.T) {
	e, request, result, _, calls := authenticationAdmissionFixture(t, CounterCommitted, 1, true)
	foreign, _, _, _, _ := authenticationAdmissionFixture(t, CounterCommitted, 1, true)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EvaluateResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]EvaluateResult{
		"zero": {}, "literal": {Decision: result.Decision, PolicyVersion: result.PolicyVersion}, "serialized": decoded,
	} {
		t.Run(name, func(t *testing.T) {
			if err := e.RequireAuthenticationAdmission(context.Background(), candidate, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
				t.Fatal("fabricated result admitted", err)
			}
		})
	}
	if err := foreign.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("foreign evaluator admitted", err)
	}
	for name, change := range map[string]func(*Context, *Subject){
		"tenant":          func(c *Context, _ *Subject) { c.Tenant += "other" },
		"attempt":         func(c *Context, _ *Subject) { c.Attempt += "other" },
		"operation":       func(c *Context, _ *Subject) { c.Operation = "identity.password.signin" },
		"network":         func(_ *Context, s *Subject) { s.Network = "192.0.2.10" },
		"device":          func(_ *Context, s *Subject) { s.Device = "another-device" },
		"extra-dimension": func(_ *Context, s *Subject) { s.User = "user" },
	} {
		t.Run(name, func(t *testing.T) {
			scope, subject := request.Context, request.Subject
			change(&scope, &subject)
			if err := e.RequireAuthenticationAdmission(context.Background(), result, scope, subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
				t.Fatal("foreign scope admitted", err)
			}
		})
	}
	// Canonical network equivalence is not a new logical counter command.
	equivalent := request.Subject
	equivalent.Network = "2001:db8::1"
	if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, equivalent); err != nil {
		t.Fatal("equivalent network rejected", err)
	}
	changed := result
	changed.PolicyVersion++
	if err := e.RequireAuthenticationAdmission(context.Background(), changed, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("changed version admitted", err)
	}
	changed = result
	changed.Decision.Action = Deny
	if err := e.RequireAuthenticationAdmission(context.Background(), changed, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("changed decision admitted", err)
	}
	if *calls != 1 {
		t.Fatal("validation repeated counter IO")
	}
}

func TestAuthenticationAdmissionRequiresAuditedCommittedAllow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome CounterOutcome
		value   uint64
		audited bool
	}{
		{"throttle", CounterCommitted, 11, true}, {"unknown", CounterUnknown, 0, true}, {"noncommit", CounterNotCommitted, 0, true}, {"unaudited", CounterCommitted, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, request, result, _, calls := authenticationAdmissionFixture(t, tc.outcome, tc.value, tc.audited)
			result.Decision = Decision{Action: Allow}
			if err := e.RequireAuthenticationAdmission(context.Background(), result, request.Context, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
				t.Fatal("restrictive/unproven result admitted", err)
			}
			if *calls != 1 {
				t.Fatal("validation repeated counter IO")
			}
		})
	}
}

func TestAuthenticationAdmissionOriginalExpiryAndContext(t *testing.T) {
	e, request, result, now, _ := authenticationAdmissionFixture(t, CounterCommitted, 1, true)
	original := *now
	// The source's original 30-second expiry is earlier than counter expiry.
	*now = original.Add(30*time.Second - time.Nanosecond)
	scope := request.Context
	scope.Now = original.Add(-time.Hour)
	scope.IndependentFactor = true
	if err := e.RequireAuthenticationAdmission(context.Background(), result, scope, request.Subject); err != nil {
		t.Fatal("fresh original result rejected", err)
	}
	*now = now.Add(time.Nanosecond)
	if err := e.RequireAuthenticationAdmission(context.Background(), result, scope, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("exclusive original expiry renewed", err)
	}
	*now = original.Add(-time.Nanosecond)
	if err := e.RequireAuthenticationAdmission(context.Background(), result, scope, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("backward clock admitted", err)
	}
	*now = original
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.RequireAuthenticationAdmission(canceled, result, scope, request.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := e.RequireAuthenticationAdmission(expired, result, scope, request.Subject); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline lost", err)
	}
	if err := e.RequireAuthenticationAdmission(nil, result, scope, request.Subject); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil context admitted", err)
	}
	if err := (Evaluator{}).RequireAuthenticationAdmission(context.Background(), result, scope, request.Subject); !errors.Is(err, ErrInvalidAuthenticationAdmission) {
		t.Fatal("zero evaluator admitted", err)
	}
}
