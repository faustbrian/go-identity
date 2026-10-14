package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// SIGNIN-06: all historical outcomes must be bound to the original consuming
// plan without retaining code. This seam proves disclosure, not real SQL or OTP.
func TestConsumingOTPRecoveryMatchesEveryOriginalFieldBeforeDisclosure(t *testing.T) {
	c, command, p := otpAttemptFixture(t, &otpAttemptProbe{})
	s, _ := command.Feature()
	q, caller := queryInputs(s.Binding)
	prepared, err := c.PrepareOTPAttemptPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	fp := [32]byte{1}
	plan, err := encodeFeaturePlan(s.Binding, fp, prepared)
	if err != nil {
		t.Fatal(err)
	}
	claim := claimRequest{safeFields: commandSafeFields(s.Binding, &s.Operation), feature: &s.Operation}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Second)
	state, class, version := "committed", "committed", int32(1)
	body := []byte(nil)
	reads, decisions := 0, 0
	allow := true
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		outcome := authorization.Allow
		if !allow {
			outcome = authorization.Deny
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		reads++
		o := commandObservation{tenant: string(q.TenantID), purpose: q.OperationID, scope: claim.safeFields, fingerprint: fp[:], plan: plan, state: &state, until: &until, now: now}
		if state != "pending" {
			o.class, o.resultVersion, o.result = &class, &version, body
		}
		return o, nil
	}
	for _, terminal := range []struct {
		state, class string
		outcome      identity.CommitOutcome
	}{
		{"committed", "committed", identity.CommitOutcomeCommitted},
		{"aborted", "denied", identity.CommitOutcomeNotCommitted},
		{"aborted", "conflict", identity.CommitOutcomeNotCommitted},
		{"aborted", "cancelled", identity.CommitOutcomeNotCommitted},
		{"aborted", "deadline-exceeded", identity.CommitOutcomeNotCommitted},
		{"aborted", "dependency-failure", identity.CommitOutcomeNotCommitted},
	} {
		t.Run(terminal.class, func(t *testing.T) {
			state, class = terminal.state, terminal.class
			result := featureOutcome(s.Binding, &s.Operation, terminal.outcome, 0)
			if terminal.outcome == identity.CommitOutcomeCommitted {
				result.AuditEventID = "original-audit"
				result.Feature.BeforeVersion, result.Feature.AfterVersion = prepared.Lifecycle.BeforeVersion, prepared.Lifecycle.AfterVersion
			}
			body, err = encodeJournalResult(claim, result)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.RecoverOTPFeatureCommand(context.Background(), q, *prepared.OTP, caller)
			if got.Binding != s.Binding || got.Outcome != terminal.outcome || got.Feature == nil || got.Feature.Operation != s.Operation {
				t.Fatal("original consuming history lost", got.Outcome, err)
			}
			if (err == nil) != (terminal.outcome == identity.CommitOutcomeCommitted) {
				t.Fatal("terminal classification changed", err)
			}
			var denied identity.ForbiddenError
			var conflict identity.ConflictError
			var cancelled identity.CancelledError
			var deadline identity.DeadlineExceededError
			var unavailable identity.UnavailableError
			switch terminal.class {
			case "denied":
				if !errors.As(err, &denied) {
					t.Fatal("denial classification lost", err)
				}
			case "conflict":
				if !errors.As(err, &conflict) || conflict.CommandID != q.CommandID {
					t.Fatal("original conflict identity lost", err)
				}
			case "cancelled":
				if !errors.As(err, &cancelled) {
					t.Fatal("cancellation classification lost", err)
				}
			case "deadline-exceeded":
				if !errors.As(err, &deadline) {
					t.Fatal("deadline classification lost", err)
				}
			case "dependency-failure":
				if !errors.As(err, &unavailable) {
					t.Fatal("dependency classification lost", err)
				}
			}
		})
	}
	for _, mutate := range []func(*OTPAttemptPlan){
		func(p *OTPAttemptPlan) { p.AttemptID = "AgICAgICAgICAgICAgICAg" },
		func(p *OTPAttemptPlan) { p.AttemptFingerprint[0]++ },
		func(p *OTPAttemptPlan) { p.FingerprintKeyVersion++ },
		func(p *OTPAttemptPlan) { p.ChallengeID += "other" },
		func(p *OTPAttemptPlan) { p.ScopeDigest[0]++ },
		func(p *OTPAttemptPlan) { p.DigestKeyVersion++ },
		func(p *OTPAttemptPlan) { p.ExpectedVersion++ },
	} {
		other := *prepared.OTP
		mutate(&other)
		got, err := c.RecoverOTPFeatureCommand(context.Background(), q, other, caller)
		var denied identity.ForbiddenError
		if got.Outcome != identity.CommitOutcomeInvalid || got.Binding.CommandID != "" || !errors.As(err, &denied) {
			t.Fatal("changed correlation disclosed history", got.Outcome, err)
		}
	}
	allow = false
	beforeReads, beforeDecisions := reads, decisions
	got, err := c.RecoverOTPFeatureCommand(context.Background(), q, *prepared.OTP, caller)
	var denied identity.ForbiddenError
	if got.Outcome != identity.CommitOutcomeInvalid || !errors.As(err, &denied) || reads != beforeReads+1 || decisions != beforeDecisions+1 {
		t.Fatal("current denial changed read shape or disclosed history")
	}
	allow = true
	state = "pending"
	c.pool = nil // Reconciliation is unavailable, not proof of noncommit.
	got, err = c.RecoverOTPFeatureCommand(context.Background(), q, *prepared.OTP, caller)
	var unknown identity.UnknownCommitError
	if got.Outcome != identity.CommitOutcomeUnknown || got.Binding != s.Binding || got.Feature == nil || !errors.As(err, &unknown) {
		t.Fatal("lost primary erased original pending outcome", got.Outcome, err)
	}
	other := *prepared.OTP
	other.AttemptFingerprint[0]++
	got, err = c.RecoverOTPFeatureCommand(context.Background(), q, other, caller)
	if got.Outcome != identity.CommitOutcomeInvalid || !errors.As(err, &denied) {
		t.Fatal("mismatched pending plan reached reconciliation", got.Outcome, err)
	}
	beforeReads, beforeDecisions = reads, decisions
	for _, invalid := range []OTPAttemptPlan{{}, {Mode: OTPCheck}} {
		if _, err := c.RecoverOTPFeatureCommand(context.Background(), q, invalid, caller); err == nil {
			t.Fatal("invalid consuming protocol accepted")
		}
	}
	if reads != beforeReads || decisions != beforeDecisions {
		t.Fatal("invalid plan performed IO")
	}
}

func TestConsumingOTPRecoveryRejectsInvalidComposition(t *testing.T) {
	q, caller := queryInputs(codecBinding())
	_, plan := otpPlanFixture(t)
	for _, c := range []*Coordinator{nil, {}, {maximumDuration: time.Minute + time.Nanosecond}} {
		if r, err := c.RecoverOTPFeatureCommand(context.Background(), q, *plan.OTP, caller); err == nil || r.Binding.CommandID != "" {
			t.Fatal("invalid composition accepted")
		}
	}
	c, _, _ := coordinatorFixture(t)
	if _, err := c.RecoverOTPFeatureCommand(nil, q, *plan.OTP, caller); err == nil {
		t.Fatal("nil context accepted")
	}
}
