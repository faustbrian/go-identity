package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

func TestOTPDenialRecoveryBindsOriginalAttemptWithoutCode(t *testing.T) {
	c, command, p := otpAttemptFixture(t, &otpAttemptProbe{})
	s, _ := command.Feature()
	q, dc := queryInputs(s.Binding)
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
	result := featureOutcome(s.Binding, &s.Operation, identity.CommitOutcomeNotCommitted, 0)
	body, err := encodeJournalResult(claim, result)
	if err != nil {
		t.Fatal(err)
	}
	state, class, version := "aborted", "denied", int32(1)
	now := time.Now().UTC().Truncate(time.Microsecond)
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
		o := commandObservation{tenant: string(q.TenantID), purpose: q.OperationID, scope: claim.safeFields, fingerprint: fp[:], plan: plan, state: &state, until: &now, now: now}
		if state != "pending" {
			o.class, o.resultVersion, o.result = &class, &version, body
		}
		return o, nil
	}
	got, err := c.RecoverOTPAttemptDenial(context.Background(), q, *prepared.OTP, dc)
	var forbidden identity.ForbiddenError
	if got.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &forbidden) || reads != 1 || decisions != 1 {
		t.Fatal("original denied attempt not recovered", got.Outcome, err, reads, decisions)
	}
	for _, mutate := range []func(*OTPAttemptPlan){
		func(p *OTPAttemptPlan) { p.AttemptID = "AgICAgICAgICAgICAgICAg" },
		func(p *OTPAttemptPlan) { p.AttemptFingerprint[0]++ },
		func(p *OTPAttemptPlan) { p.FingerprintKeyVersion++ },
		func(p *OTPAttemptPlan) { p.ChallengeID += "other" },
		func(p *OTPAttemptPlan) { p.ScopeDigest[0]++ },
		func(p *OTPAttemptPlan) { p.DigestKeyVersion++ },
		func(p *OTPAttemptPlan) { p.ExpectedVersion++ },
		func(p *OTPAttemptPlan) { p.Mode = OTPCheck },
	} {
		other := *prepared.OTP
		mutate(&other)
		got, err = c.RecoverOTPAttemptDenial(context.Background(), q, other, dc)
		if got.Outcome != identity.CommitOutcomeInvalid || !errors.As(err, &forbidden) {
			t.Fatal("changed attempt disclosed history", got.Outcome, err)
		}
	}
	allow = false
	beforeReads, beforeDecisions := reads, decisions
	got, err = c.RecoverOTPAttemptDenial(context.Background(), q, *prepared.OTP, dc)
	if got.Outcome != identity.CommitOutcomeInvalid || !errors.As(err, &forbidden) || reads != beforeReads+1 || decisions != beforeDecisions+1 {
		t.Fatal("current policy bypass or changed read shape")
	}
	allow = true
	state = "pending"
	got, err = c.RecoverOTPAttemptDenial(context.Background(), q, *prepared.OTP, dc)
	if err != nil || got.Outcome != identity.CommitOutcomeInProgress || got.RetryAfter <= 0 {
		t.Fatal("pending attempt treated as noncommit proof", got.Outcome, err)
	}
	state, class = "aborted", "conflict"
	got, err = c.RecoverOTPAttemptDenial(context.Background(), q, *prepared.OTP, dc)
	var unavailable identity.UnavailableError
	if got.Outcome != identity.CommitOutcomeInvalid || !errors.As(err, &unavailable) {
		t.Fatal("non-denial terminal profile accepted")
	}
	beforeReads, beforeDecisions = reads, decisions
	got, err = c.RecoverOTPAttemptDenial(context.Background(), q, OTPAttemptPlan{}, dc)
	if err == nil || got.Outcome != identity.CommitOutcomeInvalid || reads != beforeReads || decisions != beforeDecisions {
		t.Fatal("invalid attempt performed IO")
	}
}
