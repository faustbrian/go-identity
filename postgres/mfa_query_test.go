package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func TestQueryMFATOTPCommandRetainsDenialWithoutCurrentContinuation(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	b, p := mfaCompletionPlanFixture(t, "totp-verify")
	spec := identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}}
	command := codeCodecCommand(t, spec, "123456")
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal(err)
	}
	receipt := featureOutcome(b, &spec.Operation, identity.CommitOutcomeNotCommitted, 0)
	body, err := encodeJournalResult(claim, receipt)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, class, version := "aborted", "denied", int32(1)
	observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, state: &state, until: &now, now: now, resultVersion: &version, class: &class, result: body, plan: wire, fingerprint: fp[:], fingerprintKeyVersion: int64(c.keys.current)}
	_, caller := queryInputs(b)
	c.queryPolicy = &CommandQueryPolicy{Clock: finalProofClock{now}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.admissionPolicy = c.queryPolicy
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	// Current key and continuation state may advance; neither replaces history.
	c.keys.current = 2
	c.keys.retained[2] = [32]byte{2}
	got, found, err := c.QueryMFATOTPCommand(t.Context(), command, caller)
	var forbidden identity.ForbiddenError
	if !found || got.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &forbidden) {
		t.Fatal("original denial lost", found, err)
	}
	changed := codeCodecCommand(t, spec, "654321")
	got, found, err = c.QueryMFATOTPCommand(t.Context(), changed, caller)
	var conflict identity.ConflictError
	if !found || got.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		t.Fatal("changed code adopted denial", found, err)
	}
	for _, mode := range []string{"retired", "missing-key", "corrupt-plan", "corrupt-receipt", "read-failure"} {
		t.Run(mode, func(t *testing.T) {
			copy := observed
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
				switch mode {
				case "retired":
					copy.retired = true
				case "missing-key":
					copy.fingerprintKeyVersion = 3
				case "corrupt-plan":
					copy.plan = []byte("invalid")
				case "corrupt-receipt":
					copy.result = []byte("invalid")
				case "read-failure":
					return commandObservation{}, errors.New("private dependency failure")
				}
				return copy, nil
			}
			got, _, err := c.QueryMFATOTPCommand(t.Context(), command, caller)
			if err == nil || got != (identity.CommandResult{}) {
				t.Fatal("unproved history returned", mode, err)
			}
		})
	}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		return commandObservation{}, pgx.ErrNoRows
	}
	got, found, err = c.QueryMFATOTPCommand(t.Context(), command, caller)
	if found || err != nil || got != (identity.CommandResult{}) {
		t.Fatal("authorized absence unavailable", found, err)
	}
	c.queryPolicy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
	})
	_, found, err = c.QueryMFATOTPCommand(t.Context(), command, caller)
	if found || !errors.As(err, &forbidden) {
		t.Fatal("absence disclosed without policy", found, err)
	}
}
