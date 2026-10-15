package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

func TestPasswordMFAHistoryExposesOnlyAuthorizedCommittedScope(t *testing.T) {
	b, plan := passwordMFAPlanFixture(t)
	claim := claimRequest{commandID: b.CommandID, tenant: b.TenantID, purpose: b.OperationID, safeFields: commandSafeFields(b, &plan.Feature.Operation), feature: &plan.Feature.Operation}
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, plan)
	if err != nil {
		t.Fatal(err)
	}
	result := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: plan.Feature.Operation}}
	body, err := encodeJournalResult(claim, result)
	if err != nil {
		t.Fatal(err)
	}
	state, class, version := "committed", "committed", int32(1)
	now := time.Now().UTC().Truncate(time.Microsecond)
	observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, fingerprint: fp[:], state: &state, until: &now, now: now, plan: wire, resultVersion: &version, class: &class, result: body}
	c, _, _ := coordinatorFixture(t)
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	q, caller := queryInputs(b)
	scope, record, present, err := c.QueryPasswordMFAChallenge(context.Background(), q, caller)
	if err != nil || !present || scope != *plan.MFAContinuation || record.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("committed original scope lost", err)
	}
	observed.state, observed.resultVersion, observed.class, observed.result = &state, nil, nil, nil
	state = "pending"
	scope, record, present, err = c.QueryPasswordMFAChallenge(context.Background(), q, caller)
	if err != nil || !present || scope != (MFAContinuationPlan{}) || record.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("pending primary disclosed scope", err)
	}
	caller.Request.Subject.ID = "foreign"
	if scope, _, _, err := c.QueryPasswordMFAChallenge(context.Background(), q, caller); err == nil || scope != (MFAContinuationPlan{}) {
		t.Fatal("foreign caller disclosed primary scope")
	}
}
