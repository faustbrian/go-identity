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

func TestFeatureRecoveryExcludesKernelHistoryBeforeOwnership(t *testing.T) {
	b := codecBinding()
	q, caller := queryInputs(b)
	for _, state := range []string{"pending", "committed"} {
		c, _, _ := coordinatorFixture(t)
		now := time.Now().UTC().Truncate(time.Microsecond)
		expired := now.Add(-time.Second)
		stored := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), plan: queryFrozenPlan(t, b), fingerprint: queryFingerprint(), state: &state, until: &expired, now: now}
		if state == "committed" {
			version, class := int32(1), "committed"
			private := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", User: identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}}
			var err error
			stored.result, err = encodeJournalResult(claimRequest{safeFields: stored.scope}, private)
			if err != nil {
				t.Fatal(err)
			}
			stored.resultVersion, stored.class = &version, &class
		}
		reads, decisions := 0, 0
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			decisions++
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { reads++; return stored, nil }
		c.pool, c.registry = nil, nil // Any reconciliation would fail, not return Forbidden.
		got, err := c.RecoverFeatureCommand(context.Background(), q, caller)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got.Binding.CommandID != "" || got.Feature != nil || got.User.ID != "" || reads != 1 || decisions != 1 {
			t.Fatal("kernel history disclosed or ownership attempted", state, err)
		}
	}
}

func TestFeatureRecoveryCompositionAndCallerFailures(t *testing.T) {
	q, caller := queryInputs(codecBinding())
	for _, c := range []*Coordinator{nil, {}, {maximumDuration: time.Minute + time.Nanosecond}} {
		if got, err := c.RecoverFeatureCommand(context.Background(), q, caller); err == nil || got.Binding.CommandID != "" {
			t.Fatal("invalid composition admitted")
		}
	}
	c, _, _ := coordinatorFixture(t)
	if _, err := c.RecoverFeatureCommand(nil, q, caller); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		t.Fatal("cancelled caller reached policy")
		return authorization.Decision{}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		t.Fatal("cancelled caller reached IO")
		return commandObservation{}, nil
	}
	var cancelled identity.CancelledError
	if _, err := c.RecoverFeatureCommand(ctx, q, caller); !errors.As(err, &cancelled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestFeatureRecoveryPreservesObservedScopeWhenPrimaryReconciliationFails(t *testing.T) {
	c, command, _, _, observed, caller, _ := authenticatedQueryFixture(t)
	spec, _ := command.Feature()
	state := "pending"
	until := observed.now.Add(time.Second)
	observed.state, observed.until = &state, &until
	observed.resultVersion, observed.class, observed.result = nil, nil, nil
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	// A primary read established pending history; loss of the primary connection
	// before reconciliation cannot prove rollback or erase that exact scope.
	c.pool = nil
	q, _ := queryInputs(spec.Binding)
	got, err := c.RecoverFeatureCommand(context.Background(), q, caller)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || got.Outcome != identity.CommitOutcomeUnknown || got.Binding != spec.Binding || got.Feature == nil || got.Feature.Operation != spec.Operation || got.Validate() != nil {
		t.Fatal("failed reconciliation erased observed scope", err)
	}
}
