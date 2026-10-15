package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

func TestRecoveryRejectsInvalidCompositionBeforeIO(t *testing.T) {
	var c *Coordinator
	q, caller := queryInputs(codecBinding())
	if r, err := c.RecoverCommand(context.Background(), q, caller); err == nil || r != (CommandRecord{}) {
		t.Fatal("invalid recovery composition admitted")
	}
}

func TestRecoveryWorkHasInvocationScopedDeclarations(t *testing.T) {
	w, _, ap := auditFixture(t)
	plan := &admittedKernelPlan{audits: []AuditPlan{ap}, lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}}
	s := &recoveryWorkState{work: w, plan: plan, entry: registeredContributor{descriptor: ContributorDescriptor{Owner: "audit/postgres"}}, active: true}
	rw := RecoveryWork{state: s}
	got, err := rw.AuditPlan()
	if err != nil || got != ap {
		t.Fatal("frozen audit lost", err)
	}
	got.RetentionPolicyVersion++
	if again, _ := rw.AuditPlan(); again != ap {
		t.Fatal("declaration alias escaped")
	}
	second := ap
	second.EventIndex++
	plan.audits = append(plan.audits, second)
	plans, err := rw.AuditPlans()
	if err != nil || len(plans) != 2 || plans[0] != ap || plans[1] != second {
		t.Fatal("complete frozen audit slots lost", err)
	}
	plans[0].RetentionPolicyVersion++
	if again, _ := rw.AuditPlans(); again[0] != ap {
		t.Fatal("audit slot slice alias escaped")
	}
	if _, err := rw.AuditPlan(); err == nil {
		t.Fatal("singular getter hid multiple slots")
	}
	if _, err := rw.LifecyclePlan(); err == nil {
		t.Fatal("foreign declaration exposed")
	}
	s.entry.descriptor.Owner = "outbox/postgres"
	if got, err := rw.LifecyclePlan(); err != nil || got != *plan.lifecycle {
		t.Fatal("frozen lifecycle lost")
	}
	if _, err := rw.AuditPlan(); err == nil {
		t.Fatal("foreign audit exposed")
	}
	if _, err := rw.AuditPlans(); err == nil {
		t.Fatal("foreign audit slots exposed")
	}
	s.active = false
	if _, err := rw.Scope(); err == nil {
		t.Fatal("invocation alias survived")
	}
	if _, err := rw.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("expired query admitted")
	}
	if _, err := rw.AuditPlan(); err == nil {
		t.Fatal("expired audit exposed")
	}
	if _, err := rw.AuditPlans(); err == nil {
		t.Fatal("expired audit slots exposed")
	}
	if _, err := rw.LifecyclePlan(); err == nil {
		t.Fatal("expired lifecycle exposed")
	}
	if _, err := json.Marshal(rw); err == nil {
		t.Fatal("authority serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", rw), string(w.state.binding.CommandID)) {
		t.Fatal("scope disclosed in diagnostic")
	}
}

func TestPublicRecoveryDenialAndScopeDoNotAcquireOwnership(t *testing.T) {
	b := codecBinding()
	q, caller := queryInputs(b)
	state := "pending"
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, denied := range []bool{false, true} {
		c, _, _ := coordinatorFixture(t)
		reads, decisions := 0, 0
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			decisions++
			outcome := authorization.Allow
			if denied {
				outcome = authorization.Deny
			}
			return authorization.Decision{Outcome: outcome, Revision: 9}, nil
		})}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
			reads++
			return commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), plan: queryFrozenPlan(t, b), fingerprint: queryFingerprint(), state: &state, until: &now, now: now}, nil
		}
		foreign := q
		dc := caller
		if !denied {
			foreign.UserID = "foreign"
			dc = callerForQuery(caller, foreign)
		}
		got, err := c.RecoverCommand(context.Background(), foreign, dc)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got != (CommandRecord{}) || reads != 1 || decisions != 1 {
			t.Fatal("denied/wrong scope recovery changed work shape")
		}
	}
}
