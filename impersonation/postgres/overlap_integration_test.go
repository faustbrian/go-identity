//go:build integration

package impersonationpostgres

import (
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestImpersonationServiceCompetingApprovalPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	service, cfg, requester, approver := newM24ServiceFixture(t, ctx, pool)
	requestID := m24Must(identity.NewCommandID())
	request := m24Must(service.PrepareRequest(ctx, RequestInput{
		Authentication: requester,
		CommandID:      requestID,
		Target:         "target-user",
		Scope:          m24Must(impersonation.NewScope([]string{"address.read", "profile.read"})),
		Reason:         m24Must(impersonation.NewReason("private support case request")),
		Duration:       10 * time.Minute,
		Network:        "192.0.2.11",
	}))
	if result := m24Must(service.Execute(ctx, request)); result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("request did not commit the pending version", result.Outcome)
	}
	assertM24Grant(t, ctx, pool, requestID, "pending_approval", 1, 0)

	var approvals [2]PreparedCommand
	var bindings [2]identity.CommandBinding
	for index := range approvals {
		approvals[index] = m24Must(service.PrepareApproval(ctx, ApproveInput{
			Authentication:  approver,
			CommandID:       m24Must(identity.NewCommandID()),
			GrantID:         impersonation.GrantID(requestID),
			ExpectedVersion: 1,
			Reason:          m24Must(impersonation.NewReason("private distinct administrator approval")),
			Network:         "192.0.2.12",
		}))
		bindings[index] = m24Must(approvals[index].Binding())
		cfg.Authorization.(*m24Authorization).recovery[string(bindings[index].CommandID)] = bindings[index]
	}
	if bindings[0].CommandID == bindings[1].CommandID {
		t.Fatal("competing approvals reused a command instead of independent intent")
	}

	type execution struct {
		index  int
		result identity.CommandResult
		err    error
	}
	ready := make(chan struct{}, len(approvals))
	start := make(chan struct{})
	finished := make(chan execution, len(approvals))
	for index, command := range approvals {
		go func() {
			ready <- struct{}{}
			<-start
			result, err := service.Execute(ctx, command)
			finished <- execution{index: index, result: result, err: err}
		}()
	}
	for range approvals {
		<-ready
	}
	close(start)
	var results [2]execution
	for range approvals {
		completed := <-finished
		results[completed.index] = completed
	}

	winner, loser := -1, -1
	for index, completed := range results {
		if completed.result.Binding != bindings[index] {
			t.Fatal("competing execution returned another command's binding")
		}
		if completed.result.Outcome == identity.CommitOutcomeCommitted {
			if winner != -1 || completed.err != nil || completed.result.Feature == nil || completed.result.Feature.BeforeVersion != 1 || completed.result.Feature.AfterVersion != 2 {
				t.Fatal("competing approvals produced more than one successor or an invalid committed receipt", completed.result.Outcome, completed.err)
			}
			winner = index
			continue
		}
		var conflict identity.ConflictError
		if loser != -1 || completed.result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(completed.err, &conflict) || conflict.CommandID != bindings[index].CommandID {
			t.Fatal("losing approval did not settle as its own authoritative conflict", completed.result.Outcome, completed.err)
		}
		loser = index
	}
	if winner == -1 || loser == -1 {
		t.Fatal("competing approvals did not produce exactly one winner and one loser")
	}
	assertM24Grant(t, ctx, pool, requestID, "approved", 2, 1)
	assertM24CommandEffects(t, ctx, pool, requestID, 1)
	assertM24CommandEffects(t, ctx, pool, bindings[winner].CommandID, 1)
	assertM24DeniedEffects(t, ctx, pool, bindings[loser].CommandID)
	var decisionCommand string
	if err := pool.Raw().QueryRow(ctx, `SELECT command_id FROM identity_impersonation.approvals WHERE tenant_id='m24-tenant' AND grant_id=$1`, string(requestID)).Scan(&decisionCommand); err != nil || decisionCommand != string(bindings[winner].CommandID) {
		t.Fatal("durable decision was not bound to the winning command", err)
	}

	restarted := m24Must(NewService(pool, cfg))
	recovered, err := restarted.Recover(ctx, approver, bindings[loser])
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || conflict.CommandID != bindings[loser].CommandID || !reflect.DeepEqual(recovered, results[loser].result) {
		t.Fatal("restart recovery replaced the losing command's exact conflict result", recovered.Outcome, err)
	}
	assertM24Grant(t, ctx, pool, requestID, "approved", 2, 1)
	assertM24DeniedEffects(t, ctx, pool, bindings[loser].CommandID)
	assertM24NoSessionIssuance(t, ctx, pool)
}
