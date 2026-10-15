//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// The restarted composition receives only safe query scope, not the original
// request, proof, bearer, preparation or original reader instance.
func testRotationRestartRecovery(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, validation session.ServiceConfig, b identity.CommandBinding, expected identity.CommandResult) {
	t.Helper()
	reader, err := NewSessionService(pool, SessionServiceConfig{Repository: execution.Repository, Profile: IdentifierAdmissionConfig(execution.Profile), Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRotationExecutor(pool, RotationExecutorConfig{Execution: execution, Sessions: reader})
	if err != nil {
		t.Fatal(err)
	}
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(execution.PolicyVersion), CorrelationID: "restart-rotation", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	t.Run("restart returns exact historical receipt", func(t *testing.T) {
		for range 2 {
			got, err := restarted.RecoverRotationCommand(ctx, q, caller)
			if err != nil || !reflect.DeepEqual(got, expected) {
				t.Fatal("restart changed historical receipt", err)
			}
		}
	})
	t.Run("denied missing and substituted scope disclose nothing", func(t *testing.T) {
		queries := []identity.RecoveryQuery{q, q, q, q, q, q}
		queries[0].TenantID = "foreign"
		queries[1].UserID = "foreign"
		queries[2].RecordID = "foreign"
		queries[3].OperationID = session.RevokeOneOperation().OperationID
		queries[4].ActorID = "foreign"
		queries[5].CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		for _, query := range queries {
			got, err := restarted.RecoverRotationCommand(ctx, query, caller)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got.Binding.CommandID != "" || got.Feature != nil {
				t.Fatal("substituted scope disclosed history", err)
			}
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, queries[5].CommandID)).Scan(&count); err != nil || count != 0 {
			t.Fatal("missing recovery reserved command", err)
		}
		deniedConfig := execution
		deniedConfig.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: authorization.Revision(execution.PolicyVersion)}, nil
		})
		denied, err := NewRotationExecutor(pool, RotationExecutorConfig{Execution: deniedConfig, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		got, err := denied.RecoverRotationCommand(ctx, q, caller)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got.Binding.CommandID != "" || got.Feature != nil {
			t.Fatal("current denial disclosed history", err)
		}
	})
	t.Run("cancelled restart discloses nothing", func(t *testing.T) {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		got, err := restarted.RecoverRotationCommand(cancelled, q, caller)
		if err == nil || got.Binding.CommandID != "" || got.Feature != nil {
			t.Fatal("cancelled restart disclosed history")
		}
	})
	t.Run("pruned payload does not erase committed history", func(t *testing.T) {
		if tag, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), b.RecordID); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("prune live payload fixture", err)
		}
		got, err := restarted.RecoverRotationCommand(ctx, q, caller)
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Fatal("payload pruning erased committed receipt", err)
		}
	})
}
