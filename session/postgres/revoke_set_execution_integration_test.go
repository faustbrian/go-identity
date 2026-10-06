//go:build integration

package postgres

import (
	"context"
	"errors"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"testing"
	"time"
)

func testPublicSetRevocation(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, validation session.ServiceConfig, reader *session.SessionService, issue func(*testing.T) (session.GetResult, session.GetRequest)) {
	t.Helper()
	execution.Coordinator.FinalAuthentication = nil
	validation.Clock = nil
	config := SetRevocationServiceConfig{Execution: execution, Validation: validation, MaximumSessions: 100, MaximumDuration: 2 * time.Second}
	prepare := func(t *testing.T, source session.GetResult, all, include bool) session.RevokeSetRequest {
		t.Helper()
		spec, _ := source.Session.Bindings()
		op := session.RevokeOtherOperation()
		if all {
			op = session.RevokeAllOperation()
		}
		b := revokeBinding()
		b.TenantID, b.UserID, b.ActorID, b.RecordID, b.OperationID, b.SchemaID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID), spec.SessionID, op.OperationID, op.SchemaID
		var err error
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		var command session.SessionCommand
		if all {
			command, err = session.NewRevokeAllCommand(b, source.Session, include, 100)
		} else {
			command, err = session.NewRevokeOtherCommand(b, source.Session, 100)
		}
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRevokeSet(source, command)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	t.Run("owned bulk policy and foreign reader deny before reservation", func(t *testing.T) {
		source, _ := issue(t)
		request := prepare(t, source, false, false)
		denied := execution
		denied.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		executor, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: denied, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		result, err := executor.ExecuteRevokeSet(ctx, request)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || result.Receipt.Outcome != identity.CommitOutcomeInvalid || result.RevokedCount != 0 {
			t.Fatal("bulk denial executed", err)
		}
		foreign := *reader
		executor, err = NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: execution, Sessions: &foreign})
		if err != nil {
			t.Fatal(err)
		}
		result, err = executor.ExecuteRevokeSet(ctx, request)
		if !errors.Is(err, session.ErrUnauthenticated) || result.Receipt.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("foreign bulk custody accepted", err)
		}
		command, _ := request.Command()
		set, _ := command.RevokeSet()
		var n int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, set.Binding.CommandID)).Scan(&n); err != nil || n != 0 {
			t.Fatal("denied bulk reserved", err, n)
		}
	})
	t.Run("owned bulk retained replay and restart recovery", func(t *testing.T) {
		source, _ := issue(t)
		issue(t)
		request := prepare(t, source, true, false)
		executor, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: execution, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		result, err := executor.ExecuteRevokeSet(ctx, request)
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.RevokedCount < 1 || result.CurrentSessionRevoked {
			t.Fatal("owned bulk commit", err)
		}
		replay, err := executor.ExecuteRevokeSet(ctx, request)
		if err != nil || replay.Receipt.AuditEventID != result.Receipt.AuditEventID || replay.RevokedCount != result.RevokedCount || replay.SubjectVersion != result.SubjectVersion {
			t.Fatal("bulk replay changed result", err)
		}
		b := result.Receipt.Binding
		q, caller := revokeRecoveryInput(b)
		restarted, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: execution, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
		if err != nil || recovered.Command.Outcome != identity.CommitOutcomeCommitted || recovered.RevokedCount != result.RevokedCount || recovered.SubjectVersion != result.SubjectVersion || recovered.SessionVersion != result.Receipt.Feature.AfterVersion || recovered.CurrentSessionRevoked {
			t.Fatal("bulk restart recovery", err)
		}
		// Retained results do not depend on live source payloads. Pruning
		// cannot recreate admission or erase the command's historical result.
		if _, err = pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), b.RecordID); err != nil {
			t.Fatal(err)
		}
		pruned, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
		if err != nil || pruned.RevokedCount != recovered.RevokedCount || pruned.SessionVersion != recovered.SessionVersion {
			t.Fatal("payload pruning lost historical result", err)
		}
		var originalDigest []byte
		id := mustCommandBytes(t, b.CommandID)
		if err = pool.Raw().QueryRow(ctx, `SELECT result_digest FROM session_store.set_revocations WHERE command_id=$1`, id).Scan(&originalDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.set_revocations SET result_digest=$2 WHERE command_id=$1`, id, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.set_revocations SET result_digest=$2 WHERE command_id=$1`, id, originalDigest); err != nil {
				t.Error("retained evidence restoration failed")
			}
		}()
		corrupt, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
		if err == nil || corrupt.Command.Outcome != identity.CommitOutcomeCommitted || corrupt.RevokedCount != 0 || corrupt.SubjectVersion != 0 || corrupt.SessionVersion != 0 || corrupt.CurrentSessionRevoked {
			t.Fatal("corrupt metadata fabricated result or lost known commit", err)
		}
		q.TenantID = "foreign"
		if foreign, err := restarted.RecoverRevokeSetCommand(ctx, q, caller); err == nil || foreign.Command.Binding.CommandID != "" || foreign.RevokedCount != 0 {
			t.Fatal("foreign retained result leaked")
		}
	})
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run("public bulk "+mode, func(t *testing.T) {
			source, input := issue(t)
			sibling, _ := issue(t)
			spec, _ := source.Session.Bindings()
			vector, _ := spec.Authority.Bindings()
			var before int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(spec.TenantID), string(spec.UserID)).Scan(&before); err != nil {
				t.Fatal(err)
			}
			service, err := NewSetRevocationService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			var out session.RevokeSetResult
			if mode == "other" {
				out, err = service.RevokeOther(ctx, session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: id, CorrelationID: "public-bulk"})
			} else {
				out, err = service.RevokeAll(ctx, session.RevokeAllInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: id, CorrelationID: "public-bulk", IncludeCurrent: mode == "all-include", ExpectedSubjectVersion: vector.User.Version})
			}
			want := before - 1
			if mode == "all-include" {
				want = before
			}
			if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || int(out.RevokedCount) != want || out.SubjectVersion != vector.User.Version || out.SessionVersion != spec.Version+1 || out.CurrentSessionRevoked != (mode == "all-include") {
				t.Fatal("public bulk result", err, out.CommitOutcome, out.RevokedCount, want)
			}
			stored, err := reader.Get(ctx, input)
			if err != nil || stored.Authenticated == (mode == "all-include") {
				t.Fatal("source disposition authentication", err)
			}
			target, _ := sibling.Session.Bindings()
			native, err := NewRepository(pool, execution.Repository)
			if err != nil {
				t.Fatal(err)
			}
			tombstone, err := native.Get(ctx, target.TenantID, target.SessionID)
			if err != nil || !tombstone.Revoked {
				t.Fatal("public target not revoked", err)
			}
		})
	}
}
