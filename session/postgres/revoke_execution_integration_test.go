//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testOwnedRevokeExecution(t *testing.T, ctx context.Context, pool *database.Pool, reader *session.SessionService, credential session.GetRequest, original session.GetResult, config IssueExecutorConfig, readerConfig SessionServiceConfig, issue func(*testing.T) session.GetResult) {
	t.Helper()
	// Session authentication is sufficient; final signin proof issuance is not
	// a mandatory revocation bootstrap dependency.
	config.Coordinator.FinalAuthentication = nil
	executor, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: reader})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T, source session.GetResult, target session.Session) session.RevokeOneRequest {
		t.Helper()
		spec, _ := target.Bindings()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID)
		b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, e := session.NewRevokeOneCommand(b, target)
		if e != nil {
			t.Fatal(e)
		}
		request, e := reader.PrepareRevokeOne(source, command)
		if e != nil {
			t.Fatal(e)
		}
		return request
	}
	assertState := func(t *testing.T, record session.Session, revoked bool) {
		t.Helper()
		spec, _ := record.Bindings()
		stored, e := executor.owned.native.Get(ctx, spec.TenantID, spec.SessionID)
		if e != nil || stored.Revoked != revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != spec.FamilyVersion {
			t.Fatal("session/family state", e)
		}
		a, _, _ := encodeRecord(stored.Session)
		b, _, _ := encodeRecord(record)
		if string(a) != string(b) {
			t.Fatal("original record rewritten")
		}
	}
	claims := func(t *testing.T, request session.RevokeOneRequest, want int) {
		t.Helper()
		command, _ := request.Command()
		one, _ := command.RevokeOne()
		var count int
		if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, one.Binding.CommandID)).Scan(&count); e != nil || count != want {
			t.Fatal("reservation count", e)
		}
	}
	t.Run("owned caller target commit replay recovery", func(t *testing.T) {
		target := issue(t)
		request := prepare(t, original, target.Session)
		result, e := executor.ExecuteRevokeOne(ctx, request)
		if e != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("owned revocation", e)
		}
		assertState(t, target.Session, true)
		assertState(t, original.Session, false)
		replayed, e := executor.ExecuteRevokeOne(ctx, request)
		if e != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.AuditEventID != result.AuditEventID {
			t.Fatal("replay changed terminal outcome", e)
		}
		refreshed, e := reader.Get(ctx, credential)
		if e != nil || !refreshed.Authenticated {
			t.Fatal("new caller read", e)
		}
		command, _ := request.Command()
		changed, e := reader.PrepareRevokeOne(refreshed, command)
		if e != nil {
			t.Fatal(e)
		}
		if changed.ValidUntil().Equal(request.ValidUntil()) {
			t.Fatal("fixture did not change original input")
		}
		conflict, e := executor.ExecuteRevokeOne(ctx, changed)
		if e == nil || conflict.Outcome != identity.CommitOutcomeConflict {
			t.Fatal("command ID accepted changed source validity", e)
		}
		query := identity.RecoveryQuery{CommandID: result.Binding.CommandID, TenantID: result.Binding.TenantID, UserID: result.Binding.UserID, ActorID: result.Binding.ActorID, ActorKind: result.Binding.ActorKind, OperationID: result.Binding.OperationID, RecordID: result.Binding.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(result.Binding.PolicyVersion), CorrelationID: result.Binding.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(result.Binding.ActorID), Kind: result.Binding.ActorKind}, Action: authorization.Action(result.Binding.OperationID), Tenant: authorization.TenantID(result.Binding.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(result.Binding.UserID)}}}
		restarted, e := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: reader})
		if e != nil {
			t.Fatal(e)
		}
		history, e := restarted.RecoverRevokeOneCommand(ctx, query, caller)
		if e != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != result.Binding {
			t.Fatal("restart history lost", e)
		}
		id := mustCommandBytes(t, result.Binding.CommandID)
		var n, audits, events int
		if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&n, &audits, &events); e != nil || n != 1 || audits != 1 || events != 1 {
			t.Fatal("duplicate/missing effects", e)
		}
	})
	t.Run("current denial before reservation", func(t *testing.T) {
		target := issue(t)
		request := prepare(t, original, target.Session)
		deniedConfig := config
		deniedConfig.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		denied, e := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: deniedConfig, Sessions: reader})
		if e != nil {
			t.Fatal(e)
		}
		result, e := denied.ExecuteRevokeOne(ctx, request)
		var forbidden identity.ForbiddenError
		if !errors.As(e, &forbidden) || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("policy denial executed", e)
		}
		claims(t, request, 0)
		assertState(t, target.Session, false)
	})
	t.Run("foreign configured reader denied before reservation", func(t *testing.T) {
		target := issue(t)
		request := prepare(t, original, target.Session)
		foreign := *reader
		other, e := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: &foreign})
		if e != nil {
			t.Fatal(e)
		}
		result, e := other.ExecuteRevokeOne(ctx, request)
		if !errors.Is(e, session.ErrUnauthenticated) || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("foreign reader admitted custody", e)
		}
		claims(t, request, 0)
		assertState(t, target.Session, false)
	})
	t.Run("cached source revocation denies live target", func(t *testing.T) {
		source := issue(t)
		target := issue(t)
		request := prepare(t, source, target.Session)
		spec, _ := source.Session.Bindings()
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(spec.TenantID), spec.SessionID); e != nil {
			t.Fatal(e)
		}
		result, e := executor.ExecuteRevokeOne(ctx, request)
		if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("cached revoked source authorized")
		}
		assertState(t, target.Session, false)
	})
	t.Run("cross revocation serialized without lock upgrade deadlock", func(t *testing.T) {
		a, b := issue(t), issue(t)
		requests := []session.RevokeOneRequest{prepare(t, a, b.Session), prepare(t, b, a.Session)}
		var results [2]identity.CommandResult
		var failures [2]error
		var wg sync.WaitGroup
		for i := range requests {
			wg.Add(1)
			go func() { defer wg.Done(); results[i], failures[i] = executor.ExecuteRevokeOne(ctx, requests[i]) }()
		}
		wg.Wait()
		committed := 0
		for i, r := range results {
			if r.Outcome == identity.CommitOutcomeCommitted {
				committed++
				if failures[i] != nil {
					t.Fatal("committed cross-revoke returned failure")
				}
			} else {
				var forbidden identity.ForbiddenError
				if r.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(failures[i], &forbidden) {
					t.Fatal("cross-revoke did not resolve by source denial", failures[i])
				}
			}
		}
		if committed != 1 {
			t.Fatal("cross revocation result", committed)
		}
	})
	t.Run("original admission budget rolls back slow audit", func(t *testing.T) {
		target := issue(t)
		request := prepare(t, original, target.Session)
		shortConfig := config
		shortConfig.Clock = issueTestClock{now: request.ValidUntil().Add(-50 * time.Millisecond)}
		short, e := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: shortConfig, Sessions: reader})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION public.delay_revoke_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$; CREATE TRIGGER delay_revoke_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.delay_revoke_audit()`); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER delay_revoke_audit ON audit.identity_command_bindings;DROP FUNCTION public.delay_revoke_audit()`); e != nil {
				t.Error("audit delay cleanup")
			}
		}()
		result, e := short.ExecuteRevokeOne(ctx, request)
		if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("slow audit outlived original admission")
		}
		assertState(t, target.Session, false)
	})
	t.Run("database expiry and clock skew bound slow audit", func(t *testing.T) {
		target := issue(t)
		lag := issueTestClock{now: time.Now().Add(-200 * time.Millisecond)}
		source, _ := original.Session.Bindings()
		if lag.now.Before(source.LastActivityAt) {
			t.Fatal("source fixture is too young for skew")
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '0.12 second' WHERE tenant_id='issue' AND user_id='issue-user' AND credential_id='password'`); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=NULL WHERE tenant_id='issue' AND user_id='issue-user' AND credential_id='password'`); e != nil {
				t.Error("credential expiry cleanup")
			}
		}()
		readerConfig.Validation.Clock = lag
		skewedReader, e := NewSessionService(pool, readerConfig)
		if e != nil {
			t.Fatal(e)
		}
		caller, e := skewedReader.Get(ctx, credential)
		if e != nil || !caller.Authenticated {
			t.Fatal("short-lived primary caller", e)
		}
		b := revokeBinding()
		spec, _ := target.Session.Bindings()
		op := session.RevokeOneOperation()
		b.TenantID, b.UserID, b.ActorID, b.RecordID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID), spec.SessionID
		b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
		b.CommandID, e = identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		command, e := session.NewRevokeOneCommand(b, target.Session)
		if e != nil {
			t.Fatal(e)
		}
		request, e := skewedReader.PrepareRevokeOne(caller, command)
		if e != nil {
			t.Fatal(e)
		}
		config.Clock = lag
		skewed, e := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: config, Sessions: skewedReader})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION public.delay_skew_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.18); RETURN NEW; END $$; CREATE TRIGGER delay_skew_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.delay_skew_audit()`); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER delay_skew_audit ON audit.identity_command_bindings;DROP FUNCTION public.delay_skew_audit()`); e != nil {
				t.Error("skew delay cleanup")
			}
		}()
		result, e := skewed.ExecuteRevokeOne(ctx, request)
		if result.Outcome == identity.CommitOutcomeCommitted || e == nil {
			t.Fatal("revocation committed after database caller expiry")
		}
		assertState(t, target.Session, false)
		var native, successAudit, lifecycle int
		if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, b.CommandID), int64(audit.OutcomeSucceeded)).Scan(&native, &successAudit, &lifecycle); e != nil || native != 0 || successAudit != 0 || lifecycle != 0 {
			t.Fatal("expired caller left success effects", e)
		}
	})
}
