//go:build integration

package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testNativeSessionUpdate(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, reader *session.SessionService, issue func(*testing.T) (session.GetResult, session.GetRequest)) {
	t.Helper()
	executor, err := NewUpdateExecutor(pool, UpdateExecutorConfig{Execution: execution, Sessions: reader})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := session.NewSessionUpdater(reader, executor, session.UpdateConfig{PolicyID: execution.PolicyID, PolicyVersion: execution.PolicyVersion, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T, caller session.GetResult, id identity.CommandID, label string) session.UpdateCommandRequest {
		t.Helper()
		s, _ := caller.Session.Bindings()
		r, e := updater.Prepare(caller, session.UpdatePreparation{CommandID: id, CorrelationID: "update-cas", SessionID: s.SessionID, ExpectedVersion: s.Version, DeviceLabel: label})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	t.Run("label persists without refreshing authority or replacing bearer", func(t *testing.T) {
		caller, input := issue(t)
		old, _ := caller.Session.Bindings()
		id, _ := identity.NewCommandID()
		request, err := updater.Prepare(caller, session.UpdatePreparation{CommandID: id, CorrelationID: "update-test", SessionID: old.SessionID, ExpectedVersion: old.Version, DeviceLabel: "Work laptop"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := updater.Update(ctx, request)
		if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Device.Label != "Work laptop" {
			t.Fatal("native label not committed", err)
		}
		command, _ := request.Command()
		change, _ := command.Update()
		want, _, _ := encodeRecord(change.Successor)
		current, err := reader.Get(ctx, input)
		if err != nil || !current.Authenticated {
			t.Fatal("original bearer lost", err)
		}
		got, _, _ := encodeRecord(current.Session)
		if !bytes.Equal(got, want) {
			t.Fatal("label update changed unrelated session security state")
		}
		found := false
		q := session.SessionPageQuery{TenantID: old.TenantID, UserID: old.UserID, Audience: old.Audience, Limit: 100}
		for n := 0; n < 10; n++ {
			page, err := executor.owned.native.ReadSessionPage(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page.Entries {
				s, _ := entry.Session.Bindings()
				q.AfterSessionID = s.SessionID
				if s.SessionID == old.SessionID {
					found = entry.Label == "Work laptop"
				}
			}
			if found || !page.HasMore {
				break
			}
		}
		if !found {
			t.Fatal("owned listing lost committed label")
		}
		again, err := updater.Update(ctx, request)
		if err != nil || !again.Replayed || again.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("exact replay not observed", err)
		}
		var native, audits, events int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_updates WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, id)).Scan(&native, &audits, &events); err != nil || native != 1 || audits != 1 || events != 1 {
			t.Fatal("update effects not atomic/idempotent", err)
		}
		observed, err := updater.Recover(ctx, request)
		if err != nil || observed.CommitOutcome != identity.CommitOutcomeCommitted || observed.Session != (session.Session{}) || observed.Device.Label != "" {
			t.Fatal("recovery mutated or disclosed live metadata", err)
		}
		clearID, _ := identity.NewCommandID()
		spec, _ := current.Session.Bindings()
		clear, err := updater.Prepare(current, session.UpdatePreparation{CommandID: clearID, CorrelationID: "clear-test", SessionID: spec.SessionID, ExpectedVersion: spec.Version})
		if err != nil {
			t.Fatal(err)
		}
		if result, err = updater.Update(ctx, clear); err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Device.Label != "" {
			t.Fatal("clear not committed", err)
		}
	})
	t.Run("changed intent cannot reuse committed command", func(t *testing.T) {
		caller, _ := issue(t)
		id, _ := identity.NewCommandID()
		first, altered := prepare(t, caller, id, "First"), prepare(t, caller, id, "Changed")
		if out, err := updater.Update(ctx, first); err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		if out, err := updater.Update(ctx, altered); err == nil || out.Session != (session.Session{}) || out.Device.Label != "" {
			t.Fatal("changed intent reused command", err)
		}
		if out, err := updater.Recover(ctx, altered); err == nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Session != (session.Session{}) {
			t.Fatal("changed recovery erased commitment or accepted wrong intent", err)
		}
	})
	t.Run("concurrent source CAS has one winner", func(t *testing.T) {
		caller, input := issue(t)
		a, _ := identity.NewCommandID()
		b, _ := identity.NewCommandID()
		requests := []session.UpdateCommandRequest{prepare(t, caller, a, "A"), prepare(t, caller, b, "B")}
		type outcome struct {
			result session.UpdateResult
			err    error
		}
		start := make(chan struct{})
		results := make(chan outcome, 2)
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		for _, request := range requests {
			go func() { <-start; r, e := updater.Update(bounded, request); results <- outcome{r, e} }()
		}
		close(start)
		x, y := <-results, <-results
		winners := 0
		for _, out := range []outcome{x, y} {
			if out.err == nil && out.result.CommitOutcome == identity.CommitOutcomeCommitted {
				winners++
			} else if out.err == nil || out.result.Session != (session.Session{}) {
				t.Fatal("loser exposed metadata", out.err)
			}
		}
		if winners != 1 {
			t.Fatal("source CAS did not serialize")
		}
		current, err := reader.Get(ctx, input)
		if err != nil || !current.Authenticated {
			t.Fatal("winner lost credential", err)
		}
		old, _ := caller.Session.Bindings()
		next, _ := current.Session.Bindings()
		if next.Version != old.Version+1 {
			t.Fatal("source version incremented twice")
		}
	})
	for _, mode := range []string{"cancelled", "blocked user", "audit rollback", "ambiguous commit"} {
		t.Run(mode, func(t *testing.T) {
			caller, input := issue(t)
			id, _ := identity.NewCommandID()
			request := prepare(t, caller, id, "Rejected")
			command, _ := request.Command()
			u, _ := command.Update()
			b := u.Binding
			call := ctx
			switch mode {
			case "cancelled":
				var stop context.CancelFunc
				call, stop = context.WithCancel(ctx)
				stop()
			case "blocked user":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='issue'`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='issue'`); err != nil {
						t.Error(err)
					}
				}()
			case "audit rollback":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE TRIGGER reject_update_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_update_audit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_update_audit ON audit.identity_command_bindings;DROP FUNCTION public.reject_update_audit()`); err != nil {
						t.Error(err)
					}
				}()
			case "ambiguous commit":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_update_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE CONSTRAINT TRIGGER reject_update_commit AFTER INSERT ON session_store.session_updates DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_update_commit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_update_commit ON session_store.session_updates;DROP FUNCTION public.reject_update_commit()`); err != nil {
						t.Error(err)
					}
				}()
			}
			out, err := updater.Update(call, request)
			if err == nil || out.CommitOutcome == identity.CommitOutcomeCommitted || out.Session != (session.Session{}) {
				t.Fatal("failed update escaped metadata", err)
			}
			var labels, evidence int
			if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_labels WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.session_updates WHERE command_id=$3)`, string(b.TenantID), b.RecordID, mustCommandBytes(t, id)).Scan(&labels, &evidence); err != nil || labels != 0 || evidence != 0 {
				t.Fatal("rollback left provisional metadata", err)
			}
			if mode != "blocked user" {
				current, e := reader.Get(ctx, input)
				if e != nil || !current.Authenticated {
					t.Fatal("rollback lost original credential", e)
				}
				want, _, _ := encodeRecord(caller.Session)
				got, _, _ := encodeRecord(current.Session)
				if !bytes.Equal(want, got) {
					t.Fatal("rollback changed source record")
				}
			}
			if mode == "ambiguous commit" {
				if out.CommitOutcome != identity.CommitOutcomeUnknown {
					t.Fatal("failed acknowledgement claimed rollback")
				}
				restarted, e := NewUpdateExecutor(pool, UpdateExecutorConfig{Execution: execution, Sessions: reader})
				if e != nil {
					t.Fatal(e)
				}
				q := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				observed, e := restarted.RecoverUpdateCommand(ctx, q, executor.updateCaller(b))
				if e != nil || observed.Outcome != identity.CommitOutcomeInProgress || observed.RetryAfter <= 0 {
					t.Fatal("live lease changed", e)
				}
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, id)); e != nil {
					t.Fatal(e)
				}
				t.Run("missing evidence stays unresolved", func(t *testing.T) {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.session_updates RENAME TO hidden_session_updates`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.hidden_session_updates RENAME TO session_updates`); e != nil {
							t.Error(e)
						}
					}()
					result, e := restarted.RecoverUpdateCommand(ctx, q, executor.updateCaller(b))
					if e == nil || result.Outcome == identity.CommitOutcomeNotCommitted || result.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("missing infrastructure invented outcome", e)
					}
				})
				observed, e = restarted.RecoverUpdateCommand(ctx, q, executor.updateCaller(b))
				if e == nil || observed.Outcome != identity.CommitOutcomeNotCommitted || observed.Binding != b {
					t.Fatal("native rollback not reconciled", e)
				}
			}
		})
	}
	t.Run("restart recovery survives payload deletion and reveals no label", func(t *testing.T) {
		caller, _ := issue(t)
		id, _ := identity.NewCommandID()
		request := prepare(t, caller, id, "Private device")
		if out, e := updater.Update(ctx, request); e != nil || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal(e)
		}
		command, _ := request.Command()
		u, _ := command.Update()
		b := u.Binding
		q := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		if _, e := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), b.RecordID); e != nil {
			t.Fatal(e)
		}
		var labels int
		if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.session_labels WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), b.RecordID).Scan(&labels); e != nil || labels != 0 {
			t.Fatal("privacy cleanup retained current label", e)
		}
		restarted, e := NewUpdateExecutor(pool, UpdateExecutorConfig{Execution: execution, Sessions: reader})
		if e != nil {
			t.Fatal(e)
		}
		out, e := restarted.RecoverUpdateCommand(ctx, q, executor.updateCaller(b))
		if e != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Binding != b {
			t.Fatal("restart lost committed history", e)
		}
		foreign := q
		foreign.TenantID = "foreign"
		if out, e = restarted.RecoverUpdateCommand(ctx, foreign, executor.updateCaller(b)); e == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign recovery disclosed", e)
		}
	})
}
