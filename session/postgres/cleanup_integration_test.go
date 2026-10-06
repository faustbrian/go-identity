//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testNativeExpiryCleanup(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, reader *session.SessionService, issue func(*testing.T) (session.GetResult, session.GetRequest)) {
	t.Helper()
	config := CleanupServiceConfig{Execution: execution, ActorID: "expiry-worker", MaximumBatch: 2}
	// A deliberately offset application clock must not control deletion or lag.
	config.Execution.Clock = issueTestClock{now: time.Now().UTC().Add(-365 * 24 * time.Hour)}
	service, err := NewCleanupService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	command := func(t *testing.T, limit uint32) CleanupCommand {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return CleanupCommand{TenantID: "issue", UserID: "issue-user", CommandID: id, CorrelationID: "expiry-test", Limit: limit}
	}
	expired := func(t *testing.T) (session.SessionSpec, session.GetRequest) {
		t.Helper()
		got, input := issue(t)
		spec, _ := got.Session.Bindings()
		for _, stamp := range []*time.Time{&spec.IssuedAt, &spec.LastActivityAt, &spec.Authentication.Proof.IssuedAt, &spec.Authentication.Proof.ExpiresAt} {
			*stamp = stamp.Add(-2 * time.Hour)
		}
		aged, err := session.NewSession(spec)
		if err != nil {
			t.Fatal(err)
		}
		payload, expiry, err := encodeRecord(aged)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND session_id=$4;`, string(payload), expiry, string(spec.TenantID), spec.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.families SET issued_at=$1 WHERE tenant_id=$2 AND family_id=$3`, spec.IssuedAt.Format(storedTimeLayout), string(spec.TenantID), spec.FamilyID); err != nil {
			t.Fatal(err)
		}
		if got, err := reader.Get(ctx, input); err != nil || got.Authenticated {
			t.Fatal("expired fixture remained authenticated", err)
		}
		return spec, input
	}
	t.Run("bounded cleanup retains exact receipt and authority", func(t *testing.T) {
		active, activeInput := issue(t)
		activeSpec, _ := active.Session.Bindings()
		var targets []session.SessionSpec
		for range 3 {
			spec, _ := expired(t)
			targets = append(targets, spec)
		}
		input := command(t, 2)
		start := time.Now().UTC()
		got, err := service.CleanupExpired(ctx, input)
		if err != nil || got.Command.Outcome != identity.CommitOutcomeCommitted || got.Deleted != 2 || got.RemainingLag <= 0 || got.ObservedAt.Before(start) || got.Command.Feature == nil || got.Command.Feature.BeforeVersion != 0 || got.Command.Feature.AfterVersion != 0 {
			t.Fatal("bounded expiry cleanup", err)
		}
		if repeated, err := service.CleanupExpired(ctx, input); err != nil || !reflect.DeepEqual(repeated, got) {
			t.Fatal("cleanup retry selected a new batch", err)
		}
		changed := input
		changed.Limit = 1
		if repeated, err := service.CleanupExpired(ctx, changed); err == nil || repeated.Command.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed limit borrowed success", err)
		}
		q, caller := familyReplayRecoveryScope(got.Command.Binding, execution.PolicyVersion)
		restarted, err := NewCleanupService(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		if observed, err := restarted.RecoverCleanupCommand(ctx, q, caller); err != nil || !reflect.DeepEqual(observed, got) {
			t.Fatal("restart changed cleanup history", err)
		}
		if current, err := reader.Get(ctx, activeInput); err != nil || !current.Authenticated {
			t.Fatal("cleanup deleted active session", err)
		}
		var version string
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(activeSpec.TenantID), activeSpec.SessionID).Scan(&version); err != nil || version != "1" {
			t.Fatal("cleanup changed active authority", err)
		}
		var canonical []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT canonical_record FROM audit.records WHERE record_id=$1`, got.Command.AuditEventID).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		record, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
		if err != nil || record.Action() != "identity.session.expire" || record.ReasonCode() != "completed" || record.Actor().Kind() != audit.ActorService || record.Actor().ID() != string(config.ActorID) || record.Subject().ID() != "issue-user" || record.Attributes()["aggregate.after_version"] != "0" {
			t.Fatal("expiry audit lost maintenance semantics", err)
		}
		remaining, err := service.CleanupExpired(ctx, command(t, 2))
		if err != nil || remaining.Deleted != 1 || remaining.RemainingLag != 0 {
			t.Fatal("cleanup failed to drain backlog", err)
		}
		for _, target := range targets {
			var retired bool
			var familyVersion string
			if err := pool.Raw().QueryRow(ctx, `SELECT t.retired,f.version::text FROM session_store.token_claims t JOIN session_store.families f ON f.tenant_id=t.tenant_id AND f.family_id=$3 WHERE t.tenant_id=$1 AND t.session_id=$2`, string(target.TenantID), target.SessionID, target.FamilyID).Scan(&retired, &familyVersion); err != nil || !retired || familyVersion != "1" {
				t.Fatal("cleanup lost tombstone or changed family authority", err)
			}
		}
	})
	t.Run("locked refresh survives and remains in lag observation", func(t *testing.T) {
		target, input := expired(t)
		_, _ = expired(t)
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT session_id FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE`, string(target.TenantID), target.SessionID); err != nil {
			t.Fatal(err)
		}
		got, err := service.CleanupExpired(ctx, command(t, 1))
		if err != nil || got.Deleted != 0 || got.RemainingLag <= 0 {
			t.Fatal("cleanup did not skip locked refresh", err)
		}
		target.LastActivityAt = time.Now().UTC()
		refreshed, err := session.NewSession(target)
		if err != nil {
			t.Fatal(err)
		}
		payload, expiry, err := encodeRecord(refreshed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND session_id=$4`, string(payload), expiry, string(target.TenantID), target.SessionID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if got, err := service.CleanupExpired(ctx, command(t, 1)); err != nil || got.Deleted != 1 || got.RemainingLag != 0 {
			t.Fatal("cleanup deleted refreshed survivor", err)
		}
		if got, err := reader.Get(ctx, input); err != nil || !got.Authenticated {
			t.Fatal("surviving refreshed credential denied", err)
		}
	})
	t.Run("foreign partitions and cancelled cleanup delete nothing", func(t *testing.T) {
		_, _ = expired(t)
		for _, field := range []string{"tenant", "user", "cancelled"} {
			input, call := command(t, 1), ctx
			switch field {
			case "tenant":
				input.TenantID = "foreign"
			case "user":
				input.UserID = "foreign"
			case "cancelled":
				var stop context.CancelFunc
				call, stop = context.WithCancel(ctx)
				stop()
			}
			got, err := service.CleanupExpired(call, input)
			if field == "cancelled" {
				var cancelled identity.CancelledError
				if !errors.As(err, &cancelled) || got.Deleted != 0 {
					t.Fatal("cancelled cleanup", err)
				}
			} else if err != nil || got.Deleted != 0 || got.RemainingLag != 0 {
				t.Fatal("cleanup crossed partition", err)
			}
		}
		if got, err := service.CleanupExpired(ctx, command(t, 2)); err != nil || got.Deleted != 1 {
			t.Fatal("foreign cleanup damaged owner backlog", err)
		}
	})
	for _, mode := range []string{"denied policy", "audit rollback", "ambiguous commit"} {
		t.Run("cleanup "+mode, func(t *testing.T) {
			target, _ := expired(t)
			cfg := config
			switch mode {
			case "denied policy":
				cfg.Execution.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				})
			case "audit rollback":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_cleanup_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE TRIGGER reject_cleanup_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_cleanup_audit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_cleanup_audit ON audit.identity_command_bindings;DROP FUNCTION public.reject_cleanup_audit()`); err != nil {
						t.Error(err)
					}
				}()
			case "ambiguous commit":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_cleanup_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE CONSTRAINT TRIGGER reject_cleanup_commit AFTER INSERT ON session_store.cleanup_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_cleanup_commit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_cleanup_commit ON session_store.cleanup_results;DROP FUNCTION public.reject_cleanup_commit()`); err != nil {
						t.Error(err)
					}
				}()
			}
			call, err := NewCleanupService(pool, cfg)
			if err != nil {
				t.Fatal(err)
			}
			input := command(t, 1)
			got, err := call.CleanupExpired(ctx, input)
			if err == nil || got.Command.Outcome == identity.CommitOutcomeCommitted || got.Deleted != 0 || !got.ObservedAt.IsZero() {
				t.Fatal("failed cleanup claimed deletion", err)
			}
			var sessions, evidence, audits, events int
			var retired bool
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.cleanup_results WHERE command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$3),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3),(SELECT retired FROM session_store.token_claims WHERE tenant_id=$1 AND session_id=$2)`, string(target.TenantID), target.SessionID, mustCommandBytes(t, input.CommandID)).Scan(&sessions, &evidence, &audits, &events, &retired); err != nil || sessions != 1 || evidence != 0 || audits != 0 || events != 0 || retired {
				t.Fatal("failed cleanup leaked payload/tombstone/effects", err)
			}
			if mode == "ambiguous commit" {
				if got.Command.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("commit error falsely proved rollback")
				}
				q, caller := familyReplayRecoveryScope(got.Command.Binding, execution.PolicyVersion)
				pending, err := service.RecoverCleanupCommand(ctx, q, caller)
				if err != nil || pending.Command.Outcome != identity.CommitOutcomeInProgress || pending.Command.RetryAfter <= 0 || pending.Deleted != 0 {
					t.Fatal("live cleanup lease lost uncertainty", err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, input.CommandID)); err != nil {
					t.Fatal(err)
				}
				negative, err := service.RecoverCleanupCommand(ctx, q, caller)
				if err == nil || negative.Command.Outcome != identity.CommitOutcomeNotCommitted || negative.Deleted != 0 || negative.Command.Binding != got.Command.Binding {
					t.Fatal("cleanup negative evidence not reconciled", err)
				}
			}
		})
		// Fresh commands intentionally drain failed batches only after the
		// rejection trigger has been removed and the exact old outcome recorded.
		if got, err := service.CleanupExpired(ctx, command(t, 2)); err != nil || got.Deleted != 1 {
			t.Fatal("failed batch left an unclassified backlog", err)
		}
	}
	t.Run("concurrent cleaners do not duplicate payload deletion", func(t *testing.T) {
		for range 2 {
			_, _ = expired(t)
		}
		inputs := []CleanupCommand{command(t, 1), command(t, 1)}
		start := make(chan struct{})
		results := make(chan CleanupResult, 2)
		errors := make(chan error, 2)
		var joined sync.WaitGroup
		for _, input := range inputs {
			joined.Add(1)
			go func() {
				defer joined.Done()
				<-start
				got, err := service.CleanupExpired(ctx, input)
				results <- got
				errors <- err
			}()
		}
		close(start)
		joined.Wait()
		close(results)
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatal("concurrent cleanup", err)
			}
		}
		deleted := uint32(0)
		for got := range results {
			if got.Command.Outcome != identity.CommitOutcomeCommitted || got.Deleted > 1 {
				t.Fatal("concurrent batch lost bounds/outcome")
			}
			deleted += got.Deleted
		}
		last, err := service.CleanupExpired(ctx, command(t, 2))
		if err != nil || deleted+last.Deleted != 2 || last.RemainingLag != 0 {
			t.Fatal("concurrent cleaners lost/duplicated deletion", err)
		}
	})
}
