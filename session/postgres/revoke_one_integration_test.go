//go:build integration

package postgres

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Real public native issuance and real audit/outbox participants supply these
// fixtures. This exercises the coordinator contributor, not caller admission or
// the still-missing public idempotent logout service.
func testNativeSingleRevocation(t *testing.T, ctx context.Context, pool *database.Pool, executor *IssueExecutor, issue func(*testing.T, string) session.Session) {
	prepare := func(t *testing.T, target session.Session) (identity.CommandBinding, identity.Command, kernel.CommandPlan) {
		t.Helper()
		s, _ := target.Bindings()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.TenantID, b.UserID, b.ActorID = s.TenantID, s.UserID, identity.ActorID(s.UserID)
		b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, s.SessionID
		var e error
		b.CommandID, e = identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		native, e := session.NewRevokeOneCommand(b, target)
		if e != nil {
			t.Fatal(e)
		}
		command, e := MapCommand(native)
		if e != nil {
			t.Fatal(e)
		}
		builder, e := audit.NewBuilder(audit.BuilderConfig{})
		if e != nil {
			t.Fatal(e)
		}
		seed, e := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: s.SessionID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": s.SessionID, "aggregate.before_version": strconv.FormatUint(s.Version, 10), "aggregate.after_version": strconv.FormatUint(s.Version+1, 10), "retention.class": "standard"}})
		if e != nil {
			t.Fatal(e)
		}
		digest, e := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
		if e != nil {
			t.Fatal(e)
		}
		p, e := executor.coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: executor.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: executor.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard", RetentionPolicyVersion: 1, BindingDigest: digest, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}})
		if e != nil {
			t.Fatal(e)
		}
		return b, command, p
	}
	execute := func(b identity.CommandBinding, command identity.Command, p kernel.CommandPlan) (identity.CommandResult, error) {
		r, result, e := executor.coordinator.ReserveCommand(ctx, b, command, p)
		if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
			return result, e
		}
		w, e := executor.coordinator.Begin(ctx, r)
		if e != nil {
			return identity.CommandResult{}, e
		}
		defer executor.coordinator.Abort(w, identity.UnavailableError{})
		result, e = executor.coordinator.ApplyFeature(ctx, w, command)
		if e != nil {
			return executor.coordinator.Abort(w, e)
		}
		return executor.coordinator.Commit(w, result)
	}
	state := func(t *testing.T, target session.Session, revoked bool) {
		t.Helper()
		s, _ := target.Bindings()
		stored, e := executor.native.Get(ctx, s.TenantID, s.SessionID)
		if e != nil || stored.Revoked != revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != s.FamilyVersion {
			t.Fatal("target/family state", e)
		}
		got, _ := stored.Session.Bindings()
		ga, _ := got.Authority.Bindings()
		want, _ := s.Authority.Bindings()
		gp, _ := got.Remember.Bindings()
		wp, _ := s.Remember.Bindings()
		if ga != want || gp != wp {
			t.Fatal("authority or remember policy rewritten")
		}
		got.Authority, got.Remember = s.Authority, s.Remember
		if got != s {
			t.Fatal("original session rewritten")
		}
	}
	evidence := func(t *testing.T, b identity.CommandBinding, want int) {
		t.Helper()
		var native, auditing, lifecycle int
		id := mustCommandBytes(t, b.CommandID)
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id, int64(audit.OutcomeSucceeded)).Scan(&native, &auditing, &lifecycle); e != nil || native != want || auditing != want || lifecycle != want {
			t.Fatal("atomic retained effects", e, native, auditing, lifecycle)
		}
	}
	t.Run("exact target preserves sibling and replays once", func(t *testing.T) {
		target := issue(t, "")
		s, _ := target.Bindings()
		sibling := issue(t, s.FamilyID)
		b, command, plan := prepare(t, target)
		result, e := execute(b, command, plan)
		if e != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.BeforeVersion != s.Version || result.Feature.AfterVersion != s.Version+1 {
			t.Fatal("one-session commit", e)
		}
		state(t, target, true)
		state(t, sibling, false)
		evidence(t, b, 1)
		var canonical []byte
		if e = pool.Raw().QueryRow(ctx, `SELECT r.canonical_record FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&canonical); e != nil {
			t.Fatal(e)
		}
		audited, e := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
		if e != nil || audited.Action() != "identity.session.revoke" || audited.Subject().Type() != "session" || audited.Subject().ID() != s.SessionID || audited.Actor().ID() != string(b.ActorID) || audited.Attributes()["aggregate.after_version"] != "2" {
			t.Fatal("wrong canonical revocation event", e)
		}
		_, replay, e := executor.coordinator.ReserveCommand(ctx, b, command, plan)
		if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID {
			t.Fatal("terminal replay changed", e)
		}
		q, caller := revokeRecoveryInput(b)
		observed, e := executor.coordinator.RecoverCommand(ctx, q, caller)
		if e != nil || observed.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("historical recovery lost", e)
		}
		evidence(t, b, 1)
		altered, _ := target.Bindings()
		altered.LastActivityAt = altered.LastActivityAt.Add(time.Millisecond)
		changed, e := session.NewSession(altered)
		if e != nil {
			t.Fatal(e)
		}
		nativeChanged, e := session.NewRevokeOneCommand(b, changed)
		if e != nil {
			t.Fatal(e)
		}
		mappedChanged, e := MapCommand(nativeChanged)
		if e != nil {
			t.Fatal(e)
		}
		changedPlan, e := executor.coordinator.PrepareCommandPlan(b, mappedChanged, plan)
		if e != nil {
			t.Fatal(e)
		}
		_, conflictResult, e := executor.coordinator.ReserveCommand(ctx, b, mappedChanged, changedPlan)
		var conflict identity.ConflictError
		if !errors.As(e, &conflict) || conflictResult.Outcome != identity.CommitOutcomeConflict {
			t.Fatal("same command changed original record", e)
		}
		evidence(t, b, 1)
		var before, after string
		if e = pool.Raw().QueryRow(ctx, `SELECT before_version::text,after_version::text FROM session_store.session_revocations WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&before, &after); e != nil || before != "1" || after != "2" {
			t.Fatal("terminal successor missing", e)
		}
		// A stale original snapshot cannot produce another command transition.
		b2, c2, p2 := prepare(t, target)
		result, e = execute(b2, c2, p2)
		if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("terminal session revoked twice")
		}
		evidence(t, b2, 0)
		state(t, sibling, false)
	})
	t.Run("racing commands have one target winner", func(t *testing.T) {
		target := issue(t, "")
		b1, c1, p1 := prepare(t, target)
		b2, c2, p2 := prepare(t, target)
		var group sync.WaitGroup
		start := make(chan struct{})
		results := make(chan identity.CommandResult, 2)
		failures := make(chan error, 2)
		for _, input := range []struct {
			b identity.CommandBinding
			c identity.Command
			p kernel.CommandPlan
		}{{b1, c1, p1}, {b2, c2, p2}} {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				result, e := execute(input.b, input.c, input.p)
				results <- result
				failures <- e
			}()
		}
		close(start)
		group.Wait()
		close(results)
		close(failures)
		committed, aborted := 0, 0
		for result := range results {
			if result.Outcome == identity.CommitOutcomeCommitted {
				committed++
			} else if result.Outcome == identity.CommitOutcomeNotCommitted {
				aborted++
			} else {
				t.Fatal("unresolved race", result.Outcome)
			}
		}
		denied := 0
		for e := range failures {
			if e != nil {
				var forbidden identity.ForbiddenError
				if !errors.As(e, &forbidden) {
					t.Fatal("raced error", e)
				}
				denied++
			}
		}
		if committed != 1 || aborted != 1 || denied != 1 {
			t.Fatal("target exclusion lost")
		}
		state(t, target, true)
	})
	t.Run("every current owner dimension remains mandatory", func(t *testing.T) {
		for _, entry := range []struct{ name, change, restore string }{
			{"global", `UPDATE identity.global_authorities SET version=2 WHERE authority_id='deployment-issue'`, `UPDATE identity.global_authorities SET version=1 WHERE authority_id='deployment-issue'`},
			{"tenant", `UPDATE identity.tenant_authorities SET version=2 WHERE tenant_id='issue'`, `UPDATE identity.tenant_authorities SET version=1 WHERE tenant_id='issue'`},
			{"user", `UPDATE identity.users SET authority_version=2 WHERE tenant_id='issue'`, `UPDATE identity.users SET authority_version=1 WHERE tenant_id='issue'`},
			{"identifier", `UPDATE identity.users SET identifier_version=2 WHERE tenant_id='issue'`, `UPDATE identity.users SET identifier_version=1 WHERE tenant_id='issue'`},
			{"credential epoch", `UPDATE identity.users SET credential_version=2 WHERE tenant_id='issue'`, `UPDATE identity.users SET credential_version=1 WHERE tenant_id='issue'`},
			{"credential record", `UPDATE identity.credential_references SET version=2 WHERE tenant_id='issue'`, `UPDATE identity.credential_references SET version=1 WHERE tenant_id='issue'`},
			{"authorization", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='issue'`, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id='issue'`},
			{"family", `UPDATE session_store.families SET version=2 WHERE tenant_id='issue'`, `UPDATE session_store.families SET version=1 WHERE tenant_id='issue'`},
		} {
			t.Run(entry.name, func(t *testing.T) {
				target := issue(t, "")
				b, command, plan := prepare(t, target)
				if _, e := pool.Raw().Exec(ctx, entry.change); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, entry.restore); e != nil {
						t.Error("owner restoration failed")
					}
				}()
				result, e := execute(b, command, plan)
				if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("stale owner admitted")
				}
				if _, e := pool.Raw().Exec(ctx, entry.restore); e != nil {
					t.Fatal(e)
				}
				state(t, target, false)
				evidence(t, b, 0)
			})
		}
	})
	t.Run("missing or conflicting retained evidence stays unresolved", func(t *testing.T) {
		for _, mode := range []string{"missing infrastructure", "conflicting binding"} {
			t.Run(mode, func(t *testing.T) {
				target := issue(t, "")
				b, command, plan := prepare(t, target)
				if _, _, e := executor.coordinator.ReserveCommand(ctx, b, command, plan); e != nil {
					t.Fatal(e)
				}
				id := mustCommandBytes(t, b.CommandID)
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
					t.Fatal(e)
				}
				if mode == "missing infrastructure" {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.session_revocations RENAME TO hidden_single_revocations`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.hidden_single_revocations RENAME TO session_revocations`); e != nil {
							t.Error("evidence restoration failed")
						}
					}()
				} else {
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO session_store.session_revocations(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,1,2,$6,$6)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, make([]byte, 32)); e != nil {
						t.Fatal(e)
					}
				}
				q, caller := revokeRecoveryInput(b)
				result, e := executor.coordinator.RecoverCommand(ctx, q, caller)
				if e == nil || result.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("unproven recovery terminalized", e, result.Outcome)
				}
				var pending string
				if e := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&pending); e != nil || pending != "pending" {
					t.Fatal("recovery changed command", e)
				}
				state(t, target, false)
			})
		}
	})
	for _, mode := range []string{"credential revoked", "blocked user", "audit rollback", "cancelled commit", "ambiguous commit"} {
		t.Run(mode, func(t *testing.T) {
			target := issue(t, "")
			b, command, plan := prepare(t, target)
			switch mode {
			case "credential revoked":
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='issue'`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=true WHERE tenant_id='issue'`); e != nil {
						t.Error("restore failed")
					}
				}()
			case "blocked user":
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='issue'`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='issue'`); e != nil {
						t.Error("restore failed")
					}
				}()
			case "audit rollback":
				if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_single_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$; CREATE TRIGGER reject_single_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_single_audit()`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER reject_single_audit ON audit.identity_command_bindings;DROP FUNCTION public.reject_single_audit()`); e != nil {
						t.Error("restore failed")
					}
				}()
			case "ambiguous commit":
				if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_single_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE CONSTRAINT TRIGGER reject_single_commit AFTER INSERT ON session_store.session_revocations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_single_commit()`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER reject_single_commit ON session_store.session_revocations;DROP FUNCTION public.reject_single_commit()`); e != nil {
						t.Error("restore failed")
					}
				}()
			}
			var result identity.CommandResult
			var e error
			if mode == "cancelled commit" {
				r, _, err := executor.coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				call, cancel := context.WithCancel(ctx)
				defer cancel()
				w, err := executor.coordinator.Begin(call, r)
				if err != nil {
					t.Fatal(err)
				}
				defer executor.coordinator.Abort(w, identity.UnavailableError{})
				result, err = executor.coordinator.ApplyFeature(call, w, command)
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				result, e = executor.coordinator.Commit(w, result)
			} else {
				result, e = execute(b, command, plan)
			}
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed revocation committed", mode)
			}
			state(t, target, false)
			evidence(t, b, 0)
			if mode == "ambiguous commit" {
				if result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("commit rejection falsely proves rollback")
				}
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); e != nil {
					t.Fatal(e)
				}
				q, caller := revokeRecoveryInput(b)
				observed, e := executor.coordinator.RecoverCommand(ctx, q, caller)
				if e == nil || observed.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("negative native recovery lost", e, observed.Outcome)
				}
			}
		})
	}
}
