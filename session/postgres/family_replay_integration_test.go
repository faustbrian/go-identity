//go:build integration

package postgres

import (
	"context"
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

// All credentials come from the existing real issue/rotation harness. This
// helper owns no store, command journal, proof issuer or production substitute.
func testNativeFamilyReplay(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, validation session.ServiceConfig, reader *session.SessionService, prepare func(*testing.T) (*RotationExecutor, session.RotationRequest, session.GetRequest), issued map[string]session.Token, successors map[identity.CommandID]session.Token, issue func(*testing.T) (session.GetResult, session.GetRequest)) {
	t.Helper()
	config := FamilyReplayGuardConfig{Execution: execution, LookupKeys: validation.LookupKeys, ActorID: "session-replay-worker"}
	fixture := func(t *testing.T) (FamilyReplayInput, session.SessionSpec, session.GetRequest) {
		t.Helper()
		executor, request, _ := prepare(t)
		command, _ := request.Command()
		rotation, _ := command.Rotation()
		source, _ := rotation.Source.Bindings()
		if out, err := executor.ExecuteRotation(ctx, request); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("retire fixture credential", err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialCookie, successors[rotation.Binding.CommandID])
		if err != nil {
			t.Fatal(err)
		}
		next := session.GetRequest{TenantID: source.TenantID, Credential: credential}
		if got, err := reader.Get(ctx, next); err != nil || !got.Authenticated {
			t.Fatal("successor fixture not authenticated", err)
		}
		return FamilyReplayInput{TenantID: source.TenantID, Token: issued[source.SessionID], CommandID: id, CorrelationID: "family-replay"}, source, next
	}
	newGuard := func(t *testing.T, cfg FamilyReplayGuardConfig) *FamilyReplayGuard {
		t.Helper()
		guard, err := NewFamilyReplayGuard(pool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return guard
	}
	noCommand := func(t *testing.T, id identity.CommandID) {
		t.Helper()
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, id)).Scan(&count); err != nil || count != 0 {
			t.Fatal("non-replay reserved a command", err)
		}
	}
	for _, mode := range []string{"active", "absent", "foreign", "expired"} {
		t.Run("replay guard ignores "+mode, func(t *testing.T) {
			input, source, next := fixture(t)
			cfg := config
			switch mode {
			case "active":
				current, _ := issue(t)
				spec, _ := current.Session.Bindings()
				input.Token = issued[spec.SessionID]
			case "absent":
				var err error
				input.Token, err = session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign":
				input.TenantID = "foreign"
			case "expired":
				cfg.Execution.Clock = issueTestClock{now: source.IssuedAt.Add(48 * time.Hour)}
			}
			got, err := newGuard(t, cfg).CheckReplay(ctx, input)
			if err != nil || got.Outcome != identity.CommitOutcomeInvalid || got.Binding.CommandID != "" || got.Feature != nil {
				t.Fatal("neutral observation claimed a transition", err)
			}
			noCommand(t, input.CommandID)
			if got, err := reader.Get(ctx, next); err != nil || !got.Authenticated {
				t.Fatal("neutral observation damaged the family", err)
			}
		})
	}
	for _, mode := range []string{"denied policy", "cancelled", "corrupt lineage", "audit rollback", "ambiguous commit"} {
		t.Run("replay guard "+mode, func(t *testing.T) {
			input, source, next := fixture(t)
			cfg, call := config, ctx
			switch mode {
			case "denied policy":
				cfg.Execution.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				})
			case "cancelled":
				var stop context.CancelFunc
				call, stop = context.WithCancel(ctx)
				stop()
			case "corrupt lineage":
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_rotations SET source_digest=$1 WHERE tenant_id=$2 AND session_id=$3`, make([]byte, 32), string(source.TenantID), source.SessionID); err != nil {
					t.Fatal(err)
				}
			case "audit rollback":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_replay_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE TRIGGER reject_replay_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_replay_audit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_replay_audit ON audit.identity_command_bindings;DROP FUNCTION public.reject_replay_audit()`); err != nil {
						t.Error(err)
					}
				}()
			case "ambiguous commit":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_replay_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE CONSTRAINT TRIGGER reject_replay_commit AFTER INSERT ON session_store.family_revocations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_replay_commit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_replay_commit ON session_store.family_revocations;DROP FUNCTION public.reject_replay_commit()`); err != nil {
						t.Error(err)
					}
				}()
			}
			guard := newGuard(t, cfg)
			got, err := guard.CheckReplay(call, input)
			if err == nil || got.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed protective mutation claimed commitment", err)
			}
			var audits, events, native int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM session_store.family_revocations WHERE command_id=$1)`, mustCommandBytes(t, input.CommandID)).Scan(&audits, &events, &native); err != nil || audits != 0 || events != 0 || native != 0 {
				t.Fatal("failed mutation leaked durable effects", err)
			}
			if active, err := reader.Get(ctx, next); err != nil || !active.Authenticated {
				t.Fatal("failed mutation damaged successor", err)
			}
			if mode == "denied policy" || mode == "cancelled" || mode == "corrupt lineage" {
				noCommand(t, input.CommandID)
			}
			if mode == "ambiguous commit" {
				if got.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("failed commit falsely proved rollback")
				}
				b := got.Binding
				q, caller := familyReplayRecoveryScope(b, execution.PolicyVersion)
				restarted := newGuard(t, config)
				observed, err := restarted.RecoverReplayCommand(ctx, q, caller)
				if err != nil || observed.Outcome != identity.CommitOutcomeInProgress || observed.RetryAfter <= 0 {
					t.Fatal("live pending recovery claimed rollback", err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, input.CommandID)); err != nil {
					t.Fatal(err)
				}
				observed, err = restarted.RecoverReplayCommand(ctx, q, caller)
				if err == nil || observed.Outcome != identity.CommitOutcomeNotCommitted || observed.Feature == nil || observed.Binding != b {
					t.Fatal("negative participant evidence not reconciled", err)
				}
			}
		})
	}
	t.Run("replay guard protected audit and restart receipt", func(t *testing.T) {
		input, source, _ := fixture(t)
		guard := newGuard(t, config)
		result, err := guard.CheckReplay(ctx, input)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("protective revocation", err)
		}
		var canonical []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT canonical_record FROM audit.records WHERE record_id=$1`, result.AuditEventID).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		record, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
		if err != nil || record.Actor().Kind() != audit.ActorService || record.Actor().ID() != string(config.ActorID) || record.Subject().ID() != source.FamilyID || record.Action() != "identity.session.revoke" || record.Attributes()["retention.class"] != "protected" || record.Attributes()["aggregate.after_version"] != "2" {
			t.Fatal("protective audit lost actor/subject/retention", err)
		}
		q, caller := familyReplayRecoveryScope(result.Binding, execution.PolicyVersion)
		restarted := newGuard(t, config)
		observed, err := restarted.RecoverReplayCommand(ctx, q, caller)
		if err != nil || !reflect.DeepEqual(observed, result) {
			t.Fatal("restart changed historical receipt", err)
		}
		q.ActorID = "foreign"
		if got, err := restarted.RecoverReplayCommand(ctx, q, caller); err == nil || got.Feature != nil || got.Binding.CommandID != "" {
			t.Fatal("substituted caller disclosed receipt")
		}
		altered := input
		altered.CorrelationID = "changed-intent"
		if got, err := guard.CheckReplay(ctx, altered); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed intent borrowed a prior success", err)
		}
	})
	t.Run("competing replay commands commit one family transition", func(t *testing.T) {
		input, source, next := fixture(t)
		guard := newGuard(t, config)
		other := input
		var err error
		other.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		type observation struct {
			result identity.CommandResult
			err    error
		}
		results := make(chan observation, 2)
		start := make(chan struct{})
		var joined sync.WaitGroup
		for _, candidate := range []FamilyReplayInput{input, other} {
			joined.Add(1)
			go func() {
				defer joined.Done()
				<-start
				got, err := guard.CheckReplay(ctx, candidate)
				results <- observation{got, err}
			}()
		}
		close(start)
		joined.Wait()
		close(results)
		committed := 0
		for got := range results {
			if got.result.Outcome == identity.CommitOutcomeCommitted && got.err == nil {
				committed++
			} else if got.err == nil {
				t.Fatal("losing command claimed an unclassified success")
			}
		}
		if committed != 1 {
			t.Fatal("competing commands did not have one winner")
		}
		var version string
		var records int
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text,(SELECT count(*) FROM session_store.family_revocations WHERE tenant_id=$1 AND family_id=$2) FROM session_store.families WHERE tenant_id=$1 AND family_id=$2`, string(source.TenantID), source.FamilyID).Scan(&version, &records); err != nil || version != "2" || records != 1 {
			t.Fatal("race duplicated family transition", err)
		}
		if got, err := reader.Get(ctx, next); err != nil || got.Authenticated {
			t.Fatal("race winner did not deny successor", err)
		}
	})
}

func familyReplayRecoveryScope(b identity.CommandBinding, version uint64) (identity.RecoveryQuery, authorization.DecisionContext) {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}, authorization.DecisionContext{PolicyRevision: authorization.Revision(version), CorrelationID: "replay-recovery", Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
}
