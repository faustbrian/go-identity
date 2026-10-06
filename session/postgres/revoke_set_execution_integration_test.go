//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/faustbrian/go-authorization"
	policyStore "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"strconv"
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
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run("bulk pending recovery "+mode, func(t *testing.T) {
			source, _ := issue(t)
			request := prepare(t, source, mode != "other", mode == "all-include")
			executor, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: execution, Sessions: reader})
			if err != nil {
				t.Fatal(err)
			}
			b, command, plan, _, err := executor.prepareSet(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, result, err := executor.owned.coordinator.ReserveCommand(ctx, b, command, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("pending bulk fixture", err)
			}
			q, caller := revokeRecoveryInput(b)
			restarted, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: execution, Sessions: reader})
			if err != nil {
				t.Fatal(err)
			}
			live, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
			if err != nil || live.Command.Outcome != identity.CommitOutcomeInProgress || live.Command.RetryAfter <= 0 || live.RevokedCount != 0 || live.SessionVersion != 0 {
				t.Fatal("live lease became mutation or terminal outcome", err)
			}
			id := mustCommandBytes(t, b.CommandID)
			assertPending := func(t *testing.T) {
				t.Helper()
				var state string
				var generation int64
				if err := pool.Raw().QueryRow(ctx, `SELECT state,generation FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &generation); err != nil || state != "pending" || generation != 1 {
					t.Fatal("recovery changed unresolved ownership", err, state, generation)
				}
			}
			assertPending(t)
			if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			t.Run("unavailable evidence is not negative evidence", func(t *testing.T) {
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE session_store.set_revocations RENAME TO hidden_set_revocations`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE session_store.hidden_set_revocations RENAME TO set_revocations`); err != nil {
						t.Error("retained evidence restoration failed")
					}
				}()
				out, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
				if err == nil || out.Command.Outcome != identity.CommitOutcomeInProgress || out.RevokedCount != 0 || out.SubjectVersion != 0 || out.SessionVersion != 0 || out.CurrentSessionRevoked {
					t.Fatal("unavailable native evidence terminalized pending command", err)
				}
				assertPending(t)
			})
			t.Run("conflicting evidence cannot prove rollback", func(t *testing.T) {
				spec, _ := source.Session.Bindings()
				vector, _ := spec.Authority.Bindings()
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.set_revocations(tenant_id,command_id,purpose,user_id,source_id,before_version,after_version,subject_version,revoked_count,include_current,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,1,$9,$10,$11)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(spec.Version, 10), strconv.FormatUint(spec.Version+1, 10), strconv.FormatUint(vector.User.Version, 10), mode == "all-include", make([]byte, 32), make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.set_revocations WHERE command_id=$1`, id); err != nil {
						t.Error("conflicting evidence restoration failed")
					}
				}()
				out, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
				if err == nil || out.Command.Outcome != identity.CommitOutcomeInProgress || out.RevokedCount != 0 || out.SubjectVersion != 0 || out.SessionVersion != 0 || out.CurrentSessionRevoked {
					t.Fatal("conflicting native evidence erased pending command", err)
				}
				assertPending(t)
			})
			out, err := restarted.RecoverRevokeSetCommand(ctx, q, caller)
			if err == nil || out.Command.Outcome != identity.CommitOutcomeNotCommitted || out.Command.Binding != b || out.RevokedCount != 0 || out.SubjectVersion != 0 || out.SessionVersion != 0 || out.CurrentSessionRevoked {
				t.Fatal("negative participant evidence not reconciled", err, out.Command.Outcome)
			}
			original, _, _ := encodeRecord(source.Session)
			stored, err := executor.owned.native.Get(ctx, b.TenantID, b.RecordID)
			payload, _, _ := encodeRecord(stored.Session)
			if err != nil || stored.Revoked || !bytes.Equal(original, payload) {
				t.Fatal("negative recovery changed authenticating source", err)
			}
			var audits, events, retained int
			if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM session_store.set_revocations WHERE command_id=$1)`, id).Scan(&audits, &events, &retained); err != nil || audits != 1 || events != 0 || retained != 0 {
				t.Fatal("negative recovery retained mutation effects", err, audits, events, retained)
			}
		})
	}
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
			// Imported structural fixtures exercise set ownership, not credential
			// admission. The authenticating source above is really issued. One
			// target has another audience; foreign rows deliberately overlap user
			// or session IDs without sharing tenant/owner authority.
			crossAudience := seedSetSelectionFixture(t, ctx, pool, spec, spec.TenantID, spec.UserID, "service-b", "")
			foreignUser := seedSetSelectionFixture(t, ctx, pool, spec, spec.TenantID, "bulk-other-user", spec.Audience, "")
			foreignTenant := seedSetSelectionFixture(t, ctx, pool, spec, "bulk-other-tenant", spec.UserID, spec.Audience, spec.SessionID)
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
			cross, _ := crossAudience.Bindings()
			if stored, err := native.Get(ctx, cross.TenantID, cross.SessionID); err != nil || !stored.Revoked {
				t.Fatal("same-owner different audience survived", err)
			}
			for _, foreign := range []session.Session{foreignUser, foreignTenant} {
				scope, _ := foreign.Bindings()
				original, _, _ := encodeRecord(foreign)
				stored, err := native.Get(ctx, scope.TenantID, scope.SessionID)
				payload, _, _ := encodeRecord(stored.Session)
				if err != nil || stored.Revoked || stored.FamilyRevoked || !bytes.Equal(original, payload) {
					t.Fatal("foreign owner/tenant changed", err)
				}
			}
		})
	}
}

// Persist a structurally valid imported row with exact canonical scope keys.
// No proof, bearer, admission lease or alternative writer API is manufactured.
// The test owns the entire disposable database; this is not a consumer store.
func seedSetSelectionFixture(t *testing.T, ctx context.Context, pool *database.Pool, base session.SessionSpec, tenant identity.TenantID, user identity.UserID, audience, id string) session.Session {
	t.Helper()
	var err error
	if id == "" {
		value, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		id = string(value)
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	base.SessionID, base.FamilyID, base.TenantID, base.UserID, base.Audience = id, string(family), tenant, user, audience
	base.Version, base.FamilyVersion = 1, 1
	base.Authentication.Proof.Tenant, base.Authentication.Proof.Subject, base.Authentication.Proof.Audience = string(tenant), string(user), audience
	// Distinct rows in the same tenant cannot share digest lookup identity.
	base.Lookup.Sum = sha256.Sum256([]byte(string(tenant) + ":" + id))
	directory, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-issue", TenantID: tenant}, user)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := SessionAuthorityKeys(tenant, user, base.FamilyID, id)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := (policyStore.AuthorityScope{TenantID: authorization.TenantID(tenant), PolicyNamespace: "users", SubjectID: authorization.SubjectID(user)}).Key()
	if err != nil {
		t.Fatal(err)
	}
	b := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	base.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(directory.Global), Tenant: b(directory.Tenant), User: b(directory.User), Identifier: b(directory.Identifier), Credential: b(directory.Credential), SessionFamily: b(keys.Family), Session: b(keys.Session), Authorization: b(policy)})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(base)
	if err != nil {
		t.Fatal(err)
	}
	payload, expires, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1) ON CONFLICT(tenant_id,user_id) DO NOTHING`, string(tenant), string(user)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(tenant), base.FamilyID, string(user), base.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8::jsonb)`, string(tenant), id, string(user), base.FamilyID, int64(base.Lookup.KeyVersion), base.Lookup.Sum[:], expires, string(payload)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return record
}
