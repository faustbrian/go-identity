//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/faustbrian/go-authorization"
	"net/http"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// Reuse the owned issuer/primary/audit/outbox harness. Aging these fixture rows
// models a previously issued eligible session without sleeping or renewing any
// admission. Authentication is acquired anew only after the old durable record
// is installed. This is not an issuance workaround or an application store.
func testNativeSessionRotation(t *testing.T, ctx context.Context, pool *database.Pool, execution IssueExecutorConfig, validation session.ServiceConfig, reader *session.SessionService, issue func(*testing.T) (session.GetResult, session.GetRequest), issuedTokens map[string]session.Token) {
	t.Helper()
	successorTokens := make(map[identity.CommandID]session.Token)
	eligible := func(t *testing.T) (session.GetResult, session.GetRequest) {
		t.Helper()
		caller, input := issue(t)
		original, _ := caller.Session.Bindings()
		original.IssuedAt = original.IssuedAt.Add(-5 * time.Minute)
		original.LastActivityAt = original.LastActivityAt.Add(-5 * time.Minute)
		original.Authentication.Proof.IssuedAt = original.Authentication.Proof.IssuedAt.Add(-5 * time.Minute)
		original.Authentication.Proof.ExpiresAt = original.Authentication.Proof.ExpiresAt.Add(-5 * time.Minute)
		aged, err := session.NewSession(original)
		if err != nil {
			t.Fatal(err)
		}
		payload, expiry, err := encodeRecord(aged)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND session_id=$4`, string(payload), expiry, string(original.TenantID), original.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.families SET issued_at=$1 WHERE tenant_id=$2 AND family_id=$3`, original.IssuedAt.Format(storedTimeLayout), string(original.TenantID), original.FamilyID); err != nil {
			t.Fatal(err)
		}
		caller, err = reader.Get(ctx, input)
		if err != nil || !caller.Authenticated || !caller.NeedsRefresh {
			t.Fatal("eligible source", err)
		}
		return caller, input
	}
	prepare := func(t *testing.T) (*RotationExecutor, session.RotationRequest, session.GetRequest) {
		t.Helper()
		caller, input := eligible(t)
		config := execution
		config.Coordinator.FinalAuthentication = nil
		executor, err := NewRotationExecutor(pool, RotationExecutorConfig{Execution: config, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		old, _ := caller.Session.Bindings()
		next := old
		next.Version++
		next.LastActivityAt = time.Now().UTC()
		token, err := session.NewToken(32)
		if err != nil {
			t.Fatal(err)
		}
		next.Lookup, err = token.Digest(validation.LookupKeys[0], string(old.TenantID))
		if err != nil {
			t.Fatal(err)
		}
		vector, _ := next.Authority.Bindings()
		vector.Session.Version = next.Version
		next.Authority, err = session.NewAuthoritySnapshot(vector)
		if err != nil {
			t.Fatal(err)
		}
		successor, err := session.NewSession(next)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		successorTokens[id] = token
		b := identity.CommandBinding{CommandID: id, TenantID: old.TenantID, UserID: old.UserID, ActorID: identity.ActorID(old.UserID), ActorKind: authorization.SubjectUser, OperationID: session.RotateOperation().OperationID, RecordID: old.SessionID, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, SchemaID: session.RotateOperation().SchemaID, SchemaVersion: 1, CorrelationID: "rotation-test"}
		command, err := session.NewRotateCommand(b, caller.Session, successor)
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRotation(caller, command)
		if err != nil {
			t.Fatal(err)
		}
		return executor, request, input
	}
	t.Run("retired credential revokes its family", func(t *testing.T) {
		executor, request, _ := prepare(t)
		command, _ := request.Command()
		rotation, _ := command.Rotation()
		source, _ := rotation.Source.Bindings()
		if out, err := executor.ExecuteRotation(ctx, request); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("replay source was not rotated", err)
		}
		_, unrelated := issue(t)
		guard, err := NewFamilyReplayGuard(pool, FamilyReplayGuardConfig{Execution: execution, LookupKeys: validation.LookupKeys, ActorID: "session-replay-worker"})
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		input := FamilyReplayInput{TenantID: source.TenantID, Token: issuedTokens[source.SessionID], CommandID: id, CorrelationID: "replayed-token"}
		result, err := guard.CheckReplay(ctx, input)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.BeforeVersion != 1 || result.Feature.AfterVersion != 2 || result.Binding.ActorKind != authorization.SubjectServiceAccount || result.Binding.RecordID != source.FamilyID {
			t.Fatal("retired token did not revoke exact family", err)
		}
		repeated, err := guard.CheckReplay(ctx, input)
		if err != nil || repeated.Outcome != identity.CommitOutcomeCommitted || repeated.AuditEventID != result.AuditEventID || repeated.Binding != result.Binding {
			t.Fatal("replay check duplicated transition", err)
		}
		stored, err := executor.owned.native.Get(ctx, source.TenantID, source.SessionID)
		if err != nil || !stored.FamilyRevoked || stored.CurrentFamilyVersion != 2 {
			t.Fatal("successor retained usable family", err)
		}
		credential, err := session.NewCredential(session.CredentialCookie, successorTokens[rotation.Binding.CommandID])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := reader.Get(ctx, session.GetRequest{TenantID: source.TenantID, Credential: credential}); err != nil || got.Authenticated {
			t.Fatal("revoked successor still authenticates", err)
		}
		if got, err := reader.Get(ctx, unrelated); err != nil || !got.Authenticated {
			t.Fatal("unrelated family revoked", err)
		}
		var audits, events, revocations int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM session_store.family_revocations WHERE command_id=$1)`, mustCommandBytes(t, id)).Scan(&audits, &events, &revocations); err != nil || audits != 1 || events != 1 || revocations != 1 {
			t.Fatal("replay revocation effects not atomic/idempotent", err)
		}
	})
	testNativeFamilyReplay(t, ctx, pool, execution, validation, reader, prepare, issuedTokens, successorTokens, issue)
	t.Run("waiting direct writer cannot restore a concurrently retired digest", func(t *testing.T) {
		caller, _ := issue(t)
		old, _ := caller.Session.Bindings()
		candidate := old
		token, err := session.NewToken(32)
		if err != nil {
			t.Fatal(err)
		}
		candidate.Lookup, err = token.Digest(validation.LookupKeys[0], string(old.TenantID))
		if err != nil {
			t.Fatal(err)
		}
		changed, err := session.NewSession(candidate)
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := encodeRecord(changed)
		if err != nil {
			t.Fatal(err)
		}
		// This deliberately uses direct table writes to model old binaries;
		// it tests the universal storage guard, not the rotation command API.
		first, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback(ctx)
		if _, err = first.Exec(ctx, `UPDATE session_store.sessions SET digest=$1,record=$2::jsonb WHERE tenant_id=$3 AND session_id=$4`, candidate.Lookup.Sum[:], string(payload), string(old.TenantID), old.SessionID); err != nil {
			t.Fatal(err)
		}
		second, err := pool.Raw().Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Release()
		var pid int32
		if err = second.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		result := make(chan error, 1)
		go func() {
			_, err := second.Exec(bounded, `UPDATE session_store.sessions SET digest=$1 WHERE tenant_id=$2 AND session_id=$3`, old.Lookup.Sum[:], string(old.TenantID), old.SessionID)
			result <- err
		}()
		// Always join the bounded writer before releasing its connection, even
		// when the barrier or first commit fails.
		joined := false
		defer func() {
			if !joined {
				stop()
				<-result
			}
		}()
		blocked := false
		for !blocked && bounded.Err() == nil {
			if err = pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-timer.C:
				case <-bounded.Done():
				}
				timer.Stop()
			}
		}
		if !blocked {
			t.Fatal("second writer never reached lock barrier")
		}
		if err = first.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = <-result
		joined = true
		var rejected *pgconn.PgError
		if !errors.As(err, &rejected) || rejected.Code != "23505" {
			t.Fatal("waiting writer restored retired digest")
		}
	})
	t.Run("deletion cannot reissue the same digest and session ID", func(t *testing.T) {
		caller, _ := issue(t)
		record, _ := caller.Session.Bindings()
		payload, expiry, err := encodeRecord(caller.Session)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(record.TenantID), record.SessionID); err != nil {
			t.Fatal(err)
		}
		_, err = pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,$5::numeric,$10::numeric,'active',$6,$7,$8,$9::jsonb)`, string(record.TenantID), string(record.UserID), record.SessionID, record.FamilyID, strconv.FormatUint(record.Version, 10), int64(record.Lookup.KeyVersion), record.Lookup.Sum[:], expiry, string(payload), strconv.FormatUint(record.FamilyVersion, 10))
		var rejected *pgconn.PgError
		if !errors.As(err, &rejected) || rejected.Code != "23505" {
			t.Fatal("deleted digest/session ID resurrected")
		}
	})
	t.Run("distinct commands race one original source", func(t *testing.T) {
		executor, first, input := prepare(t)
		command, _ := first.Command()
		rotation, _ := command.Rotation()
		// Obtain a second authenticating observation before either mutation.
		caller, err := reader.Get(ctx, input)
		if err != nil || !caller.Authenticated {
			t.Fatal(err)
		}
		next, _ := rotation.Successor.Bindings()
		next.LastActivityAt = time.Now().UTC()
		next.Lookup.Sum[0] ^= 1
		successor, err := session.NewSession(next)
		if err != nil {
			t.Fatal(err)
		}
		b := rotation.Binding
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		other, err := session.NewRotateCommand(b, rotation.Source, successor)
		if err != nil {
			t.Fatal(err)
		}
		second, err := reader.PrepareRotation(caller, other)
		if err != nil {
			t.Fatal(err)
		}
		type outcome struct {
			result session.RotationExecution
			err    error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		for _, request := range []session.RotationRequest{first, second} {
			go func() { <-start; r, err := executor.ExecuteRotation(call, request); results <- outcome{r, err} }()
		}
		close(start)
		a, z := <-results, <-results
		committed := 0
		for _, got := range []outcome{a, z} {
			if got.result.Receipt.Outcome == identity.CommitOutcomeCommitted && got.err == nil {
				committed++
			} else if got.err == nil || got.result.Session != (session.Session{}) {
				t.Fatal("loser escaped a successor", got.err)
			}
		}
		if committed != 1 {
			t.Fatal("source did not have exactly one winner")
		}
		var count int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.session_rotations WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), b.RecordID).Scan(&count); err != nil || count != 1 {
			t.Fatal("duplicate durable rotation", err)
		}
	})
	for _, mode := range []string{"cancelled", "blocked user", "audit rollback", "ambiguous commit"} {
		t.Run(mode, func(t *testing.T) {
			executor, request, input := prepare(t)
			command, _ := request.Command()
			rotation, _ := command.Rotation()
			b := rotation.Binding
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
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE TRIGGER reject_rotation_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_audit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_rotation_audit ON audit.identity_command_bindings;DROP FUNCTION public.reject_rotation_audit()`); err != nil {
						t.Error(err)
					}
				}()
			case "ambiguous commit":
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_rotation_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$;CREATE CONSTRAINT TRIGGER reject_rotation_commit AFTER INSERT ON session_store.session_rotations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_commit()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_rotation_commit ON session_store.session_rotations;DROP FUNCTION public.reject_rotation_commit()`); err != nil {
						t.Error(err)
					}
				}()
			}
			out, err := executor.ExecuteRotation(call, request)
			if err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted || out.Session != (session.Session{}) {
				t.Fatal("failed rotation escaped successor", err)
			}
			var records, retired int
			if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.session_rotations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), mustCommandBytes(t, b.CommandID)).Scan(&records); err != nil {
				t.Fatal(err)
			}
			if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.retired_tokens WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), mustCommandBytes(t, b.CommandID)).Scan(&retired); err != nil || records != 0 || retired != 0 {
				t.Fatal("rollback retained provisional rotation", err)
			}
			if mode != "blocked user" {
				if old, err := reader.Get(ctx, input); err != nil || !old.Authenticated {
					t.Fatal("rollback lost original session", err)
				}
			}
			if mode == "ambiguous commit" {
				if out.Receipt.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("commit failure falsely proves rollback")
				}
				restarted, err := NewRotationExecutor(pool, RotationExecutorConfig{Execution: execution, Sessions: reader})
				if err != nil {
					t.Fatal(err)
				}
				q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				trustedCaller := executor.rotationCaller(b)
				observed, err := restarted.RecoverRotationCommand(ctx, q, trustedCaller)
				if err != nil || observed.Outcome != identity.CommitOutcomeInProgress || observed.RetryAfter <= 0 || observed.Binding != b {
					t.Fatal("live restart lost original pending outcome", err)
				}
				var generation int64
				var leaseBefore, leaseAfter time.Time
				if err = pool.Raw().QueryRow(ctx, `SELECT generation,lease_until FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&generation, &leaseBefore); err != nil || generation != 1 {
					t.Fatal("live recovery took ownership", err)
				}
				if _, err = restarted.RecoverRotationCommand(ctx, q, trustedCaller); err != nil {
					t.Fatal(err)
				}
				if err = pool.Raw().QueryRow(ctx, `SELECT generation,lease_until FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&generation, &leaseAfter); err != nil || generation != 1 || !leaseBefore.Equal(leaseAfter) {
					t.Fatal("live recovery renewed custody", err)
				}
				if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); err != nil {
					t.Fatal(err)
				}
				t.Run("missing rotation evidence cannot prove rollback", func(t *testing.T) {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE session_store.session_rotations RENAME TO hidden_session_rotations`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := pool.Raw().Exec(ctx, `ALTER TABLE session_store.hidden_session_rotations RENAME TO session_rotations`); err != nil {
							t.Error("restore rotation evidence", err)
						}
					}()
					got, err := restarted.RecoverRotationCommand(ctx, q, trustedCaller)
					if err == nil || got.Binding != b || (got.Outcome != identity.CommitOutcomeInProgress && got.Outcome != identity.CommitOutcomeUnknown) {
						t.Fatal("missing evidence falsely terminalized command", err)
					}
					var state string
					if err = pool.Raw().QueryRow(ctx, `SELECT state,generation FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&state, &generation); err != nil || state != "pending" || generation != 1 {
						t.Fatal("failed recovery changed durable ownership", err)
					}
				})
				observed, err = restarted.RecoverRotationCommand(ctx, q, trustedCaller)
				if err == nil || observed.Binding != b || observed.Outcome != identity.CommitOutcomeNotCommitted || observed.Feature == nil || observed.Feature.Operation != session.RotateOperation() {
					t.Fatal("restart did not reconcile proven negative evidence", err)
				}
				recovered, err := executor.RecoverRotation(ctx, request)
				if err == nil || recovered.Receipt.Outcome != identity.CommitOutcomeNotCommitted || recovered.Session != (session.Session{}) {
					t.Fatal("negative recovery incomplete", err)
				}
			}
		})
	}
	t.Run("owned rotation retires digest and retains historical recovery", func(t *testing.T) {
		caller, input := issue(t)
		original, _ := caller.Session.Bindings()
		original.IssuedAt = original.IssuedAt.Add(-5 * time.Minute)
		original.LastActivityAt = original.LastActivityAt.Add(-5 * time.Minute)
		original.Authentication.Proof.IssuedAt = original.Authentication.Proof.IssuedAt.Add(-5 * time.Minute)
		original.Authentication.Proof.ExpiresAt = original.Authentication.Proof.ExpiresAt.Add(-5 * time.Minute)
		aged, err := session.NewSession(original)
		if err != nil {
			t.Fatal("historical eligible record", err)
		}
		payload, expiry, err := encodeRecord(aged)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id=$3 AND session_id=$4`, string(payload), expiry, string(original.TenantID), original.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.families SET issued_at=$1 WHERE tenant_id=$2 AND family_id=$3`, original.IssuedAt.Format(storedTimeLayout), string(original.TenantID), original.FamilyID); err != nil {
			t.Fatal(err)
		}
		caller, err = reader.Get(ctx, input)
		if err != nil || !caller.Authenticated || !caller.NeedsRefresh {
			t.Fatal("eligible primary source", err)
		}
		execution.Coordinator.FinalAuthentication = nil
		executor, err := NewRotationExecutor(pool, RotationExecutorConfig{Execution: execution, Sessions: reader})
		if err != nil {
			t.Fatal(err)
		}
		cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
		rotator, err := session.NewSessionRotator(reader, executor, session.RotationConfig{PolicyID: execution.PolicyID, PolicyVersion: execution.PolicyVersion, MaximumDuration: 2 * time.Second, LookupKey: validation.LookupKeys[0], TokenSize: 32, Cookie: cookie})
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := rotator.Prepare(caller, id, "native-rotation")
		if err != nil {
			t.Fatal(err)
		}
		request, _ := prepared.Request()
		command, _ := request.Command()
		transition, _ := command.Rotation()
		result, err := rotator.Rotate(ctx, prepared)
		if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
			t.Fatal("rotation did not commit", err)
		}
		wire, err := result.Token.Reveal()
		if err != nil {
			t.Fatal("new committed credential withheld", err)
		}
		token, err := session.ParseToken(wire)
		if err != nil {
			t.Fatal(err)
		}
		credential, _ := session.NewCredential(session.CredentialCookie, token)
		nextInput := session.GetRequest{TenantID: input.TenantID, Credential: credential}
		got, err := reader.Get(ctx, nextInput)
		if err != nil || !got.Authenticated {
			t.Fatal("successor not readable", err)
		}
		want, _, _ := encodeRecord(transition.Successor)
		actual, _, _ := encodeRecord(got.Session)
		if !bytes.Equal(want, actual) {
			t.Fatal("stored successor differs")
		}
		if got, err = reader.Get(ctx, input); err != nil || got.Authenticated {
			t.Fatal("retired source credential accepted", err)
		}
		// Older binaries and direct table writers must obey the same digest
		// invariant, not only the new executor's advisory precheck. Attempt to
		// restore the retired digest on the very same surviving session ID.
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET digest_version=$1,digest=$2 WHERE tenant_id=$3 AND session_id=$4`, int64(original.Lookup.KeyVersion), original.Lookup.Sum[:], string(input.TenantID), original.SessionID); err == nil {
			t.Fatal("direct writer resurrected retired digest")
		}
		if got, err = reader.Get(ctx, nextInput); err != nil || !got.Authenticated {
			t.Fatal("rejected direct write damaged successor", err)
		}
		replayed, err := executor.ExecuteRotation(ctx, request)
		if err != nil || !replayed.Replayed || replayed.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("exact replay changed outcome", err)
		}
		recovered, err := rotator.Recover(ctx, request)
		if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed {
			t.Fatal("historical recovery", err)
		}
		if _, err = recovered.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) {
			t.Fatal("recovery redelivered credential")
		}
		testRotationRestartRecovery(t, ctx, pool, execution, validation, transition.Binding, replayed.Receipt)
		for _, column := range []string{"source_digest", "successor_digest", "intent_digest"} {
			var saved []byte
			if err = pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM session_store.session_rotations WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id)).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.session_rotations SET `+column+`=decode(repeat('00',32),'hex') WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id)); err != nil {
				t.Fatal(err)
			}
			bad, badErr := executor.RecoverRotation(ctx, request)
			if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.session_rotations SET `+column+`=$3 WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id), saved); err != nil {
				t.Fatal("restore retained fixture", err)
			}
			if badErr == nil || bad.Receipt.Outcome != identity.CommitOutcomeCommitted || bad.Session != (session.Session{}) {
				t.Fatal("corrupt evidence disclosed a session or erased known commit", column, badErr)
			}
		}
		// Internally consistent retained metadata must still match the original
		// request: recomputing its checksum cannot authorize another successor.
		substitute, _ := transition.Successor.Bindings()
		substitute.Lookup.Sum[0] ^= 1
		forged, err := session.NewSession(substitute)
		if err != nil {
			t.Fatal(err)
		}
		forgedRecord, _, err := encodeRecord(forged)
		if err != nil {
			t.Fatal(err)
		}
		forgedHash := sha256.Sum256(forgedRecord)
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.session_rotations SET successor_record=$3::jsonb,successor_digest=$4 WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id), string(forgedRecord), forgedHash[:]); err != nil {
			t.Fatal(err)
		}
		bad, badErr := executor.RecoverRotation(ctx, request)
		originalHash := sha256.Sum256(want)
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.session_rotations SET successor_record=$3::jsonb,successor_digest=$4 WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id), string(want), originalHash[:]); err != nil {
			t.Fatal("restore substituted metadata", err)
		}
		if badErr == nil || bad.Receipt.Outcome != identity.CommitOutcomeCommitted || bad.Session != (session.Session{}) {
			t.Fatal("substituted successor disclosed or known commit erased", badErr)
		}
		var receipts, retired int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.session_rotations WHERE tenant_id=$1 AND command_id=$2`, string(input.TenantID), mustCommandBytes(t, id)).Scan(&receipts); err != nil || receipts != 1 {
			t.Fatal("terminal rotation evidence", err)
		}
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.retired_tokens WHERE tenant_id=$1 AND digest_version=$2 AND digest=$3`, string(input.TenantID), int64(original.Lookup.KeyVersion), original.Lookup.Sum[:]).Scan(&retired); err != nil || retired != 1 {
			t.Fatal("original digest not durably retired", err)
		}
	})
}
