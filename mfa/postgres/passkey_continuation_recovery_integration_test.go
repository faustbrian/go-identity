//go:build integration

package mfapostgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// A real primary SQL oracle for retained MFA evidence, not assertion or factor
// authentication. The public native consumer separately supplies recovery Work.
func testPasskeyContinuationRecoveryPostgres(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	base := ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}
	history, err := (PasskeyContinuationMigrationSource{Base: base, Version: 3}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history[1:] { // Enclosing fixture owns factor authority.
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Raw().Exec(ctx, `DROP TABLE identity_mfa.continuations`); err != nil {
			t.Error("owned continuation cleanup failed", err)
		}
	})
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	raw := mustContinuationCommandBytes(string(command))
	b := identity.CommandBinding{CommandID: command, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, RecordID: string(command), OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1}
	s, _ := continuationFixture(t).Bindings()
	s.TenantID, s.SubjectID = b.TenantID, identity.SubjectID(b.UserID)
	s.PolicyVersion = b.PolicyVersion
	s.PasskeyCommandID, s.PrimaryProofID = command, auth.ProofID(command)
	s.AllowedMethods = []string{"totp"}
	c, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeContinuationScope(c)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	digest, err := c.ScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	challenge := kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: b.UserID, ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}
	if !s.ExpiresAt.Before(time.Now()) {
		t.Fatal("fixture must exercise already-expired historical evidence")
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,decode(repeat('03',32),'hex'),1,decode('01','hex'))`, raw, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal(err)
	}
	// A foundation row with NULL generation is intentionally not an original
	// reservation. Supply the real journal shape, not a forged committed receipt.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose,state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at) VALUES($1,$2,$3,'pending',1,1,$1,current_timestamp+interval '1 minute',current_timestamp,current_timestamp,current_timestamp)`, raw, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('03',32),'hex'),1,$7,$8,1,1,$9,$9,$10,$11)`, string(s.TenantID), string(s.ID), string(s.SubjectID), string(s.SourcePreAuthID), raw, b.OperationID, digest[:], wire, s.MaxAttempts, s.IssuedAt, s.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"expired-pending", "expired", "completed", "challenged", "revoked", "absent", "wrong-child", "wrong-user", "wrong-digest", "corrupt-wire", "foreign-fingerprint", "future-generation", "wrong-source", "wrong-time", "unmarked-primary", "storage-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			declared := challenge
			statement := ""
			switch mode {
			case "storage-unavailable":
				statement = `DROP TABLE identity_mfa.continuations`
			case "expired":
				statement = `UPDATE identity_mfa.continuations SET state=4`
			case "completed":
				statement = `UPDATE identity_mfa.continuations SET state=3,version=2,attempts_remaining=2`
			case "challenged":
				statement = `UPDATE identity_mfa.continuations SET state=2,version=2,attempts_remaining=2`
			case "revoked":
				statement = `UPDATE identity_mfa.continuations SET state=5,version=4,attempts_remaining=0`
			case "absent":
				statement = `DELETE FROM identity_mfa.continuations`
			case "wrong-child":
				statement = `UPDATE identity_mfa.continuations SET continuation_id='AgICAgICAgICAgICAgICAg'`
			case "wrong-user":
				if _, err := tx.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','recovery-foreign-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('02',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('02',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('02',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','recovery-foreign-user',1,0,decode(repeat('02',16),'hex'),'identity.password.signup')`); err != nil {
					t.Fatal(err)
				}
				statement = `UPDATE identity_mfa.continuations SET user_id='recovery-foreign-user'`
			case "wrong-digest":
				statement = `UPDATE identity_mfa.continuations SET scope_digest=decode(repeat('04',32),'hex')`
			case "corrupt-wire":
				statement = `UPDATE identity_mfa.continuations SET original_scope=decode('01','hex')`
			case "foreign-fingerprint":
				statement = `UPDATE identity_mfa.continuations SET origin_fingerprint=decode(repeat('04',32),'hex')`
			case "future-generation":
				statement = `UPDATE identity_mfa.continuations SET origin_generation=2`
			case "wrong-source":
				statement = `UPDATE identity_mfa.continuations SET source_preauth_id='AgICAgICAgICAgICAgICAg'`
			case "wrong-time":
				statement = `UPDATE identity_mfa.continuations SET expires_at=expires_at+interval '1 second'`
			case "unmarked-primary":
				legacy := s
				legacy.PasskeyCommandID = ""
				projection, err := mfa.NewPartialAuthContinuation(legacy)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := encodeContinuationScope(projection)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(encoded)
				declared.ScopeDigest, err = projection.ScopeDigest()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `UPDATE identity_mfa.continuations SET original_scope=$1,scope_digest=$2`, encoded, declared.ScopeDigest[:]); err != nil {
					t.Fatal(err)
				}
			}
			if statement != "" {
				if _, err := tx.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			status, err := recoverPasskeyContinuation(ctx, func(ctx context.Context, q string, args []any, dest ...any) error {
				return tx.QueryRow(ctx, q, args...).Scan(dest...)
			}, b, declared)
			switch mode {
			case "expired-pending", "expired", "completed", "challenged", "revoked":
				if err != nil || status != kernel.RecoveryCommitted {
					t.Fatal("historical lifecycle erased original commitment", status, err)
				}
			case "absent":
				if err != nil || status != kernel.RecoveryNotCommitted {
					t.Fatal("missing participant evidence did not remain noncommit vote", status, err)
				}
			default:
				if err == nil || status != kernel.RecoveryUnknown {
					t.Fatal("conflicting evidence classified as commitment/noncommit", status, err)
				}
			}
		})
	}
	var stored []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT original_scope FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2 AND state=1 AND version=1 AND attempts_remaining=max_attempts`, string(s.TenantID), string(s.ID)).Scan(&stored); err != nil || !bytes.Equal(stored, wire) {
		t.Fatal("read-only recovery changed original scope or lifecycle", err)
	}
	clear(stored)
	canceled, stop := context.WithCancel(ctx)
	stop()
	status, err := recoverPasskeyContinuation(canceled, func(ctx context.Context, q string, args []any, dest ...any) error {
		return pool.Raw().QueryRow(ctx, q, args...).Scan(dest...)
	}, b, challenge)
	if status != kernel.RecoveryUnknown || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation became recovery evidence", status, err)
	}
}
