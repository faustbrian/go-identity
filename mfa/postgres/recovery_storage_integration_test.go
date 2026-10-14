//go:build integration

package mfapostgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Bootstrap and raw transactions are labeled storage-oracle seams, not native
// callback custody or public authentication. The real SQL locks, digest compare,
// burn, shared-budget completion and rollback are exercised against PostgreSQL.
func testRecoveryStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, recoverySetSQL); err != nil {
		t.Fatal("recovery storage install", err)
	}
	tenant, user := "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg"
	signup, enrollment, origin, use := "AAAAAAAAAAAAAAAAAAAAAw", "AAAAAAAAAAAAAAAAAAAABA", "AAAAAAAAAAAAAAAAAAAABQ", "AAAAAAAAAAAAAAAAAAAABg"
	for _, command := range []struct{ id, purpose string }{{signup, "identity.password.signup"}, {enrollment, "identity.mfa.enable"}, {origin, "identity.magic-link.consume"}, {use, "identity.mfa.recovery-use"}} {
		id := mustContinuationCommandBytes(command.id)
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,decode('01','hex'))`, id, tenant, command.purpose, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, tenant, command.purpose); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=decode(repeat('01',16),'hex'),lease_until=now(),heartbeat_at=now(),created_at=now(),updated_at=now(),result_version=1,terminal_class='committed',result=decode('01','hex'),terminal_at=now() WHERE command_id=$1`, mustContinuationCommandBytes(origin)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, tenant, user); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES($1,$2,7,1,$3,'identity.password.signup')`, tenant, user, mustContinuationCommandBytes(signup)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,$3,2,1,1,'SHA1',6,30,0,'Example',decode('01','hex'),$4,'identity.mfa.enable',$5,$6,$5)`, tenant, user, enrollment, mustContinuationCommandBytes(enrollment), now, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, _ := continuationFixture(t).Bindings()
	s.TenantID, s.SubjectID, s.SourcePreAuthID = identity.TenantID(tenant), identity.SubjectID(user), identity.PreAuthTransactionID(origin)
	s.IssuedAt, s.ExpiresAt, s.PrimaryProofExpiresAt = now, now.Add(2*time.Minute), now.Add(3*time.Minute)
	c, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := encodeContinuationScope(c)
	digest, _ := c.ScopeDigest()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,'identity.magic-link.consume',$6,1,$7,$8,1,1,3,3,$9,$10)`, tenant, string(s.ID), user, origin, mustContinuationCommandBytes(origin), make([]byte, 32), digest[:], wire, s.IssuedAt, s.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	m := RecoverySetMetadata{TenantID: s.TenantID, UserID: identity.UserID(user), FactorID: enrollment, SetID: enrollment, SetVersion: 1, RowVersion: 1, KeyVersion: 1, CodeCount: 1}
	code, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	binding, _ := recoveryCodeBinding(m)
	codeDigest, _ := code.KeyedDigest([32]byte{1}, binding)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.recovery_sets VALUES($1,$2,$3,$3,1,1,2,1,1,$4,'identity.mfa.enable',$5)`, tenant, user, enrollment, mustContinuationCommandBytes(enrollment), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.recovery_codes(tenant_id,set_id,code_index,digest) VALUES($1,$2,0,$3)`, tenant, enrollment, codeDigest[:]); err != nil {
		t.Fatal(err)
	}
	keys, _ := NewRecoveryVerificationKeys(map[uint32][32]byte{1: {1}})
	b := kernel.MFARecoveryAttemptBinding{Command: identity.CommandBinding{TenantID: s.TenantID, CommandID: identity.CommandID(use), AnonymousFlowID: origin, OperationID: "identity.mfa.recovery-use"}, Plan: kernel.MFACompletionPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(user), ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, ContinuationVersion: s.Version}}
	for _, mode := range []string{"wrong", "consumed", "pending", "blocked", "stale-factor", "foreign-flow", "missing-key", "incomplete-set", "expired", "exhausted", "stale-set", "rollback", "last-attempt", "commit"} {
		t.Run("recovery-storage-"+mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			store := recoveryStore{sql: totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
				return tx.QueryRow(ctx, q, args...).Scan(dest...)
			}, exec: func(ctx context.Context, q string, args ...any) (int64, error) {
				tag, err := tx.Exec(ctx, q, args...)
				return tag.RowsAffected(), err
			}}, read: func(ctx context.Context, b identity.CommandBinding, p kernel.MFACompletionPlan) ([]recoveryCodeRow, error) {
				rows, err := tx.Query(ctx, recoveryRowsSQL, string(b.TenantID), string(p.UserID))
				if err != nil {
					return nil, err
				}
				defer rows.Close()
				var result []recoveryCodeRow
				for rows.Next() {
					r := recoveryCodeRow{set: m}
					var epoch, version, enrollment string
					var digest []byte
					if err := rows.Scan(&r.set.SetID, &r.set.FactorID, &epoch, &version, &r.set.KeyVersion, &r.set.CodeCount, &r.index, &digest, &r.consumed, &enrollment); err != nil {
						return nil, err
					}
					r.set.SetVersion, _ = strconv.ParseUint(epoch, 10, 64)
					r.set.RowVersion, _ = strconv.ParseUint(version, 10, 64)
					r.set.FactorEnrollmentVersion, _ = strconv.ParseUint(enrollment, 10, 64)
					copy(r.digest[:], digest)
					result = append(result, r)
				}
				return result, rows.Err()
			}}
			command, input := b, code
			switch mode {
			case "wrong":
				input, _ = auth.NewRecoveryCode("different-recovery-code")
			case "consumed":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.recovery_codes SET consumed_command_id=$1,consumed_purpose='identity.mfa.recovery-use',consumed_at=clock_timestamp() WHERE tenant_id=$2`, mustContinuationCommandBytes(use), tenant)
			case "pending":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=1 WHERE tenant_id=$1`, tenant)
			case "blocked":
				_, err = tx.Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1`, tenant)
			case "stale-factor":
				command.Plan.FactorVersion++
			case "foreign-flow":
				command.Command.AnonymousFlowID = use
			case "missing-key":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET key_version=2 WHERE tenant_id=$1`, tenant)
			case "incomplete-set":
				_, err = tx.Exec(ctx, `DELETE FROM identity_mfa.recovery_codes WHERE tenant_id=$1`, tenant)
			case "expired":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET issued_at=date_trunc('second',clock_timestamp())-interval '2 seconds',expires_at=date_trunc('second',clock_timestamp())-interval '1 second' WHERE tenant_id=$1`, tenant)
			case "exhausted":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET state=4,version=4,attempts_remaining=0 WHERE tenant_id=$1`, tenant)
				command.Plan.ContinuationVersion = 4
			case "last-attempt":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET state=2,version=3,attempts_remaining=1 WHERE tenant_id=$1`, tenant)
				command.Plan.ContinuationVersion = 3
			}
			if err != nil {
				t.Fatal(err)
			}
			current, at, row, found, err := lockRecovery(ctx, store, command, keys, input)
			if mode == "blocked" || mode == "stale-factor" || mode == "foreign-flow" || mode == "missing-key" || mode == "incomplete-set" || mode == "expired" || mode == "exhausted" {
				if err == nil {
					t.Fatal("invalid authority compared recovery input")
				}
				return
			}
			if err != nil {
				t.Fatal("current recovery lock unavailable", err)
			}
			if mode == "wrong" || mode == "consumed" || mode == "pending" {
				if found {
					t.Fatal("invalid code or pending set authenticated")
				}
				if err := spendMFAAttempt(ctx, store.sql, current, at, "recovery-code"); err != nil {
					t.Fatal(err)
				}
				var remaining int32
				if err := tx.QueryRow(ctx, `SELECT attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1`, tenant).Scan(&remaining); err != nil || remaining != 2 {
					t.Fatal("wrong recovery code did not spend one shared attempt", err)
				}
				return
			}
			if !found {
				t.Fatal("original unused enrollment code rejected")
			}
			if mode == "stale-set" {
				if _, err := tx.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET row_version=2 WHERE tenant_id=$1`, tenant); err != nil {
					t.Fatal(err)
				}
				if completeRecovery(ctx, store.sql, current, row, command.Command, at) == nil {
					t.Fatal("stale set consumed code")
				}
				return
			}
			if err := completeRecovery(ctx, store.sql, current, row, command.Command, at); err != nil {
				t.Fatal("atomic recovery completion failed", err)
			}
			var state int16
			var remaining int32
			var consumed bool
			if err := tx.QueryRow(ctx, `SELECT c.state,c.attempts_remaining,k.consumed_command_id=$1 FROM identity_mfa.continuations c JOIN identity_mfa.recovery_codes k ON k.tenant_id=c.tenant_id WHERE c.tenant_id=$2`, mustContinuationCommandBytes(use), tenant).Scan(&state, &remaining, &consumed); err != nil || state != int16(mfa.Completed) || !consumed || (mode == "last-attempt" && remaining != 0) {
				t.Fatal("burn and continuation split", err)
			}
			if completeRecovery(ctx, store.sql, current, row, command.Command, at) == nil {
				t.Fatal("code burned twice")
			}
			if mode == "commit" {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if mode != "commit" {
				if err := pool.Raw().QueryRow(ctx, `SELECT c.state,c.attempts_remaining,(k.consumed_at IS NOT NULL) FROM identity_mfa.continuations c JOIN identity_mfa.recovery_codes k ON k.tenant_id=c.tenant_id WHERE c.tenant_id=$1`, tenant).Scan(&state, &remaining, &consumed); err != nil || state != int16(mfa.Pending) || remaining != 3 || consumed {
					t.Fatal("rollback retained recovery effects", err)
				}
			}
		})
	}
}
