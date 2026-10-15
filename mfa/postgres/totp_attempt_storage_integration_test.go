//go:build integration

package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

// The explicit transaction is a storage oracle, not native callback authority
// or proof that a public MFA service can authenticate. All writes roll back.
func testTOTPAttemptStorage(t *testing.T, ctx context.Context, pool *database.Pool, snapshot TOTPFactorSnapshot) {
	t.Helper()
	m, _ := snapshot.Metadata()
	var policy, flow string
	if err := pool.Raw().QueryRow(ctx, `SELECT source_preauth_id,(convert_from(original_scope,'UTF8')::jsonb->'Scope'->>'PolicyVersion') FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(m.TenantID), string(m.ContinuationID)).Scan(&flow, &policy); err != nil {
		t.Fatal(err)
	}
	pv, err := strconv.ParseUint(policy, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	b := kernel.MFATOTPAttemptBinding{Command: identity.CommandBinding{TenantID: m.TenantID, AnonymousFlowID: flow}, Plan: kernel.MFACompletionPlan{ID: identity.CommandID(m.ContinuationID), UserID: m.UserID, ScopeDigest: m.ScopeDigest, PolicyVersion: pv, FactorVersion: m.FactorAuthorityVersion, ContinuationVersion: m.ContinuationVersion}}
	for _, mode := range []string{"absent", "eligible", "stale-epoch", "foreign-flow", "exhaustion"} {
		t.Run("missing-factor-"+mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			sql := totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
				return tx.QueryRow(ctx, q, args...).Scan(dest...)
			}, exec: func(ctx context.Context, q string, args ...any) (int64, error) {
				tag, err := tx.Exec(ctx, q, args...)
				return tag.RowsAffected(), err
			}}
			binding, factor := b, "BwcHBwcHBwcHBwcHBwcHBw"
			switch mode {
			case "eligible":
				factor = m.FactorID
			case "stale-epoch":
				binding.Plan.FactorVersion++
			case "foreign-flow":
				binding.Command.AnonymousFlowID = "foreign"
			case "exhaustion":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET state=2,version=2,attempts_remaining=1 WHERE tenant_id=$1 AND continuation_id=$2`, string(m.TenantID), string(m.ContinuationID))
				if err != nil {
					t.Fatal(err)
				}
				binding.Plan.ContinuationVersion = 2
			}
			err = recordMissingTOTPAttempt(ctx, sql, binding, factor)
			var state int16
			var remaining int32
			if readErr := tx.QueryRow(ctx, `SELECT state,attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(m.TenantID), string(m.ContinuationID)).Scan(&state, &remaining); readErr != nil {
				t.Fatal(readErr)
			}
			switch mode {
			case "absent":
				if err != nil || remaining != 2 || state != int16(mfa.Challenged) {
					t.Fatal("missing factor did not spend shared budget", err)
				}
			case "exhaustion":
				if err != nil || remaining != 0 || state != int16(mfa.Revoked) {
					t.Fatal("missing factor did not revoke exhausted continuation", err)
				}
			default:
				if err == nil || remaining != 3 || state != int16(mfa.Pending) {
					t.Fatal("eligible/stale/foreign factor charged shared budget", err)
				}
			}
		})
	}
	for _, mode := range []string{"denied", "exhausted", "completed", "completed-final-attempt", "completed-stale-row", "completed-future-counter", "blocked", "stale-factor", "stale-profile", "stale-replay", "expired", "foreign-flow", "foreign-policy", "foreign-scope"} {
		t.Run("attempt-"+mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			sql := totpAttemptSQL{
				query: func(ctx context.Context, q string, args []any, dest ...any) error {
					return tx.QueryRow(ctx, q, args...).Scan(dest...)
				},
				exec: func(ctx context.Context, q string, args ...any) (int64, error) {
					tag, e := tx.Exec(ctx, q, args...)
					return tag.RowsAffected(), e
				},
			}
			switch mode {
			case "blocked":
				_, err = tx.Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, string(m.TenantID), string(m.UserID))
			case "stale-factor":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(m.TenantID), string(m.UserID))
			case "stale-profile":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.totp_factors SET issuer='Changed' WHERE tenant_id=$1 AND factor_id=$2`, string(m.TenantID), m.FactorID)
			case "stale-replay":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.totp_factors SET last_step=0 WHERE tenant_id=$1 AND factor_id=$2`, string(m.TenantID), m.FactorID)
			case "expired":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET expires_at=date_trunc('second',clock_timestamp())-interval '1 second',issued_at=date_trunc('second',clock_timestamp())-interval '2 seconds' WHERE tenant_id=$1 AND continuation_id=$2`, string(m.TenantID), string(m.ContinuationID))
			case "exhausted", "completed-final-attempt":
				_, err = tx.Exec(ctx, `UPDATE identity_mfa.continuations SET state=2,version=2,attempts_remaining=1 WHERE tenant_id=$1 AND continuation_id=$2`, string(m.TenantID), string(m.ContinuationID))
			}
			if err != nil {
				t.Fatal(err)
			}
			current := snapshot
			binding := b
			switch mode {
			case "foreign-flow":
				binding.Command.AnonymousFlowID = "foreign"
			case "foreign-policy":
				binding.Plan.PolicyVersion++
			case "foreign-scope":
				binding.Plan.ScopeDigest[0]++
			}
			if mode == "exhausted" || mode == "completed-final-attempt" {
				custody := snapshot.custody()
				custody.metadata.ContinuationVersion = 2
				current = TOTPFactorSnapshot{custody: func() totpFactorCustody { return custody }}
				binding.Plan.ContinuationVersion = 2
			}
			c, now, err := lockTOTPAttempt(ctx, sql, binding, current)
			if mode != "denied" && mode != "exhausted" && mode != "completed" && mode != "completed-final-attempt" && mode != "completed-stale-row" && mode != "completed-future-counter" {
				if err == nil {
					t.Fatal("changed authority admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("current encrypted factor denied", err)
			}
			if now.IsZero() || now.Location() != time.UTC {
				t.Fatal("missing database time")
			}
			s, _ := c.Bindings()
			if mode == "completed" || mode == "completed-final-attempt" || mode == "completed-stale-row" || mode == "completed-future-counter" {
				step := uint64(now.Unix() / int64(m.Profile.Period/time.Second))
				if mode == "completed-stale-row" {
					if _, err := tx.Exec(ctx, `UPDATE identity_mfa.totp_factors SET row_version=row_version+1 WHERE tenant_id=$1 AND factor_id=$2`, string(m.TenantID), m.FactorID); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "completed-future-counter" {
					step += 3
				}
				if mode == "completed" || mode == "completed-final-attempt" {
					// The fixture factor uses the public RFC 6238 key. Compute
					// its current code independently, then compare opaque input
					// with the actual verifier while these same locks are held.
					var moving [8]byte
					binary.BigEndian.PutUint64(moving[:], step)
					mac := hmac.New(sha1.New, []byte("12345678901234567890"))
					_, _ = mac.Write(moving[:])
					hash := mac.Sum(nil)
					offset := hash[len(hash)-1] & 15
					code, err := auth.NewOneTimeCode(fmt.Sprintf("%08d", (binary.BigEndian.Uint32(hash[offset:offset+4])&0x7fffffff)%100000000))
					clear(hash)
					if err != nil {
						t.Fatal("fixture code rejected")
					}
					secret, err := password.NewSecret([]byte("12345678901234567890"))
					if err != nil {
						t.Fatal(err)
					}
					defer secret.Destroy()
					verifier, err := mfa.NewTOTPVerifier([32]byte{1})
					if err != nil {
						t.Fatal(err)
					}
					step, err = verifier.Verify(ctx, secret, code, m.Profile, []byte("fixture/locked-completion/key-version-1"), now, m.Replay)
					if err != nil {
						t.Fatal("actual locked code verification failed", err)
					}
				}
				err = completeTOTP(ctx, sql, c, current, now, step)
				if mode == "completed-stale-row" || mode == "completed-future-counter" {
					if err == nil {
						t.Fatal("stale or unverified counter completed continuation")
					}
					return
				}
				if err != nil {
					t.Fatal("current completion rejected", err)
				}
				var state int16
				var version, last, row string
				var remaining int32
				if err = tx.QueryRow(ctx, `SELECT c.state,c.version::text,c.attempts_remaining,t.last_step::text,t.row_version::text FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, string(m.TenantID), string(m.ContinuationID), m.FactorID).Scan(&state, &version, &remaining, &last, &row); err != nil {
					t.Fatal(err)
				}
				if mfa.ContinuationState(state) != mfa.Completed || version != strconv.FormatUint(s.Version+1, 10) || remaining != int32(s.AttemptsRemaining-1) || last != strconv.FormatUint(step, 10) || row != strconv.FormatUint(m.RowVersion+1, 10) {
					t.Fatal("completion split shared budget and factor replay")
				}
				if completeTOTP(ctx, sql, c, current, now, step) == nil {
					t.Fatal("same factor and continuation completed twice")
				}
				if err = tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				var restoredState int16
				var restoredLast *string
				if err = pool.Raw().QueryRow(ctx, `SELECT c.state,t.last_step::text FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, string(m.TenantID), string(m.ContinuationID), m.FactorID).Scan(&restoredState, &restoredLast); err != nil || mfa.ContinuationState(restoredState) != mfa.Pending || restoredLast != nil {
					t.Fatal("rollback retained successful replay or completion", err)
				}
				return
			}
			if err = spendTOTPAttempt(ctx, sql, c, now); err != nil {
				t.Fatal(err)
			}
			if err = spendTOTPAttempt(ctx, sql, c, now); err == nil {
				t.Fatal("same version spent twice")
			}
			var state int16
			var version string
			var remaining int32
			var last *string
			if err = tx.QueryRow(ctx, `SELECT c.state,c.version::text,c.attempts_remaining,t.last_step::text FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, string(m.TenantID), string(m.ContinuationID), m.FactorID).Scan(&state, &version, &remaining, &last); err != nil {
				t.Fatal(err)
			}
			want := mfa.Challenged
			if mode == "exhausted" {
				want = mfa.Revoked
			}
			if mfa.ContinuationState(state) != want || version != strconv.FormatUint(s.Version+1, 10) || remaining != int32(s.AttemptsRemaining-1) || last != nil {
				t.Fatal("denial renewed scope, skipped charge or advanced replay")
			}
		})
	}
	t.Run("attempt-lock-cancellation", func(t *testing.T) {
		first, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback(context.Background())
		if _, err = first.Exec(ctx, `SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(m.TenantID), string(m.UserID)); err != nil {
			t.Fatal(err)
		}
		second, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Rollback(context.Background())
		bounded, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
		defer cancel()
		sql := totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
			return second.QueryRow(ctx, q, args...).Scan(dest...)
		}}
		if _, _, err = lockTOTPAttempt(bounded, sql, b, snapshot); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("contended lock ignored bounded cancellation", err)
		}
	})
}
