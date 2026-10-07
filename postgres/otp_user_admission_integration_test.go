//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testOTPUserAuthority(t *testing.T, ctx context.Context, pool *database.Pool) {
	w, _, _ := otpAuthorityFixture(t, ctx, "attempt", "")
	b := w.state.binding
	// Remove the existing test-only reference. Successful admission must not
	// require or create one for this passwordless user.
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"attempt", "reservation", "apply", "finalize"} {
		for _, mode := range []string{"exact", "aggregate-only", "user-stale", "identifier-stale", "credential-stale", "blocked", "absent", "full-width", "lock-deadline", "retained-lock", "open-cursor"} {
			t.Run("passwordless/"+phase+"/"+mode, func(t *testing.T) {
				_, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=101,authority_version=13,identifier_version=17,credential_version=19 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
				if err != nil {
					t.Fatal(err)
				}
				expected := UserAuthorityAdmission{UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19}
				sql := ""
				switch mode {
				case "aggregate-only":
					sql = `UPDATE identity.users SET version=102 WHERE tenant_id=$1 AND user_id=$2`
				case "user-stale":
					sql = `UPDATE identity.users SET authority_version=14 WHERE tenant_id=$1 AND user_id=$2`
				case "identifier-stale":
					sql = `UPDATE identity.users SET identifier_version=18 WHERE tenant_id=$1 AND user_id=$2`
				case "credential-stale":
					sql = `UPDATE identity.users SET credential_version=20 WHERE tenant_id=$1 AND user_id=$2`
				case "blocked":
					sql = `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`
				case "full-width":
					sql = `UPDATE identity.users SET authority_version=18446744073709551615,identifier_version=18446744073709551614,credential_version=18446744073709551613 WHERE tenant_id=$1 AND user_id=$2`
					expected = UserAuthorityAdmission{^uint64(0), ^uint64(0) - 1, ^uint64(0) - 2}
				}
				if sql != "" {
					if _, err = pool.Raw().Exec(ctx, sql, string(b.TenantID), string(b.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				live, check, deactivate := otpUserCheck(t, ctx, phase, "")
				live.state.tx = tx
				defer deactivate()
				defer invalidateWork(live)
				if mode == "absent" {
					if _, err = tx.Exec(ctx, `DELETE FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
						t.Fatal(err)
					}
				}
				id := "passwordless-" + phase + "-" + mode
				if _, err = live.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES($1)`, id); err != nil {
					t.Fatal(err)
				}
				checkCtx := ctx
				if mode == "lock-deadline" {
					blocker, e := pool.Raw().Begin(ctx)
					if e != nil {
						t.Fatal(e)
					}
					defer blocker.Rollback(ctx)
					if _, e = blocker.Exec(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(b.TenantID), string(b.UserID)); e != nil {
						t.Fatal(e)
					}
					var cancel context.CancelFunc
					checkCtx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
					defer cancel()
					// Release the competing writer before later outcome reads.
					err = check(checkCtx, expected)
					if e = blocker.Rollback(ctx); e != nil {
						t.Fatal(e)
					}
				} else if mode == "open-cursor" {
					rows, e := live.Query(ctx, "SELECT 1")
					if e != nil {
						t.Fatal(e)
					}
					err = check(ctx, expected)
					rows.Close()
				} else {
					err = check(checkCtx, expected)
				}
				allow := mode == "exact" || mode == "aggregate-only" || mode == "full-width" || mode == "retained-lock"
				if allow {
					if err != nil || live.state.failed != nil {
						t.Fatalf("passwordless exact admission denied: %v", err)
					}
					if mode == "retained-lock" {
						blocked, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
						_, e := pool.Raw().Exec(blocked, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
						cancel()
						if !errors.Is(e, context.DeadlineExceeded) {
							t.Fatalf("user share lock not retained: %v", e)
						}
					}
					if err = tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					if err == nil || live.state.failed == nil {
						t.Fatal("ignored user denial left live transaction usable")
					}
					if mode == "lock-deadline" && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("lock deadline classification: %v", err)
					}
					if mode != "lock-deadline" && mode != "open-cursor" {
						var denied identity.ForbiddenError
						if !errors.As(err, &denied) {
							t.Fatalf("denial classification: %v", err)
						}
					}
					if _, e := live.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES('passwordless-ignored')`); e == nil {
						t.Fatal("denial permitted later effects")
					}
					if e := tx.Rollback(ctx); e != nil && !(mode == "lock-deadline" && tx.Conn().IsClosed()) {
						t.Fatal(e)
					}
				}
				var effects, refs int
				if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.otp_authority_effects WHERE id=$1`, id).Scan(&effects); err != nil {
					t.Fatal(err)
				}
				if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)).Scan(&refs); err != nil {
					t.Fatal(err)
				}
				if (allow && effects != 1) || (!allow && effects != 0) || refs != 0 {
					t.Fatal("passwordless authority/effects or credential-free invariant diverged")
				}
			})
		}
	}
}
