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

// Use the existing isolated authority fixture and real user-row lifecycle
// locks. No credential row or password/identifier epoch substitutes for owner
// security. Complete API-key issuance/verification remains a separate consumer.
func testCurrentUserStatusAdmission(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, mode := range []string{"exact", "aggregate-only", "other-epochs", "stale-security", "suspended", "banned", "deleted", "missing", "maximum", "lock-deadline", "retained-lock", "ignored-denial", "open-cursor"} {
		t.Run(mode, func(t *testing.T) {
			w, _, returned := otpUserCheck(t, ctx, "feature", "")
			defer returned()
			defer invalidateWork(w)
			b := w.state.binding
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=101,authority_version=13,identifier_version=17,credential_version=19 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
				t.Fatal(err)
			}
			expected := identity.UserStatusRecord{User: identity.User{TenantID: b.TenantID, ID: b.UserID, Version: 101, Status: identity.StatusActive}, AuthorityVersion: 13}
			switch mode {
			case "aggregate-only":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=102 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			case "other-epochs":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET identifier_version=18,credential_version=20 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			case "stale-security", "ignored-denial":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=14 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			case "suspended", "banned", "deleted":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status=$3 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID), mode); err != nil {
					t.Fatal(err)
				}
			case "maximum":
				expected.AuthorityVersion = ^uint64(0)
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=18446744073709551615 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			w.state.tx = tx
			owner := w.state.featureInvocation.(FeatureExecutionContributor)
			if mode == "missing" {
				if _, err := tx.Exec(ctx, `DELETE FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			id := "user-status-" + mode
			if _, err := w.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES($1)`, id); err != nil {
				t.Fatal(err)
			}
			var checkErr error
			if mode == "lock-deadline" {
				blocker, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(ctx)
				if _, err := blocker.Exec(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 30*time.Millisecond)
				checkErr = w.RequireActiveUserStatus(bounded, owner, expected)
				stop()
				if err := blocker.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			} else if mode == "open-cursor" {
				rows, err := w.Query(ctx, "SELECT 1")
				if err != nil {
					t.Fatal(err)
				}
				checkErr = w.RequireActiveUserStatus(ctx, owner, expected)
				rows.Close()
			} else {
				checkErr = w.RequireActiveUserStatus(ctx, owner, expected)
			}
			allow := mode == "exact" || mode == "aggregate-only" || mode == "other-epochs" || mode == "maximum" || mode == "retained-lock"
			if allow {
				if checkErr != nil || w.state.failed != nil {
					t.Fatal("current independent user authority denied", checkErr)
				}
				if mode == "retained-lock" {
					bounded, stop := context.WithTimeout(ctx, 30*time.Millisecond)
					_, err := pool.Raw().Exec(bounded, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
					stop()
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("owner lock did not fence lifecycle mutation", err)
					}
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if checkErr == nil || w.state.failed == nil || w.usable() == nil {
					t.Fatal("ignored denial left Work usable")
				}
				if mode == "lock-deadline" && !errors.Is(checkErr, context.DeadlineExceeded) {
					t.Fatal("owner lock deadline lost cancellation", checkErr)
				}
				if mode != "lock-deadline" && mode != "open-cursor" {
					var forbidden identity.ForbiddenError
					if !errors.As(checkErr, &forbidden) {
						t.Fatal("owner denial was not uniform", checkErr)
					}
				}
				if _, err := w.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES('ignored-user-status')`); err == nil {
					t.Fatal("poisoned transaction accepted later writes")
				}
				if err := tx.Rollback(ctx); err != nil && !(mode == "lock-deadline" && tx.Conn().IsClosed()) {
					t.Fatal(err)
				}
			}
			var count, credentials int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.otp_authority_effects WHERE id=$1),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$2 AND user_id=$3)`, id, string(b.TenantID), string(b.UserID)).Scan(&count, &credentials); err != nil || count != map[bool]int{false: 0, true: 1}[allow] || credentials != 0 {
				t.Fatal("authority check changed rollback or credential independence", err)
			}
		})
	}
}
