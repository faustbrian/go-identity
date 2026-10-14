//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// These storage tests use test-owned transactions. Native Send/current-flow,
// challenge replacement and encrypted delivery composition remain separate work.
func TestNativeSendWindowStorage(t *testing.T) {
	for _, mode := range []string{"persist", "guard-live-prefix", "hour-prune", "rollback", "concurrent", "key-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer := otpDatabase(t)
			_, a, _, _ := nativeChallenge(t, ctx, db)
			for _, source := range []interface {
				Load(context.Context) ([]migrations.Migration, error)
			}{LockoutMigrationSource{Schema: "otp_store", Version: 101}, SendFamilyMigrationSource{Schema: "otp_store", Version: 102}} {
				ms, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(ctx, ms[0].UpSQL()); err != nil {
					t.Fatal(err)
				}
			}
			p, _ := newLockoutProfile([32]byte{91})
			key := p.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, key[:]); err != nil {
				t.Fatal(err)
			}
			ab, _ := a.Bindings()
			cb, _ := ab.Continuation.Bindings()
			scope := cb.Scope
			initialize := func(conn *pgx.Conn, scope otp.DigestScopeSpec) error {
				tx, err := conn.Begin(ctx)
				if err != nil {
					return err
				}
				defer tx.Rollback(context.Background())
				if err := p.initializeSendFamily(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
					return err
				}
				return tx.Commit(ctx)
			}
			if err := initialize(db, scope); err != nil {
				t.Fatal(err)
			}
			policy := sendPolicy(t, 2)
			if mode == "key-mismatch" {
				wrong, _ := newLockoutProfile([32]byte{92})
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if err := wrong.initializeSendFamily(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err == nil {
					t.Fatal("changed key refilled allowance")
				}
				return
			}
			attempt := func(conn *pgx.Conn, rollback bool) error {
				tx, err := conn.Begin(ctx)
				if err != nil {
					return err
				}
				defer tx.Rollback(context.Background())
				row, err := p.loadSendFamily(ctx, sqlChallengeQuery(tx), "otp_store", scope)
				if err != nil {
					return err
				}
				var now time.Time
				if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					return err
				}
				if mode == "guard-live-prefix" && row.version == 1 {
					// Seed historical primary state without sleeping or bypassing
					// the installed monotonicity guard. Later writes use current time.
					now = now.Add(-2 * time.Minute)
				}
				if mode == "hour-prune" && row.version == 1 {
					now = now.Add(-65 * time.Minute)
				}
				if err := persistSendWindow(ctx, sqlChallengeExec(tx), row, policy, now); err != nil {
					return err
				}
				if rollback {
					return tx.Rollback(ctx)
				}
				return tx.Commit(ctx)
			}
			if mode == "concurrent" {
				start := make(chan struct{})
				results := make(chan error, 2)
				var wg sync.WaitGroup
				for _, conn := range []*pgx.Conn{db, peer} {
					wg.Add(1)
					go func(conn *pgx.Conn) { defer wg.Done(); <-start; results <- attempt(conn, false) }(conn)
				}
				close(start)
				wg.Wait()
				close(results)
				wins := 0
				for err := range results {
					if err == nil {
						wins++
					} else if !errors.Is(err, ErrInvalidCommand) {
						t.Fatal(err)
					}
				}
				if wins != 1 {
					t.Fatal("concurrent sends exceeded cooldown", wins)
				}
			} else if err := attempt(db, mode == "rollback"); err != nil {
				t.Fatal(err)
			}
			// Recreating a flow/challenge or policy cannot recreate the family row.
			scope.ChallengeID = "successor"
			scope.PolicyVersion++
			scope.Generation++
			scope.TargetID = "other"
			scope.AuthorizationBinding = [32]byte{4}
			if err := initialize(db, scope); err != nil {
				t.Fatal(err)
			}
			var count, histories int
			var version string
			if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.send_families`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT cardinality(sent_at),version::text FROM otp_store.send_families`).Scan(&histories, &version); err != nil {
				t.Fatal(err)
			}
			want, wantVersion := 1, "2"
			if mode == "rollback" {
				want, wantVersion = 0, "1"
			}
			if count != 1 || histories != want || version != wantVersion {
				t.Fatal("send state escaped transaction or reset", count, histories, version)
			}
			if mode == "hour-prune" {
				if err := attempt(db, false); err != nil {
					t.Fatal("expired window could not advance", err)
				}
				var recent bool
				if err := db.QueryRow(ctx, `SELECT cardinality(sent_at),version::text,sent_at[1]>clock_timestamp()-interval '1 minute' FROM otp_store.send_families`).Scan(&histories, &version, &recent); err != nil || histories != 1 || version != "3" || !recent {
					t.Fatal("rolling history not pruned", histories, version, recent, err)
				}
			}
			if mode == "persist" || mode == "guard-live-prefix" {
				for _, sql := range []string{
					`DELETE FROM otp_store.send_families`,
					`UPDATE otp_store.send_families SET sent_at=ARRAY[]::timestamptz[],version=3`,
					`UPDATE otp_store.send_families SET sent_at=ARRAY[clock_timestamp()],version=3`,
					`UPDATE otp_store.send_families SET sent_at=sent_at||ARRAY[NULL::timestamptz],version=3`,
					`UPDATE otp_store.send_families SET scope_digest=decode(repeat('01',32),'hex'),version=3`,
					`UPDATE otp_store.send_families SET sent_at=sent_at||ARRAY[clock_timestamp()+interval '1 hour'],version=3`,
				} {
					if _, err := db.Exec(ctx, sql); err == nil {
						t.Fatal("family guard allowed allowance reset")
					}
				}
				if err := db.QueryRow(ctx, `SELECT cardinality(sent_at),version::text FROM otp_store.send_families`).Scan(&histories, &version); err != nil || histories != 1 || version != "2" {
					t.Fatal("guard rejection changed state", histories, version, err)
				}
				if mode == "guard-live-prefix" {
					if err := attempt(db, false); err != nil {
						t.Fatal("valid live-prefix append denied", err)
					}
					if err := db.QueryRow(ctx, `SELECT cardinality(sent_at),version::text FROM otp_store.send_families`).Scan(&histories, &version); err != nil || histories != 2 || version != "3" {
						t.Fatal("live prefix was lost", histories, version, err)
					}
				}
			}
		})
	}
}
