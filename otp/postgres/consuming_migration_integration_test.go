//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Installing the extension over historical rows must conserve existing custody;
// nullable legacy rows do not gain an invented original submission projection.
func TestConsumingMigrationPreservesPopulatedState(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(map[bool]string{false: "issued", true: "legacy-reserved"}[reserved], func(t *testing.T) {
			ctx, db, _ := otpDatabase(t)
			codec, attempt, _, _ := nativeChallenge(t, ctx, db)
			binding := nativeConsumer(t, ctx, db, codec, attempt, 1)
			if reserved {
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				reserveNative(t, ctx, tx, codec, attempt, binding)
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			var before, after []byte
			if err := db.QueryRow(ctx, `SELECT to_jsonb(c)::text FROM otp_store.challenges c`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			history, err := (ConsumingMigrationSource{Schema: "otp_store", Version: 102}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
				t.Fatal("populated migration", err)
			}
			var missing bool
			if err := db.QueryRow(ctx, `SELECT (to_jsonb(c)-'consumer_envelope'-'consumer_owner'-'consumer_record_requirement'-'consumer_subject_requirement')::text, consumer_envelope IS NULL AND consumer_owner IS NULL AND consumer_record_requirement IS NULL AND consumer_subject_requirement IS NULL FROM otp_store.challenges c`).Scan(&after, &missing); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !missing {
				t.Fatal("migration rewrote historical state or invented original custody")
			}
			// Recovery's native restoration boundary cannot interpret a nullable
			// historical projection as evidence, even with a valid command binding.
			participant := &Contributor{schema: "otp_store", codec: codec}
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, _, restoreErr := participant.retainedOriginal(ctx, sqlChallengeQuery(tx), binding)
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if restoreErr == nil {
				t.Fatal("legacy missing original custody acquired recovery authority")
			}
		})
	}
}

func assertOriginalCustodyImmutable(t *testing.T, ctx context.Context, db *pgx.Conn) {
	t.Helper()
	for _, sql := range []string{`UPDATE otp_store.challenges SET consumer_envelope=NULL,consumer_owner=NULL,consumer_record_requirement=NULL,consumer_subject_requirement=NULL`, `UPDATE otp_store.challenges SET consumer_envelope=decode('01','hex')`} {
		_, err := db.Exec(ctx, sql)
		var constraint interface{ SQLState() string }
		if !errors.As(err, &constraint) || constraint.SQLState() != "23514" {
			t.Fatal("original custody mutation did not fail its invariant", err)
		}
	}
}
