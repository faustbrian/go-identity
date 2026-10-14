//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
)

func TestNativeReservationPreservesTerminalVersionCapacity(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	if _, err := db.Exec(ctx, `ALTER TABLE otp_store.challenges DISABLE TRIGGER otp_challenge_guard; UPDATE otp_store.challenges SET version=18446744073709551614; ALTER TABLE otp_store.challenges ENABLE TRIGGER otp_challenge_guard`); err != nil {
		t.Fatal(err)
	}
	r, _ := c.issuers[7].SealForCommand(a)
	code, _ := a.Code()
	submission, err := c.issuers[7].PrepareForCommand(ctx, r.Binding, r.Operation, r.Attempt.Continuation, otp.AttemptModeConsume, ^uint64(0)-1, code)
	if err != nil {
		t.Fatal(err)
	}
	b := nativeConsumer(t, ctx, db, c, submission, 1)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	row, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	d, err := c.verifier.EvaluateAttempt(row.challenge, submission, now)
	if err != nil || d.Outcome != otp.AttemptReserved {
		t.Fatal(err)
	}
	if err := persistReservation(ctx, sqlChallengeExec(tx), row, d, b, now); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("reservation exhausted version needed for terminal CAS")
	}
}

func TestNativeRebindPreservesTerminalVersionCapacity(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	b := nativeConsumer(t, ctx, db, c, a, 1)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	reserveNative(t, ctx, tx, c, a, b)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `ALTER TABLE otp_store.challenges DISABLE TRIGGER otp_challenge_guard; UPDATE otp_store.challenges SET version=18446744073709551614; ALTER TABLE otp_store.challenges ENABLE TRIGGER otp_challenge_guard`); err != nil {
		t.Fatal(err)
	}
	b.PreviousGeneration, b.Generation = 1, 2
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	row, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", b, 1, string(b.Command.UserID))
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if err := rebindReservation(ctx, sqlChallengeExec(tx), row, b, now); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("rebind exhausted version needed for terminal CAS")
	}
}
