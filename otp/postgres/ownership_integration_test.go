//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// These tests establish native SQL effects, not coordinator authorization or
// noncommit proof. Only production sealed phase handles may dispatch them.
func nativeConsumer(t *testing.T, ctx context.Context, db *pgx.Conn, c *AttemptCodec, a otp.AttemptCommand, generation uint64) identitypostgres.OTPReservationBinding {
	t.Helper()
	r, err := c.issuers[7].SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.recordPlan(r, 3)
	if err != nil {
		t.Fatal(err)
	}
	b := identitypostgres.OTPReservationBinding{Command: r.Binding, Plan: plan, Generation: generation, Fingerprint: [32]byte{88}}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.Command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, string(b.Command.TenantID), b.Command.OperationID, b.Fingerprint[:], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, string(b.Command.TenantID), b.Command.OperationID); err != nil {
		t.Fatal(err)
	}
	return b
}

func reserveNative(t *testing.T, ctx context.Context, tx pgx.Tx, c *AttemptCodec, a otp.AttemptCommand, b identitypostgres.OTPReservationBinding) {
	t.Helper()
	row, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", a, 3)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	d, err := c.verifier.EvaluateAttempt(row.challenge, a, now)
	if err != nil || d.Outcome != otp.AttemptReserved {
		t.Fatal("correct consuming proposal unavailable", err)
	}
	if err := persistReservation(ctx, sqlChallengeExec(tx), row, d, b, now); err != nil {
		t.Fatal(err)
	}
}

func TestNativeReservationAndAtomicFinalization(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	b := nativeConsumer(t, ctx, db, c, a, 1)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	reserveNative(t, ctx, tx, c, a, b)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	var used int
	if err := db.QueryRow(ctx, `SELECT state,used_attempts FROM otp_store.challenges`).Scan(&state, &used); err != nil || state != "issued" || used != 0 {
		t.Fatal("reserve rollback spent code", err)
	}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	reserveNative(t, ctx, tx, c, a, b)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE TABLE public.otp_domain_effect(id integer PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{false, true} {
		tx, err = db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		owned, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", b, 1)
		if err != nil {
			t.Fatal(err)
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.otp_domain_effect VALUES(1)`); err != nil {
			t.Fatal(err)
		}
		if err := terminalReservation(ctx, sqlChallengeExec(tx), owned, b, reservationFinalized, now); err != nil {
			t.Fatal(err)
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `SELECT state,used_attempts FROM otp_store.challenges`).Scan(&state, &used); err != nil {
			t.Fatal(err)
		}
		var effects int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM public.otp_domain_effect`).Scan(&effects); err != nil {
			t.Fatal(err)
		}
		if commit && (state != "finalized" || effects != 1 || used != 1) || !commit && (state != "reserved" || effects != 0 || used != 1) {
			t.Fatal("terminal and domain effects split")
		}
	}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", b, 1); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("terminal code regained ownership")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var owner, attempt []byte
	var attemptID string
	if err := db.QueryRow(ctx, `SELECT consumer_fingerprint,consumer_attempt_fingerprint,consumer_attempt_id FROM otp_store.challenges`).Scan(&owner, &attempt, &attemptID); err != nil || !bytes.Equal(owner, b.Fingerprint[:]) || !bytes.Equal(attempt, b.Plan.AttemptFingerprint[:]) || attemptID != b.Plan.AttemptID {
		t.Fatal("original custody lost", err)
	}
}

func TestNativeReservationTakeoverPreservesOriginalCustody(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	b := nativeConsumer(t, ctx, db, c, a, ^uint64(0)-1)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	reserveNative(t, ctx, tx, c, a, b)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := db.QueryRow(ctx, `SELECT reserved_at FROM otp_store.challenges`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	next := b
	next.PreviousGeneration, next.Generation = b.Generation, b.Generation+1
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	row, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", next, b.Generation)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if err := rebindReservation(ctx, sqlChallengeExec(tx), row, next, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var used int
	var generation, version string
	if err := db.QueryRow(ctx, `SELECT reserved_at,used_attempts,consumer_generation::text,version::text FROM otp_store.challenges`).Scan(&after, &used, &generation, &version); err != nil || !before.Equal(after) || used != 1 || generation != "18446744073709551615" || version != "3" {
		t.Fatal("takeover renewed or charged original ownership", err)
	}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", b, b.Generation); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("stale generation retained ownership", err)
	}
	next.PreviousGeneration = 0
	row, err = loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", next, next.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if err := terminalReservation(ctx, sqlChallengeExec(tx), row, next, reservationFinalized, now); err != nil {
		t.Fatal("full-width generation could not finalize", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeReservationReleaseAndOwnershipIsolation(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "recovery"}[recover], func(t *testing.T) {
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
			tx, err = db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			changes := []func(*identitypostgres.OTPReservationBinding){
				func(v *identitypostgres.OTPReservationBinding) { v.Command.TenantID = "foreign" },
				func(v *identitypostgres.OTPReservationBinding) { v.Command.UserID = "foreign" },
				func(v *identitypostgres.OTPReservationBinding) { v.Command.OperationID = "identity.otp.foreign" },
				func(v *identitypostgres.OTPReservationBinding) { v.Fingerprint[0]++ },
				func(v *identitypostgres.OTPReservationBinding) { v.Plan.AttemptFingerprint[0]++ },
				func(v *identitypostgres.OTPReservationBinding) { v.Plan.ScopeDigest[0]++ },
				func(v *identitypostgres.OTPReservationBinding) { v.Plan.FingerprintKeyVersion++ },
				func(v *identitypostgres.OTPReservationBinding) { v.Plan.DigestKeyVersion++ },
			}
			for i, change := range changes {
				foreign := b
				change(&foreign)
				if _, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", foreign, 1); !errors.Is(err, ErrInvalidCommand) {
					t.Fatalf("ownership substitution %d selected reservation: %v", i, err)
				}
			}
			release := b
			release.PreviousGeneration = 1
			if recover {
				release.Generation = 2
			}
			row, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", release, 1)
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			skipped := release
			skipped.Generation = 3
			badRow := row
			badRow.binding = skipped
			if err := terminalReservation(ctx, sqlChallengeExec(tx), badRow, skipped, reservationReleased, now); !errors.Is(err, ErrInvalidCommand) {
				t.Fatal("skipped release generation accepted", err)
			}
			if err := terminalReservation(ctx, sqlChallengeExec(tx), row, release, reservationReleased, now); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var state, generation string
			var used int
			if err := db.QueryRow(ctx, `SELECT state,consumer_generation::text,used_attempts FROM otp_store.challenges`).Scan(&state, &generation, &used); err != nil || state != "released" || used != 1 || (!recover && generation != "1") || (recover && generation != "2") {
				t.Fatal("release renewed code or changed spent allowance", err)
			}
			tx, err = db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", release, release.Generation); !errors.Is(err, ErrInvalidCommand) {
				t.Fatal("released challenge regained ownership", err)
			}
		})
	}
}

func TestNativeReservationExpiryNeverAuthorizesRelease(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db, 59*time.Second)
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
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	row, err := loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", b, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the original still-positive sampled time after real database expiry.
	// The persistence fence, not a caller clock, must reject the late commit.
	var sampled time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&sampled); err != nil {
		t.Fatal(err)
	}
	if !sampled.Before(row.expiresAt) {
		t.Fatal("fixture expired before observation")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	if err := terminalReservation(ctx, sqlChallengeExec(tx), row, b, reservationFinalized, sampled); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("stale sampled validity authorized finalization", err)
	}
	next := b
	next.PreviousGeneration, next.Generation = 1, 2
	rebound := row
	rebound.binding = next
	if err := rebindReservation(ctx, sqlChallengeExec(tx), rebound, next, sampled); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("stale sampled validity authorized takeover", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM otp_store.challenges`).Scan(&state); err != nil || state != "reserved" {
		t.Fatal("expiry inferred noncommit", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// This only exercises the persistence projection of an explicitly supplied
	// release phase. The test does not establish the coordinator's noncommit proof.
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	release := b
	release.PreviousGeneration = 1
	row, err = loadReservation(ctx, sqlChallengeQuery(tx), "otp_store", release, 1)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if err := terminalReservation(ctx, sqlChallengeExec(tx), row, release, reservationReleased, now); err != nil {
		t.Fatal("expired original custody could not project proven release", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
