//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/otp"
	"github.com/jackc/pgx/v5"
)

// Native helper tests deliberately stop short of command replay/current flow
// authority. The transaction here is test-owned, never a public store escape.
func sqlChallengeQuery(tx pgx.Tx) challengeQuery {
	return func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return tx.Query(ctx, sql, args...)
	}
}
func sqlChallengeExec(tx pgx.Tx) challengeExec {
	return func(ctx context.Context, sql string, args ...any) (int64, error) {
		tag, err := tx.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}
}

func nativeChallenge(t *testing.T, ctx context.Context, db *pgx.Conn, age ...time.Duration) (*AttemptCodec, otp.AttemptCommand, time.Time, []byte) {
	t.Helper()
	h, _ := (MigrationSource{Schema: "otp_store", Version: 100}).Load(ctx)
	if _, err := db.Exec(ctx, h[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1'),(4,'hmac-sha256-v1')`); err != nil {
		t.Fatal(err)
	}
	c, _ := NewAttemptCodec(codecConfig())
	original, spec := mappedAttempt(t, otp.PurposeEmailVerification, false)
	b, _ := original.Bindings()
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := original.Code()
	a, err := issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, b.Continuation, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := b.Continuation.DigestScope()
	v, _ := otp.NewVerifier(3, codecConfig().CodeKeys)
	digest, _ := v.Digest(scope, code)
	stored := digest.Storage()
	sd, _ := v.ScopeDigest(scope, 3)
	issue := otpCommand(t, ctx, db, "tenant", 77)
	if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=$2,lease_until=instant.now,heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now,result_version=1,terminal_class='committed',result=$2,terminal_at=instant.now FROM instant WHERE command_id=$1`, issue, bytes.Repeat([]byte{77}, 16)); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if len(age) != 0 {
		now = now.Add(-age[0])
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.challenges(tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version) VALUES('tenant','challenge','user','email-verification',$1,'identity.otp.send',$2,3,$3,$4,11,12,'0123456789',6,60000000,30000000,3,3,'retain',true,2,60000000,$5::timestamptz,$5::timestamptz+interval '60 seconds','issued',1)`, issue, bytes.Repeat([]byte{77}, 32), stored.Value[:], sd.Value[:], now); err != nil {
		t.Fatal(err)
	}
	return c, a, now, issue
}

func TestNativeChallengeScopeAndPolicy(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, now, issue := nativeChallenge(t, ctx, db)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	locked, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", a, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := locked.challenge.Bindings()
	p, check, e := b.Policy.Bindings()
	if e != nil || p.Replacement != otp.RetainPrevious || p.Attempts != 3 || p.TTL != time.Minute || !check.Enabled || check.MaximumChecks != 2 || check.LockoutAfter != time.Minute || b.Version != 1 || !b.IssuedAt.Equal(now) || b.ExpiresAt.Sub(now) != time.Minute || b.Digest.KeyVersion != 3 {
		t.Fatal("frozen primary policy changed")
	}
	if _, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", a, 4); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("retained alternate version selected original row")
	}
	original, _ := a.Bindings()
	changed, _ := original.Continuation.Bindings()
	changed.Scope.AuthorizationBinding = [32]byte{}
	changed.Scope.Destination, _ = otp.NewDestinationInput("foreign@example.test")
	foreignFlow, err := otp.NewContinuation(changed.Scope, changed.Authorization, changed.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := c.issuers[7].SealForCommand(a)
	code, _ := a.Code()
	foreign, err := c.issuers[7].PrepareForCommand(ctx, sealed.Binding, sealed.Operation, foreignFlow, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", foreign, 3); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("foreign destination selected counter authority")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE identity.commands SET state='pending',result_version=NULL,terminal_class=NULL,result=NULL,terminal_at=NULL WHERE command_id=$1`, issue); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", a, 3); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("uncommitted issuance became eligible")
	}
}

func TestNativeFullWidthSnapshotAndCAS(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	// Simulate a valid restored full-width version in this disposable database;
	// only fixture installation bypasses the normal incremental writer.
	if _, err := db.Exec(ctx, `ALTER TABLE otp_store.challenges DISABLE TRIGGER otp_challenge_guard; UPDATE otp_store.challenges SET version=18446744073709551614; ALTER TABLE otp_store.challenges ENABLE TRIGGER otp_challenge_guard`); err != nil {
		t.Fatal(err)
	}
	r, _ := c.issuers[7].SealForCommand(a)
	wrong, _ := auth.NewOneTimeCode("654321")
	submission, err := c.issuers[7].PrepareForCommand(ctx, r.Binding, r.Operation, r.Attempt.Continuation, otp.AttemptModeConsume, ^uint64(0)-1, wrong)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	locked, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	d, err := c.verifier.EvaluateAttempt(locked.challenge, submission, now)
	if err != nil || d.Version != ^uint64(0) {
		t.Fatal("full width evaluation truncated", err)
	}
	if err := persistCount(ctx, sqlChallengeExec(tx), locked, d, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRow(ctx, `SELECT version::text FROM otp_store.challenges`).Scan(&version); err != nil || version != "18446744073709551615" {
		t.Fatal("full width CAS truncated", err)
	}
}

func TestNativeCountedChallengeRollbackAndBudget(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	b, _ := a.Bindings()
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	r, err := issuer.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := auth.NewOneTimeCode("654321")
	for n := uint64(1); n <= 3; n++ {
		// A fresh logical submission; this test does not impersonate journal replay.
		submission, err := issuer.PrepareForCommand(ctx, r.Binding, r.Operation, b.Continuation, otp.AttemptModeConsume, n, wrong)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		})
		locked, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
		if err != nil {
			t.Fatal(err)
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		decision, err := c.verifier.EvaluateAttempt(locked.challenge, submission, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := persistCount(ctx, sqlChallengeExec(tx), locked, decision, now); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT used_attempts FROM otp_store.challenges`).Scan(&count); err != nil || count != 0 {
				t.Fatal("rollback retained a charge", err)
			}
			tx, err = db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			locked, err = c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistCount(ctx, sqlChallengeExec(tx), locked, decision, now); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var used, failed int
	var state, version string
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,state,version::text FROM otp_store.challenges`).Scan(&used, &failed, &state, &version); err != nil || used != 3 || failed != 3 || state != "exhausted" || version != "4" {
		t.Fatal("shared budget not enforced", err)
	}
}

func TestNativeCountedChecksAndExclusiveExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "checks", true: "expired"}[expired], func(t *testing.T) {
			ctx, db, _ := otpDatabase(t)
			age := time.Duration(0)
			if expired {
				age = 2 * time.Minute
			}
			c, a, _, _ := nativeChallenge(t, ctx, db, age)
			r, _ := c.issuers[7].SealForCommand(a)
			code, _ := a.Code()
			for n := uint64(1); n <= 3; n++ {
				if expired && n > 1 {
					break
				}
				// First wrong consume, then correct bounded non-consuming checks.
				mode := otp.AttemptModeCheck
				input := code
				if n == 1 && !expired {
					mode = otp.AttemptModeConsume
					input, _ = auth.NewOneTimeCode("654321")
				}
				submission, err := c.issuers[7].PrepareForCommand(ctx, r.Binding, r.Operation, r.Attempt.Continuation, mode, n, input)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				locked, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
				if err != nil {
					t.Fatal(err)
				}
				var now time.Time
				if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				d, err := c.verifier.EvaluateAttempt(locked.challenge, submission, now)
				if err != nil {
					t.Fatal(err)
				}
				if n > 1 && !expired && (d.Outcome != otp.AttemptChecked || d.LockoutAfter != 0) {
					t.Fatal("correct check acquired consumption or lockout")
				}
				if err := persistCount(ctx, sqlChallengeExec(tx), locked, d, now); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			var used, failed, checks int
			var state string
			if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,checks,state FROM otp_store.challenges`).Scan(&used, &failed, &checks, &state); err != nil {
				t.Fatal(err)
			}
			if expired {
				if used != 0 || failed != 0 || checks != 0 || state != "expired" {
					t.Fatal("expiry charged allowance")
				}
			} else if used != 3 || failed != 1 || checks != 2 || state != "exhausted" {
				t.Fatal("checks bypassed shared comparison cap")
			}
		})
	}
}

func TestNativeChallengeConcurrentVersionFence(t *testing.T) {
	ctx, db, peer := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	r, _ := c.issuers[7].SealForCommand(a)
	wrong, _ := auth.NewOneTimeCode("654321")
	submission, err := c.issuers[7].PrepareForCommand(ctx, r.Binding, r.Operation, r.Attempt.Continuation, otp.AttemptModeConsume, 1, wrong)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	locked, err := c.loadChallenge(ctx, sqlChallengeQuery(tx), "otp_store", submission, 3)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	started := make(chan struct{})
	done := make(chan struct{})
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer func() {
		stopWorker()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
		<-done
	}()
	go func() {
		defer close(done)
		other, err := peer.Begin(workerCtx)
		if err != nil {
			close(started)
			result <- err
			return
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = other.Rollback(cleanup)
		}()
		close(started)
		current, err := c.loadChallenge(workerCtx, sqlChallengeQuery(other), "otp_store", submission, 3)
		if err != nil {
			result <- err
			return
		}
		var now time.Time
		if err := other.QueryRow(workerCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			result <- err
			return
		}
		d, err := c.verifier.EvaluateAttempt(current.challenge, submission, now)
		if err != nil {
			result <- err
			return
		}
		if d.Outcome != otp.AttemptConflict {
			result <- errors.New("stale contender received allowance")
			return
		}
		if err := persistCount(workerCtx, sqlChallengeExec(other), current, d, now); !errors.Is(err, ErrInvalidCommand) {
			result <- errors.New("stale contender wrote a charge")
			return
		}
		result <- nil
	}()
	<-started
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	d, err := c.verifier.EvaluateAttempt(locked.challenge, submission, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistCount(ctx, sqlChallengeExec(tx), locked, d, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("contender did not terminate")
	}
	var used int
	if err := db.QueryRow(ctx, `SELECT used_attempts FROM otp_store.challenges`).Scan(&used); err != nil || used != 1 {
		t.Fatal("concurrent stale submission charged twice", err)
	}
}
