//go:build integration

package postgres

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
	"github.com/jackc/pgx/v5"
)

func TestNativeIssuanceReplacementAndRollback(t *testing.T) {
	for _, mode := range []string{"replace", "retain", "retained-horizon", "expired-legacy", "rollback", "insert-failure", "reserved", "reserved-expired", "collision", "same-command", "expired", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer := otpDatabase(t)
			age := time.Duration(0)
			if mode == "expired-legacy" {
				age = time.Hour
			}
			codec, a, _, _ := nativeChallenge(t, ctx, db, age)
			p := installIssuanceStorage(t, ctx, db)
			if mode != "expired-legacy" {
				if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='revoked',version=version+1,terminal_at=clock_timestamp()`); err != nil {
					t.Fatal(err)
				}
			}
			var primary time.Time
			if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primary); err != nil {
				t.Fatal(err)
			}
			base, _ := a.Bindings()
			cb, _ := base.Continuation.Bindings()
			profileSpec, _ := sendPolicy(t, 3).Bindings()
			profileSpec.TTL = 10 * time.Minute
			profileSpec.Replacement = otp.ReplacePrevious
			if mode == "retain" || mode == "retained-horizon" {
				profileSpec.Replacement = otp.RetainPrevious
			}
			profile, _ := otp.NewCodeProfile(profileSpec)
			policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
			draft := func(id string, at time.Time) otp.Challenge {
				scope := cb.Scope
				scope.ChallengeID = id
				scope.AuthorizationBinding = [32]byte{}
				continuation, err := otp.NewContinuation(scope, cb.Authorization, cb.RememberPolicy)
				if err != nil {
					t.Fatal(err)
				}
				bound, _ := continuation.DigestScope()
				code, _ := a.Code()
				digest, err := codec.verifier.Digest(bound, code)
				if err != nil {
					t.Fatal(err)
				}
				c, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: continuation, Policy: policy, Digest: digest.Storage(), IssuedAt: at, ExpiresAt: at.Add(profileSpec.TTL), State: otp.ChallengeIssued, Version: 1})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			first := draft("first", primary.Add(-2*time.Minute))
			firstCommand := pendingIssuance(t, ctx, db, 90)
			secondCommand := pendingIssuance(t, ctx, db, 91)
			thirdCommand := pendingIssuance(t, ctx, db, 92)
			write := func(conn *pgx.Conn, c otp.Challenge, command []byte, at time.Time, rollback bool, fail bool) error {
				tx, err := conn.Begin(ctx)
				if err != nil {
					return err
				}
				defer rollbackIssuanceTest(tx)
				s, _ := c.Bindings()
				scope, _ := s.Continuation.Bindings()
				if err := p.initializeSendFamily(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope.Scope); err != nil {
					return err
				}
				family, err := p.loadSendFamily(ctx, sqlChallengeQuery(tx), "otp_store", scope.Scope)
				if err != nil {
					return err
				}
				if at.IsZero() {
					if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
						return err
					}
				}
				binding := storageIssuanceBinding(t, command, scope.Scope.ChallengeID)
				if fail {
					// Fail the actual INSERT after family append and predecessor
					// revocation, not an earlier mocked callback.
					if _, err := tx.Exec(ctx, `ALTER TABLE otp_store.challenges ADD CONSTRAINT issuance_test_reject CHECK(challenge_id<>'second')`); err != nil {
						return err
					}
				}
				if err := p.persistIssuance(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), codec, family, c, binding, at); err != nil {
					return err
				}
				if rollback {
					return tx.Rollback(ctx)
				}
				return tx.Commit(ctx)
			}
			if mode == "retained-horizon" {
				// Build legal historical hourly windows without sleeping or
				// bypassing the monotonicity guard. Only their last instant remains.
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackIssuanceTest(tx)
				initial, _ := first.Bindings()
				scope, _ := initial.Continuation.Bindings()
				if err := p.initializeSendFamily(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope.Scope); err != nil {
					t.Fatal(err)
				}
				for n := 11; n > 0; n-- {
					row, err := p.loadSendFamily(ctx, sqlChallengeQuery(tx), "otp_store", scope.Scope)
					if err != nil {
						t.Fatal(err)
					}
					if err := persistSendWindow(ctx, sqlChallengeExec(tx), row, profile, primary.Add(-time.Duration(n)*2*time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := write(db, first, firstCommand, primary.Add(-2*time.Minute), false, false); err != nil {
				t.Fatal(err)
			}
			seedExpired := func(id string, n byte, at time.Time) {
				// A restored historical challenge is a valid issued snapshot,
				// but its state may not yet have been terminalized by cleanup.
				old := draft(id, at)
				s, _ := old.Bindings()
				scope, _ := s.Continuation.DigestScope()
				digest, err := codec.verifier.ScopeDigest(scope, s.Digest.KeyVersion)
				if err != nil {
					t.Fatal(err)
				}
				command := pendingIssuance(t, ctx, db, n)
				if _, err := db.Exec(ctx, `INSERT INTO otp_store.challenges(
 tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,
 digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,
 maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version,send_family_digest)
 SELECT e.tenant_id,$1::text,e.subject_id,e.purpose,$2::bytea,e.issue_command_purpose,j.fingerprint,
 e.digest_key_version,$3::bytea,$4::bytea,e.policy_version,e.scope_generation,e.alphabet,e.code_length,e.ttl_us,e.resend_interval_us,
 e.maximum_sends,e.attempt_limit,e.replacement,e.checks_enabled,e.check_limit,e.lockout_us,$5::timestamptz,$6::timestamptz,'issued',1,e.send_family_digest
 FROM otp_store.challenges e JOIN identity.identity_command_id_claims j ON j.command_id=$2
 WHERE e.challenge_id='first'`, id, command, s.Digest.Value[:], digest.Value[:], s.IssuedAt, s.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "retained-horizon" {
				for n := 1; n <= 11; n++ {
					seedExpired("past-"+string(rune('a'+n)), byte(110+n), primary.Add(-time.Duration(n)*2*time.Hour))
				}
			}
			if mode == "reserved-expired" {
				seedExpired("expired-reserved", 110, primary.Add(-2*time.Hour))
				consumer := pendingIssuance(t, ctx, db, 99)
				if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='reserved',version=2,used_attempts=1,
 consumer_command_id=$1,consumer_purpose='identity.otp.send',consumer_fingerprint=$2,consumer_generation=1,
 consumer_attempt_id='AgICAgICAgICAgICAgICAg',consumer_attempt_fingerprint=$2,consumer_issuer_version=7,reserved_at=issued_at+interval '5 seconds'
 WHERE challenge_id='expired-reserved'`, consumer, makeTestFingerprint(99)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "reserved" {
				consumer := pendingIssuance(t, ctx, db, 99)
				if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='reserved',version=2,used_attempts=1,
 consumer_command_id=$1,consumer_purpose='identity.otp.send',consumer_fingerprint=$2,consumer_generation=1,
 consumer_attempt_id='AgICAgICAgICAgICAgICAg',consumer_attempt_fingerprint=$2,consumer_issuer_version=7,reserved_at=$3
 WHERE challenge_id='first'`, consumer, makeTestFingerprint(99), primary); err != nil {
					t.Fatal(err)
				}
			}
			second := draft("second", primary)
			if mode == "same-command" {
				secondCommand = firstCommand
			}
			if mode == "collision" {
				second = draft("first", primary)
			}
			if mode == "expired" {
				second = draft("second", primary.Add(-11*time.Minute))
			}
			denied := mode == "reserved" || mode == "reserved-expired" || mode == "collision" || mode == "same-command" || mode == "expired" || mode == "insert-failure"
			if mode == "concurrent" {
				start := make(chan struct{})
				results := make(chan error, 2)
				var wg sync.WaitGroup
				for n, conn := range []*pgx.Conn{db, peer} {
					c, command := second, secondCommand
					if n == 1 {
						c, command = draft("third", primary), thirdCommand
					}
					wg.Add(1)
					go func(conn *pgx.Conn, c otp.Challenge, command []byte) {
						defer wg.Done()
						<-start
						results <- write(conn, c, command, time.Time{}, false, false)
					}(conn, c, command)
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
					t.Fatal("resend race admitted multiple challenges", wins)
				}
			} else {
				err := write(db, second, secondCommand, time.Time{}, mode == "rollback", mode == "insert-failure")
				if denied && err == nil || !denied && err != nil {
					t.Fatal("unexpected issue outcome", err)
				}
			}
			var state, version string
			var issued, expires time.Time
			if err := db.QueryRow(ctx, `SELECT state,version::text,issued_at,expires_at FROM otp_store.challenges WHERE challenge_id='first'`).Scan(&state, &version, &issued, &expires); err != nil {
				t.Fatal(err)
			}
			wantState, wantVersion := "revoked", "2"
			if mode == "retain" || mode == "retained-horizon" || mode == "rollback" || denied {
				wantState, wantVersion = "issued", "1"
			}
			if mode == "reserved" {
				wantState, wantVersion = "reserved", "2"
			}
			if state != wantState || version != wantVersion || !issued.Equal(primary.Add(-2*time.Minute)) || !expires.Equal(primary.Add(8*time.Minute)) {
				t.Fatal("predecessor custody escaped atomic policy", state, version)
			}
			var sends, chall int
			if err := db.QueryRow(ctx, `SELECT cardinality(sent_at) FROM otp_store.send_families`).Scan(&sends); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges WHERE send_family_digest IS NOT NULL`).Scan(&chall); err != nil {
				t.Fatal(err)
			}
			want := 2
			if mode == "rollback" || denied {
				want = 1
			}
			wantChallenges := want
			if mode == "retained-horizon" {
				wantChallenges += 11
			}
			if mode == "reserved-expired" {
				wantChallenges++
			}
			if sends != want || chall != wantChallenges {
				t.Fatal("partial issuance or double charge", sends, chall, want)
			}
			if mode == "retained-horizon" {
				var untouched int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges WHERE challenge_id LIKE 'past-%' AND state='issued' AND version=1 AND expires_at<clock_timestamp()`).Scan(&untouched); err != nil || untouched != 11 {
					t.Fatal("expired retained custody was rewritten", untouched, err)
				}
			}
			if mode == "reserved-expired" {
				var unchanged bool
				if err := db.QueryRow(ctx, `SELECT state='reserved' AND version=2 AND consumer_generation=1 AND terminal_at IS NULL FROM otp_store.challenges WHERE challenge_id='expired-reserved'`).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("expiry released unresolved reservation", err)
				}
			}
		})
	}
}

func makeTestFingerprint(n byte) []byte {
	p := make([]byte, 32)
	for i := range p {
		p[i] = n
	}
	return p
}
