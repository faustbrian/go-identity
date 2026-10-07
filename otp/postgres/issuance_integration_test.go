//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Test-owned transactions exercise the actual storage writer. These tests do
// not establish native Send, primary admission or encrypted delivery composition.
func TestNativeChallengeIssuanceStorage(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	p := installIssuanceStorage(t, ctx, db)
	// The legacy explicit-column reader still reconstructs original issued
	// policy/custody after the opt-in schema extension.
	read, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := c.loadChallenge(ctx, sqlChallengeQuery(read), "otp_store", a, 3)
	if err != nil {
		rollbackIssuanceTest(read)
		t.Fatal("migration broke legacy custody reader", err)
	}
	snapshot, err := old.challenge.Bindings()
	if err != nil || snapshot.Version != 1 || snapshot.State != otp.ChallengeIssued {
		rollbackIssuanceTest(read)
		t.Fatal("migration changed legacy custody")
	}
	if err := read.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	unbound := pendingIssuance(t, ctx, db, 98)
	_, err = db.Exec(ctx, insertChallenge, "tenant", "legacy-later", unbound, makeTestFingerprint(98))
	var oldWriter *pgconn.PgError
	if !errors.As(err, &oldWriter) || oldWriter.Code != "23514" || oldWriter.Message != "OTP issuance family required" {
		t.Fatal("older unbound writer did not fail closed")
	}
	// Existing populated legacy challenges remain usable by their old profile;
	// unknown family membership must fail closed rather than guess a destination.
	b, _ := a.Bindings()
	cb, _ := b.Continuation.Bindings()
	profile := sendPolicy(t, 3)
	policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	issue := pendingIssuance(t, ctx, db, 90)
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	cb.Scope.AuthorizationBinding = [32]byte{}
	cb.Scope.ChallengeID = "new-challenge"
	continuation, err := otp.NewContinuation(cb.Scope, cb.Authorization, cb.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ = continuation.Bindings()
	scope, _ := continuation.DigestScope()
	code, _ := a.Code()
	digest, err := c.verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: continuation, Policy: policy, Digest: digest.Storage(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), State: otp.ChallengeIssued, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: identity.CommandID(base64.RawURLEncoding.EncodeToString(issue)), TenantID: "tenant", UserID: "user", OperationID: "identity.otp.send", RecordID: "new-challenge"}
	write := func() error {
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		defer rollbackIssuanceTest(tx)
		if err := p.initializeSendFamily(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", cb.Scope); err != nil {
			return err
		}
		family, err := p.loadSendFamily(ctx, sqlChallengeQuery(tx), "otp_store", cb.Scope)
		if err != nil {
			return err
		}
		var current time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&current); err != nil {
			return err
		}
		if err := p.persistIssuance(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), c, family, draft, binding, current); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := write(); err == nil {
		t.Fatal("unmapped live legacy challenge bypassed family policy")
	}
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='revoked',version=version+1,terminal_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	var count, used int
	var stored, family, fingerprint []byte
	if err := db.QueryRow(ctx, `SELECT code_digest,send_family_digest,issue_fingerprint,used_attempts FROM otp_store.challenges WHERE challenge_id='new-challenge'`).Scan(&stored, &family, &fingerprint, &used); err != nil || len(stored) != 32 || len(family) != 32 || used != 0 || !bytes.Equal(fingerprint, makeTestFingerprint(90)) {
		t.Fatal("issued custody missing", err)
	}
	if err := db.QueryRow(ctx, `SELECT cardinality(sent_at) FROM otp_store.send_families`).Scan(&count); err != nil || count != 1 {
		t.Fatal("send and challenge did not commit together", count, err)
	}
	// Exact recorded values are independently checked, including keyed complete
	// scope and original policy/time; plaintext and destination are not stored.
	var expires, issued time.Time
	var recordedScope []byte
	if err := db.QueryRow(ctx, `SELECT issued_at,expires_at,scope_digest FROM otp_store.challenges WHERE challenge_id='new-challenge'`).Scan(&issued, &expires, &recordedScope); err != nil || !issued.Equal(now) || !expires.Equal(now.Add(time.Minute)) {
		t.Fatal("issuance renewed time", err)
	}
	storedDigest := digest.Storage()
	expectedScope, err := c.verifier.ScopeDigest(scope, storedDigest.KeyVersion)
	if err != nil || string(recordedScope) != string(expectedScope.Value[:]) || string(stored) != string(storedDigest.Value[:]) {
		t.Fatal("stored digests lost exact scope")
	}
	for _, changed := range [][]byte{nil, make([]byte, 32)} {
		// This is otherwise a valid counted wrong-code transition, so the old
		// lifecycle guard cannot mask missing family immutability.
		_, err := db.Exec(ctx, `UPDATE otp_store.challenges SET send_family_digest=$1,version=version+1,
 used_attempts=used_attempts+1,failed_attempts=failed_attempts+1 WHERE challenge_id='new-challenge'`, changed)
		var rejected *pgconn.PgError
		if !errors.As(err, &rejected) || rejected.Code != "23514" {
			t.Fatal("migration permitted family rewrite")
		}
	}
}

func installIssuanceStorage(t *testing.T, ctx context.Context, db *pgx.Conn) lockoutProfile {
	t.Helper()
	for _, source := range []migrations.Source{
		LockoutMigrationSource{Schema: "otp_store", Version: 101},
		SendFamilyMigrationSource{Schema: "otp_store", Version: 102},
		IssuanceMigrationSource{Schema: "otp_store", Version: 103},
	} {
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
	return p
}

func pendingIssuance(t *testing.T, ctx context.Context, db *pgx.Conn, n byte) []byte {
	t.Helper()
	issue := otpCommand(t, ctx, db, "tenant", n)
	if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now)
 UPDATE identity.commands SET state='pending',generation=1,attempt=1,lease_owner=$1,
 lease_until=instant.now+interval '5 seconds',heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now
 FROM instant WHERE command_id=$1`, issue); err != nil {
		t.Fatal(err)
	}
	return issue
}

func rollbackIssuanceTest(tx pgx.Tx) {
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = tx.Rollback(ctx)
}
