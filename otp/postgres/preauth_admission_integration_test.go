//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

type admissionTestTx struct{ pgx.Tx }

func (q admissionTestTx) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := q.Tx.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

func admissionDatabase(t *testing.T) (context.Context, *pgx.Conn, *pgx.Conn, *preAuthProfile) {
	t.Helper()
	ctx, db, peer := otpDatabase(t)
	for _, source := range []migrations.Source{
		sessionpg.MigrationSource{Schema: "session_store", Version: 200},
		sessionpg.PreAuthMigrationSource{Schema: "session_store", Version: 201},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, err := newPreAuthProfile(sessionpg.Config{Schema: "session_store", MaximumDuration: 3 * time.Second}, map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, peer, p
}

func admissionBegin(t *testing.T, ctx context.Context, db *pgx.Conn) admissionTestTx {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	return admissionTestTx{tx}
}

func admissionInsert(t *testing.T, ctx context.Context, db *pgx.Conn, p *preAuthProfile, r session.PreAuthTransaction) {
	t.Helper()
	tx := admissionBegin(t, ctx, db)
	if err := sessionpg.InsertPreAuth(ctx, tx, p.config, r); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func admissionSnapshot(t *testing.T, ctx context.Context, q admissionTestTx) string {
	t.Helper()
	var snapshot string
	if err := q.Tx.QueryRow(ctx, `SELECT json_build_object('flows',(SELECT json_agg(f ORDER BY flow_id) FROM session_store.preauth_transactions f),'commands',(SELECT json_agg(c ORDER BY command_id) FROM identity.commands c))::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestNativePreAuthPrimaryAdmission(t *testing.T) {
	ctx, db, _, p := admissionDatabase(t)
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	c, command, plan, original, wire := admissionFixture(t, now.Add(-time.Second))
	admissionInsert(t, ctx, db, p, original)
	spec, _ := command.Feature()
	code, _ := command.OneTimeCode()
	wrong, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32))))
	for _, input := range []identity.Command{wrong, command, wrong, command} {
		tx := admissionBegin(t, ctx, db)
		before := admissionSnapshot(t, ctx, tx)
		_, err := admitPreAuth(ctx, tx, p, c, input, plan, nil)
		if cookie, _ := input.PreAuthCookie(); cookie.Token() == wrongCookieWire() {
			if !errors.Is(err, ErrInvalidCommand) {
				t.Fatal("wrong cookie admitted", err)
			}
		} else if err != nil {
			t.Fatal("original issued flow denied", err)
		}
		if after := admissionSnapshot(t, ctx, tx); after != before {
			t.Fatal("read admission mutated durable state")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Stale custody cannot borrow a different coherently encoded primary intent.
	projection, _ := original.Bindings()
	changed := projection
	changed.Binding.Intent.Nonce[0]++
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	changed.Cookie, _ = token.PreAuthDigest(key, changed.Binding)
	changedRecord, _ := session.NewPreAuthTransaction(changed)
	if _, err := db.Exec(ctx, `DELETE FROM session_store.preauth_transactions`); err != nil {
		t.Fatal(err)
	}
	admissionInsert(t, ctx, db, p, changedRecord)
	tx := admissionBegin(t, ctx, db)
	if _, err := admitPreAuth(ctx, tx, p, c, command, plan, nil); err == nil {
		t.Fatal("fresh primary intent replaced authenticated original")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM session_store.preauth_transactions`); err != nil {
		t.Fatal(err)
	}
	admissionInsert(t, ctx, db, p, original)
	if _, err := db.Exec(ctx, `UPDATE session_store.preauth_transactions SET issued_version=2,version=2`); err != nil {
		t.Fatal(err)
	}
	tx = admissionBegin(t, ctx, db)
	if _, err := admitPreAuth(ctx, tx, p, c, command, plan, nil); err == nil {
		t.Fatal("changed issued primary version admitted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE session_store.preauth_transactions SET issued_version=1,version=1`); err != nil {
		t.Fatal(err)
	}
	// Exact reserved custody is distinct from an issued flow.
	use := sessionpg.PreAuthUse{Command: spec.Binding, Fingerprint: [32]byte{11}, Generation: 1}
	tx = admissionBegin(t, ctx, db)
	if err := sessionpg.ReservePreAuth(ctx, tx, p.config, original, use); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	custody := kernel.OTPReservationBinding{Command: use.Command, Plan: plan, Fingerprint: use.Fingerprint, Generation: use.Generation}
	for _, mutate := range []func(*kernel.OTPReservationBinding){nil,
		func(b *kernel.OTPReservationBinding) { b.Generation++ },
		func(b *kernel.OTPReservationBinding) { b.Fingerprint[0]++ },
		func(b *kernel.OTPReservationBinding) { b.Command.CommandID, _ = identity.NewCommandID() },
		func(b *kernel.OTPReservationBinding) { b.PreviousGeneration = 1 },
	} {
		candidate := custody
		if mutate != nil {
			mutate(&candidate)
		}
		tx := admissionBegin(t, ctx, db)
		before := admissionSnapshot(t, ctx, tx)
		_, err := admitPreAuth(ctx, tx, p, c, command, plan, &candidate)
		if mutate == nil && err != nil {
			t.Fatal("exact reserved owner denied", err)
		}
		if mutate != nil && err == nil {
			t.Fatal("foreign reservation owner admitted")
		}
		if before != admissionSnapshot(t, ctx, tx) {
			t.Fatal("reserved admission mutated state")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	tx = admissionBegin(t, ctx, db)
	if _, err := admitPreAuth(ctx, tx, p, c, command, plan, nil); err == nil {
		t.Fatal("reserved flow admitted as issued")
	}
	if err := sessionpg.FinalizePreAuth(ctx, tx, p.config, original, use); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx = admissionBegin(t, ctx, db)
	if _, err := admitPreAuth(ctx, tx, p, c, command, plan, &custody); err == nil {
		t.Fatal("terminal flow admitted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM session_store.preauth_transactions`); err != nil {
		t.Fatal(err)
	}
	tx = admissionBegin(t, ctx, db)
	if _, err := admitPreAuth(ctx, tx, p, c, command, plan, nil); err == nil {
		t.Fatal("missing flow admitted")
	}
}

func wrongCookieWire() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32))
}

func TestNativePreAuthExpiryAfterLockWait(t *testing.T) {
	ctx, db, peer, p := admissionDatabase(t)
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	c, command, plan, original, _ := admissionFixture(t, now.Add(-5*time.Minute+1200*time.Millisecond))
	admissionInsert(t, ctx, db, p, original)
	holder := admissionBegin(t, ctx, db)
	if _, err := holder.Tx.Exec(ctx, `SELECT flow_id FROM session_store.preauth_transactions FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	reader := admissionBegin(t, ctx, peer)
	var pid int
	if err := reader.Tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	projection, _ := original.Bindings()
	if err := reader.Tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if !now.Before(projection.Binding.ExpiresAt) {
		t.Fatal("fixture expired before lock wait")
	}
	done := make(chan error, 1)
	go func() { _, err := admitPreAuth(ctx, reader, p, c, command, plan, nil); done <- err }()
	joined := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = holder.Rollback(cleanup)
		if !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("admission goroutine cleanup failed")
			}
		}
	}()
	// A third connection can observe authoritative lock waiting while the two
	// owned transaction connections remain serial-use.
	observer, err := pgx.Connect(ctx, db.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := observer.Close(cleanup); err != nil {
			t.Error("observer cleanup", err)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission did not wait for primary exclusion")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for {
		if err := observer.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		if !now.Before(projection.Binding.ExpiresAt) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatal("post-lock exclusive primary expiry not enforced", err)
	}
}
