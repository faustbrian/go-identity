//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/otp"
)

func TestNativeLockoutSurvivesReissueAndPurposeChanges(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	c, a, _, _ := nativeChallenge(t, ctx, db)
	_ = c
	m, err := (LockoutMigrationSource{Schema: "otp_store", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, m[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	profile, err := newLockoutProfile([32]byte{91})
	if err != nil {
		t.Fatal(err)
	}
	check := profile.binding()
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding(singleton,key_binding) VALUES(true,$1)`, check[:]); err != nil {
		t.Fatal(err)
	}
	ab, _ := a.Bindings()
	continuation, _ := ab.Continuation.Bindings()
	scope := continuation.Scope
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := profile.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
		t.Fatal(err)
	}
	locked, now, err := profile.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := extendLockouts(ctx, sqlChallengeExec(tx), locked, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// These fields intentionally do not form shared abuse identity.
	scope.ChallengeID = "reissued"
	scope.TargetID = "other-target"
	scope.Generation++
	scope.PolicyVersion++
	scope.Purpose = otp.PurposePasswordReset
	scope.AuthorizationBinding = [32]byte{3}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := profile.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
		t.Fatal(err)
	}
	if _, _, err := profile.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("reissued challenge reset shared lockout", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.lockouts`).Scan(&count); err != nil || count != 2 {
		t.Fatal("reissue created independent abuse allowance", err)
	}
	// A different deployment key must deny, not address a fresh empty namespace.
	foreign, _ := newLockoutProfile([32]byte{92})
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, _, err := foreign.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope); !errors.Is(err, ErrUnavailable) {
		t.Fatal("changed lockout key bypassed original authority", err)
	}
}

func TestNativeLockoutRollbackAndMissingScope(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	_, a, _, _ := nativeChallenge(t, ctx, db)
	m, err := (LockoutMigrationSource{Schema: "otp_store", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, m[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	p, _ := newLockoutProfile([32]byte{91})
	check := p.binding()
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, check[:]); err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	continuation, _ := b.Continuation.Bindings()
	scope := continuation.Scope
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, _, err := p.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("missing lockout rows admitted verification", err)
	}
	if err := p.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
		t.Fatal(err)
	}
	locked, now, err := p.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := extendLockouts(ctx, sqlChallengeExec(tx), locked, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.lockouts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("rolled back denial retained lockout", err)
	}
}

func TestNativeLockoutScopeIsolationAndRetention(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	_, a, _, _ := nativeChallenge(t, ctx, db)
	m, err := (LockoutMigrationSource{Schema: "otp_store", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, m[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	p, _ := newLockoutProfile([32]byte{91})
	check := p.binding()
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, check[:]); err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	continuation, _ := b.Continuation.Bindings()
	scope := continuation.Scope
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := p.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
		t.Fatal(err)
	}
	locked, now, err := p.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := extendLockouts(ctx, sqlChallengeExec(tx), locked, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"subject-change", "destination-change", "pre-account", "tenant"} {
		changed := scope
		switch variant {
		case "subject-change":
			changed.SubjectID = "other-subject"
		case "destination-change":
			changed.Destination, _ = otp.NewDestinationInput("other@example.test")
		case "pre-account":
			changed.SubjectID = ""
		case "tenant":
			changed.TenantID = "other-tenant"
		}
		tx, err = db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if err := p.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", changed); err != nil {
			t.Fatal(err)
		}
		_, _, err = p.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", changed)
		if variant == "tenant" && err != nil || variant != "tenant" && !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("scope isolation %s: %v", variant, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{
		`DELETE FROM otp_store.lockouts`,
		`UPDATE otp_store.lockouts SET version=version+1,blocked_until=clock_timestamp()`,
		`UPDATE otp_store.lockout_key_binding SET key_binding=decode(repeat('01',32),'hex')`,
		`DELETE FROM otp_store.lockout_key_binding`,
	} {
		if _, err := db.Exec(ctx, sql); err == nil {
			t.Fatal("lockout state/key reset accepted")
		}
	}
}

func TestNativeLockoutUsesTimeAfterLockWait(t *testing.T) {
	ctx, db, peer := otpDatabase(t)
	_, a, _, _ := nativeChallenge(t, ctx, db)
	m, err := (LockoutMigrationSource{Schema: "otp_store", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, m[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	p, _ := newLockoutProfile([32]byte{91})
	check := p.binding()
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, check[:]); err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	continuation, _ := b.Continuation.Bindings()
	scope := continuation.Scope
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := p.initializeLockouts(ctx, sqlChallengeQuery(tx), sqlChallengeExec(tx), "otp_store", scope); err != nil {
		t.Fatal(err)
	}
	// Real verification starts after the issuance transaction has committed the
	// scope rows. An uncommitted insert is absent to the peer, not lockable.
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	locked, now, err := p.loadLockouts(ctx, sqlChallengeQuery(tx), "otp_store", scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := extendLockouts(ctx, sqlChallengeExec(tx), locked, now, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var workerErr error
	var sampled time.Time
	go func() {
		defer close(done)
		tx, e := peer.Begin(workerCtx)
		if e != nil {
			workerErr = e
			return
		}
		defer tx.Rollback(context.Background())
		_, sampled, workerErr = p.loadLockouts(workerCtx, sqlChallengeQuery(tx), "otp_store", scope)
	}()
	defer func() { cancel(); _ = tx.Rollback(context.Background()); <-done }()
	// Observe a real lock wait, not a scheduler-dependent sleep assertion.
	limit := time.Now().Add(time.Second)
	for {
		if _, err := tx.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			t.Fatal(err)
		}
		var waiting bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, peer.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("peer never reached lock wait")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if workerErr != nil || sampled.Before(now.Add(100*time.Millisecond)) {
		t.Fatal("pre-wait time controlled expiry", workerErr)
	}
}
