//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testVelocityRecovery(t *testing.T, ctx context.Context, pool *database.Pool, journal VelocityJournal, cfg VelocityJournalConfig, dsn, databaseName string) {
	t.Helper()
	recoveryConfig := VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 2 * time.Second}
	newOwner := func(c VelocityRecoveryConfig) VelocityRecovery {
		t.Helper()
		owner, err := NewVelocityRecovery(c)
		if err != nil {
			t.Fatal(err)
		}
		return owner
	}
	owner := newOwner(recoveryConfig)
	boot := [16]byte{1}
	var leases [4]VelocityRecoveryLease
	var errs [4]error
	owners := []VelocityRecovery{owner, newOwner(recoveryConfig), newOwner(recoveryConfig), newOwner(recoveryConfig)}
	var wg sync.WaitGroup
	for i := range owners {
		wg.Add(1)
		go func() { defer wg.Done(); leases[i], errs[i] = owners[i].Acquire(ctx, "native-tenant", boot) }()
	}
	wg.Wait()
	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner >= 0 {
				t.Fatal("multiple live recovery owners")
			}
			winner = i
		} else {
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || leases[i].state != nil {
				t.Fatal("unsafe competing lease", err)
			}
		}
	}
	if winner < 0 {
		t.Fatal("no recovery owner")
	}
	owner = owners[winner]
	lease := leases[winner]
	if err := owner.CheckLease(ctx, lease); err != nil {
		t.Fatal("live lease denied", err)
	}
	if err := newOwner(recoveryConfig).CheckLease(ctx, lease); err == nil {
		t.Fatal("foreign owner used receipt")
	}
	var state, generation string
	var from, through, expires time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT state,generation::text,replay_from,replay_through,lease_expires_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "native-tenant", journal.state.namespace, boot[:]).Scan(&state, &generation, &from, &through, &expires); err != nil || state != "replaying" || generation != "1" || !through.Equal(from) || expires.Sub(from) <= time.Hour {
		t.Fatal("unsafe initialized recovery epoch", err)
	}
	renewed, err := owner.Renew(ctx, lease)
	if err != nil {
		t.Fatal("live renewal denied", err)
	}
	if err := owner.CheckLease(ctx, lease); err == nil {
		t.Fatal("superseded lease still live")
	}
	if err := owner.CheckLease(ctx, renewed); err != nil {
		t.Fatal("renewed lease denied", err)
	}
	var renewalResults [4]VelocityRecoveryLease
	var renewalErrors [4]error
	for i := range renewalResults {
		wg.Add(1)
		go func() { defer wg.Done(); renewalResults[i], renewalErrors[i] = owner.Renew(ctx, renewed) }()
	}
	wg.Wait()
	renewalWinner := -1
	for i, err := range renewalErrors {
		if err == nil {
			if renewalWinner >= 0 {
				t.Fatal("multiple superseding renewals")
			}
			renewalWinner = i
		}
	}
	if renewalWinner < 0 {
		t.Fatal("no renewal winner")
	}
	renewed = renewalResults[renewalWinner]
	if _, err := owner.Acquire(ctx, "native-tenant", [16]byte{2}); err == nil {
		t.Fatal("live owner replaced by different boot")
	}
	if _, err := owner.Acquire(ctx, "recovery-other", boot); err != nil {
		t.Fatal("tenant lease collision", err)
	}
	otherCfg := cfg
	otherCfg.Namespace = "reference/other"
	otherJournal, err := NewVelocityJournal(otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	otherRecovery := recoveryConfig
	otherRecovery.Journal = otherJournal
	if _, err := newOwner(otherRecovery).Acquire(ctx, "native-tenant", boot); err != nil {
		t.Fatal("namespace lease collision", err)
	}

	// Authority time controls takeover, not process time or receipt expiry.
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "native-tenant", journal.state.namespace, boot[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Renew(ctx, renewed); err == nil {
		t.Fatal("expired owner renewed")
	}
	next := newOwner(recoveryConfig)
	taken, err := next.Acquire(ctx, "native-tenant", boot)
	if err != nil {
		t.Fatal("expired lease takeover denied", err)
	}
	if err := owner.CheckLease(ctx, renewed); err == nil {
		t.Fatal("stale owner survived takeover")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "native-tenant", journal.state.namespace, boot[:]).Scan(&generation); err != nil || generation != "2" {
		t.Fatal("generation did not advance", err)
	}
	if err := next.CheckLease(ctx, taken); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "native-tenant", journal.state.namespace, boot[:]); err != nil {
		t.Fatal(err)
	}
	replacement, err := owner.Acquire(ctx, "native-tenant", [16]byte{2})
	if err != nil {
		t.Fatal("new boot takeover denied", err)
	}
	if err := next.CheckLease(ctx, taken); err == nil {
		t.Fatal("retired boot still live")
	}
	if _, err := owner.Acquire(ctx, "native-tenant", boot); err == nil {
		t.Fatal("retired boot resurrected")
	}
	var healthy int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM risk_store.velocity_epochs WHERE namespace_digest=$1 AND state='healthy'`, journal.state.namespace).Scan(&healthy); err != nil || healthy != 0 {
		t.Fatal("ownership fabricated health", err)
	}
	if err := owner.CheckLease(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	// Exhausted numeric generations fail without wraparound or retirement.
	if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET generation=18446744073709551615,lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "native-tenant", journal.state.namespace, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Acquire(ctx, "native-tenant", [16]byte{3}); err == nil {
		t.Fatal("generation overflow admitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := owner.Acquire(cancelled, "cancelled", boot); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := owner.Acquire(nil, "nil-context", boot); err == nil {
		t.Fatal("nil context admitted")
	}
	if _, err := owner.Acquire(ctx, "", boot); err == nil {
		t.Fatal("empty tenant admitted")
	}
	if _, err := owner.Acquire(ctx, "tenant", [16]byte{}); err == nil {
		t.Fatal("zero boot admitted")
	}
	// Wait across real expiry while the recovery lock is held. Sampling time
	// before acquiring the lock would incorrectly validate this stale receipt.
	shortConfig := recoveryConfig
	shortConfig.LeaseDuration = 200 * time.Millisecond
	short := newOwner(shortConfig)
	shortLease, err := short.Acquire(ctx, "recovery-lock-boundary", boot)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer velocityRollback(blocker)
	if err := short.state.lock(ctx, blocker, "recovery-lock-boundary"); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- short.CheckLease(ctx, shortLease) }()
	waiting := false
	for i := 0; i < 40; i++ {
		// PostgreSQL caches activity per transaction; each wait observation must
		// see current backend state rather than the first poll's snapshot.
		if _, err := blocker.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			break
		}
		if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%')`).Scan(&waiting); err != nil {
			break
		}
		if waiting {
			break
		}
		if _, err := blocker.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
			break
		}
	}
	if waiting {
		_, err = blocker.Exec(ctx, `SELECT pg_sleep(0.25)`)
	}
	velocityRollback(blocker)
	blockedError := <-blocked
	if !waiting || err != nil || blockedError == nil {
		t.Fatal("post-lock database expiry not enforced", err, blockedError)
	}
	// A real successful COMMIT with its acknowledgement dropped grants no receipt.
	faultPool, fault := newCommitAckPool(t, ctx, dsn, databaseName, nil)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("recovery fault pool cleanup")
		}
	}()
	faultCfg := cfg
	faultCfg.Pool = faultPool
	faultCfg.Namespace = "reference/recovery-ack"
	faultJournal, err := NewVelocityJournal(faultCfg)
	if err != nil {
		t.Fatal(err)
	}
	faultRecovery := recoveryConfig
	faultRecovery.Journal = faultJournal
	faultOwner := newOwner(faultRecovery)
	faultBoot := [16]byte{9}
	fault.velocityEpoch.Store(&faultBoot)
	lost, err := faultOwner.Acquire(ctx, "recovery-ack", faultBoot)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || lost.state != nil || fault.hits.Load() != 1 {
		t.Fatal("ambiguous lease granted custody", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, "recovery-ack", faultJournal.state.namespace, faultBoot[:]).Scan(&state); err != nil || state != "replaying" {
		t.Fatal("fault did not reach authoritative commit", err)
	}
	if _, err := faultOwner.Acquire(ctx, "recovery-ack", faultBoot); err == nil {
		t.Fatal("unknown lease retried into duplicate ownership")
	}
}
