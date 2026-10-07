//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityCoverage(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	issuer, _, _, verifier := risk.NewVelocityRecoveryAuthorities()
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 5 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, "coverage-tenant", [16]byte{81})
	if err != nil {
		t.Fatal(err)
	}
	// Empty retained history proves a stable cut, not prior temporal coverage.
	if closure, err := recovery.PrepareCoveredClosure(ctx, lease); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("fresh empty history manufactured full-window coverage")
	}
	var started, now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT journal_started_at,clock_timestamp() FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&started, &now); err != nil || started.After(now) || started.Before(now.Add(-time.Second)) {
		t.Fatal("journal start was backdated", err)
	}
	// Historical primary fixture models one hour of continuously journal-owned
	// execution, not a caller-provided production timestamp or healthy override.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	covered, err := recovery.PrepareCoveredClosure(ctx, lease)
	if err != nil {
		t.Fatal("complete empty interval did not qualify", err)
	}
	if err := recovery.CheckCoveredClosure(ctx, covered); err != nil {
		t.Fatal(err)
	}
	renewed, err := recovery.Renew(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckCoveredClosure(ctx, covered); err == nil {
		t.Fatal("renewed lease accepted old coverage closure")
	}
	covered, err = recovery.PrepareCoveredClosure(ctx, renewed)
	if err != nil {
		t.Fatal("renewal reset continuous journal coverage", err)
	}
	boundary := covered.state.through.Add(-time.Hour)
	for _, offset := range []time.Duration{time.Microsecond, 0, -time.Microsecond} {
		if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:], boundary.Add(offset)); err != nil {
			t.Fatal(err)
		}
		got, err := recovery.PrepareCoveredClosure(ctx, renewed)
		if offset > 0 {
			if err == nil || got != (VelocityRecoveryClosure{}) {
				t.Fatal("one microsecond short qualified")
			}
		} else if err != nil {
			t.Fatal("complete boundary denied", offset, err)
		} else {
			covered = got
		}
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	for _, epoch := range [][16]byte{{81}, {82}} {
		next, err := recovery.Acquire(ctx, lease.state.tenant, epoch)
		if err != nil {
			t.Fatal("takeover failed", err)
		}
		got, err := recovery.PrepareCoveredClosure(ctx, next)
		if err != nil || !got.state.started.Equal(covered.state.started) {
			t.Fatal("takeover/boot reset coverage", err)
		}
		if err := recovery.CheckCoveredClosure(ctx, covered); err == nil {
			t.Fatal("old closure survived takeover")
		}
		covered, renewed, lease = got, next, next
		if epoch == [16]byte{81} {
			if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET lease_expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := recovery.CheckCoveredClosure(ctx, covered); err == nil {
		t.Fatal("missing historical coverage remained eligible")
	}
	if closure, err := recovery.PrepareCoveredClosure(ctx, renewed); err == nil || closure != (VelocityRecoveryClosure{}) {
		t.Fatal("missing coverage was manufactured from replay cut")
	}
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT journal_started_at,clock_timestamp() FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, lease.state.tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&started, &now); err != nil || started.Before(now.Add(-time.Second)) || started.After(now) {
		t.Fatal("unknown provenance did not restart at primary time", err)
	}
}
