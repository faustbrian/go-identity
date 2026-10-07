//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityOwnedClosure(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	issuer, reader, _, verifier := risk.NewVelocityRecoveryAuthorities()
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	// Runtime interface assertion keeps the initial missing consumer path
	// executable rather than counting a missing-symbol compilation as behavior.
	exporter, ok := any(r).(interface {
		OwnedClosure(context.Context, VelocityRecoveryLease, risk.VelocityLease, VelocityRecoveryClosure) (risk.VelocityClosure, error)
	})
	if !ok {
		t.Fatal("primary covered closure cannot reach configured native consumer")
	}
	l, err := r.Acquire(ctx, "owned-closure-tenant", [16]byte{91})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := r.PrepareClosure(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := exporter.OwnedClosure(ctx, l, owned, ordinary); err == nil || got != (risk.VelocityClosure{}) {
		t.Fatal("ordinary stable cut became covered custody")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '1 hour 1 second' WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	covered, err := r.PrepareCoveredClosure(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := exporter.OwnedClosure(ctx, l, owned, covered)
	if err != nil {
		t.Fatal("covered primary cut not exported", err)
	}
	b, err := reader.Closure(ctx, owned, exported)
	if err != nil || b.ID == [32]byte{} || b.Position != 0 || !b.ReplayFrom.Equal(covered.state.from) || !b.ReplayThrough.Equal(covered.state.through) || !b.JournalStartedAt.Equal(covered.state.started) || b.MaximumWindow != time.Hour {
		t.Fatal("export changed original primary cut", err)
	}
	retry, err := exporter.OwnedClosure(ctx, l, owned, covered)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Closure(ctx, owned, retry); err != nil || got != b {
		t.Fatal("retry renewed original cut", err)
	}
	replacement, err := r.OwnedLease(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Closure(ctx, replacement, exported); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("replacement rebound exact lease", err)
	}
	fj, _, _, _ := risk.NewVelocityRecoveryAuthorities()
	lb, err := reader.Lease(owned)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := fj.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := exporter.OwnedClosure(ctx, l, foreign, covered); err == nil || got != (risk.VelocityClosure{}) {
		t.Fatal("foreign graph exported", err)
	}
	for _, change := range []func(*risk.VelocityLeaseBinding){
		func(b *risk.VelocityLeaseBinding) { b.Tenant = "other-owned-closure-tenant" },
		func(b *risk.VelocityLeaseBinding) { b.Namespace[0] ^= 1 },
		func(b *risk.VelocityLeaseBinding) { b.Epoch[0] ^= 1 },
		func(b *risk.VelocityLeaseBinding) { b.Owner[0] ^= 1 },
		func(b *risk.VelocityLeaseBinding) { b.Generation++ },
		func(b *risk.VelocityLeaseBinding) { b.ExpiresAt = b.ExpiresAt.Add(time.Microsecond) },
	} {
		changed := lb
		change(&changed)
		mismatched, err := issuer.Lease(changed, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal("invalid mismatch fixture", err)
		}
		if got, err := exporter.OwnedClosure(ctx, l, mismatched, covered); err == nil || got != (risk.VelocityClosure{}) {
			t.Fatal("projected lease mismatch exported", err)
		}
	}
	foreignRecovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 20 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := foreignRecovery.OwnedClosure(ctx, l, owned, covered); err == nil || got != (risk.VelocityClosure{}) {
		t.Fatal("foreign primary owner exported", err)
	}
	if got, err := r.OwnedClosure(ctx, VelocityRecoveryLease{}, owned, covered); err == nil || got != (risk.VelocityClosure{}) {
		t.Fatal("zero lease exported", err)
	}
	for _, malformed := range []VelocityRecoveryClosure{{}, ordinary} {
		if got, err := exporter.OwnedClosure(ctx, l, owned, malformed); err == nil || got != (risk.VelocityClosure{}) {
			t.Fatal("invalid closure exported", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := exporter.OwnedClosure(canceled, l, owned, covered); !errors.Is(err, context.Canceled) || got != (risk.VelocityClosure{}) {
		t.Fatal("canceled export returned custody", err)
	}
	var state string
	var expiry time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT state,lease_expires_at FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]).Scan(&state, &expiry); err != nil || state != "replaying" || !expiry.Equal(lb.ExpiresAt) {
		t.Fatal("export created health or renewed lease", err)
	}
	// Coverage loss invalidates already exported handles without preparing a
	// replacement cut, then restoration preserves the original keyed identity.
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Closure(ctx, owned, exported); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("coverage loss retained exported facts", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.state.tenant, journal.state.namespace, l.state.epoch[:], covered.state.started); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Closure(ctx, owned, exported); err != nil || got != b {
		t.Fatal("restored original cut changed", err)
	}
	if _, err := r.Renew(ctx, l); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Closure(ctx, owned, exported); err == nil || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("renewal retained old exported custody", err)
	}
}
