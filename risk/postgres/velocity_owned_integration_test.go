//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func testVelocityOwnedHistory(t *testing.T, ctx context.Context, journal VelocityJournal, cfg VelocityJournalConfig) {
	t.Helper()
	var now time.Time
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: cfg.Policy, Keys: cfg.Keys, Store: neverVelocityStore{}, Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(risk.Context{Tenant: "owned-replay-tenant", Operation: "identity.profile.get", Attempt: "original"}, risk.Subject{User: "subject"}, risk.BeforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := journal.RecordAttempt(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	b := command.Bindings()
	var snapshots []risk.Counter
	for _, target := range b.Targets {
		snapshots = append(snapshots, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(b.Window)})
	}
	if err := journal.RecordResult(ctx, attempt, risk.CounterCommitted, snapshots); err != nil {
		t.Fatal(err)
	}
	issuer, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	recovery, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: 5 * time.Second, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := recovery.Acquire(ctx, b.Tenant, [16]byte{71})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := recovery.OwnedLease(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	page, err := recovery.ReadPage(ctx, lease, VelocityReplayCursor{}, 100)
	if err != nil || len(page.Records()) != 1 {
		t.Fatal("owned history unavailable", err)
	}
	record := page.Records()[0]
	history, err := recovery.OwnedHistory(ctx, lease, owned, record)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := reader.History(ctx, owned, history)
	if err != nil || facts.Fingerprint != b.Fingerprint || facts.Attempt != record.Projection().AttemptDigest || facts.Position <= 0 || facts.Outcome != risk.VelocityHistoryCommitted || len(facts.Snapshot) != 2 || !facts.Snapshot[0].ObservedAt.Equal(now) {
		t.Fatal("authenticated original facts replaced")
	}
	// The fixture represents an attributable native restore acknowledgement;
	// this test proves primary checkpoint semantics, not native execution.
	ack, err := native.Acknowledge(ctx, owned, history)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, ack); err != nil {
		t.Fatal("acknowledged restore not checkpointed", err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, ack); err != nil {
		t.Fatal("duplicate restore checkpoint not idempotent", err)
	}
	var applied int64
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT applied_position FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, b.Tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&applied); err != nil || applied != facts.Position {
		t.Fatal("durable original position missing", err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, risk.VelocityAcknowledgement{}); err == nil {
		t.Fatal("fabricated effect checkpoint admitted")
	}
	// Possession of genuine history grants no configured native issuance. Even
	// a separately valid issuer's acknowledgement must not advance this owner.
	foreignIssuer, _, foreignNative, _ := risk.NewVelocityRecoveryAuthorities()
	if _, err := foreignNative.Acknowledge(ctx, owned, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("genuine holder promoted foreign native issuance", err)
	}
	lb, err := reader.Lease(owned)
	if err != nil {
		t.Fatal(err)
	}
	foreignLease, err := foreignIssuer.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	foreignHistory, err := foreignIssuer.History(foreignLease, facts)
	if err != nil {
		t.Fatal(err)
	}
	foreignAck, err := foreignNative.Acknowledge(ctx, foreignLease, foreignHistory)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecordApplied(ctx, lease, foreignLease, foreignAck); err == nil {
		t.Fatal("foreign authentic effect advanced configured primary progress")
	}
	if err := recovery.RecordApplied(ctx, lease, owned, foreignAck); err == nil {
		t.Fatal("foreign authentic effect crossed genuine primary custody")
	}
	if err := cfg.Pool.Raw().QueryRow(ctx, `SELECT applied_position FROM risk_store.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, b.Tenant, journal.state.namespace, lease.state.epoch[:]).Scan(&applied); err != nil || applied != facts.Position {
		t.Fatal("rejected foreign effect changed durable progress", err)
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_position=applied_position+1 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, b.Tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, ack); err == nil {
		t.Fatal("altered durable progress admitted")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_epochs SET applied_position=applied_position-1 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, b.Tenant, journal.state.namespace, lease.state.epoch[:]); err != nil {
		t.Fatal(err)
	}
	// Two later records must be acknowledged in scoped change order, even when
	// global positions have gaps belonging to other tenants.
	for _, name := range []string{"second", "third"} {
		later, err := c.Prepare(risk.Context{Tenant: b.Tenant, Operation: b.Operation, Attempt: name}, risk.Subject{User: "subject"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := journal.RecordAttempt(ctx, later)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.RecordResult(ctx, receipt, risk.CounterNotCommitted, nil); err != nil {
			t.Fatal(err)
		}
	}
	laterPage, err := recovery.ReadPage(ctx, lease, page.Next(), 100)
	if err != nil || len(laterPage.Records()) != 2 {
		t.Fatal("later history missing", err)
	}
	var laterAcks []risk.VelocityAcknowledgement
	for _, row := range laterPage.Records() {
		h, err := recovery.OwnedHistory(ctx, lease, owned, row)
		hf, readErr := reader.History(ctx, owned, h)
		if err != nil || readErr != nil || hf.Outcome != risk.VelocityHistoryNotCommitted {
			t.Fatal("noncommit classification changed", err)
		}
		a, err := native.Acknowledge(ctx, owned, h)
		if err != nil {
			t.Fatal(err)
		}
		laterAcks = append(laterAcks, a)
	}
	if err := recovery.RecordApplied(ctx, lease, owned, laterAcks[1]); err == nil {
		t.Fatal("gap skipped unapplied history")
	}
	for _, a := range laterAcks {
		if err := recovery.RecordApplied(ctx, lease, owned, a); err != nil {
			t.Fatal("ordered history checkpoint failed", err)
		}
	}
	// Pending and unknown facts remain recoverable history, never no-effect
	// acknowledgement or permission to skip an unresolved write.
	for _, name := range []string{"pending", "unknown"} {
		later, err := c.Prepare(risk.Context{Tenant: b.Tenant, Operation: b.Operation, Attempt: name}, risk.Subject{User: "subject"}, risk.BeforeReturn)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := journal.RecordAttempt(ctx, later)
		if err != nil {
			t.Fatal(err)
		}
		if name == "unknown" {
			if err := journal.RecordResult(ctx, receipt, risk.CounterUnknown, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	unresolved, err := recovery.ReadPage(ctx, lease, laterPage.Next(), 100)
	if err != nil || len(unresolved.Records()) != 2 {
		t.Fatal("unresolved history lost", err)
	}
	for i, row := range unresolved.Records() {
		h, err := recovery.OwnedHistory(ctx, lease, owned, row)
		want := []risk.VelocityHistoryOutcome{risk.VelocityHistoryPending, risk.VelocityHistoryUnknown}[i]
		hf, readErr := reader.History(ctx, owned, h)
		if err != nil || readErr != nil || hf.Outcome != want {
			t.Fatal("unresolved classification changed", err)
		}
		if _, err := native.Acknowledge(ctx, owned, h); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) {
			t.Fatal("unresolved history acknowledged", err)
		}
	}
	// Struct projections cannot manufacture the durable owner's opaque record.
	if _, err := recovery.OwnedHistory(ctx, lease, owned, VelocityReplayRecord{}); err == nil {
		t.Fatal("fabricated history admitted")
	}
	if _, err := recovery.OwnedHistory(ctx, lease, risk.VelocityLease{}, record); err == nil {
		t.Fatal("foreign native custody admitted")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET counter_fingerprint=set_byte(counter_fingerprint,0,get_byte(counter_fingerprint,0)#1) WHERE sequence=$1`, attempt.state.sequence); err != nil {
		t.Fatal(err)
	}
	if h, err := recovery.OwnedHistory(ctx, lease, owned, record); err == nil || h != (risk.VelocityHistory{}) {
		t.Fatal("tampered current history reached native effects")
	}
	if _, err := cfg.Pool.Raw().Exec(ctx, `UPDATE risk_store.velocity_attempts SET counter_fingerprint=set_byte(counter_fingerprint,0,get_byte(counter_fingerprint,0)#1) WHERE sequence=$1`, attempt.state.sequence); err != nil {
		t.Fatal(err)
	}
	renewed, err := recovery.Renew(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Check(ctx, owned); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) {
		t.Fatal("old native custody survived renewal", err)
	}
	if _, err := recovery.OwnedHistory(ctx, renewed, owned, record); err == nil {
		t.Fatal("old native custody crossed superseding receipt")
	}
	if err := recovery.RecordApplied(ctx, renewed, owned, ack); err == nil {
		t.Fatal("stale native acknowledgement advanced progress")
	}
}
