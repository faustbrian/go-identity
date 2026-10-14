package valkey

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func ownedHistoryFixture(t *testing.T) (commandLayout, commandPlan, risk.VelocityLease, risk.VelocityHistory, risk.VelocityJournalIssuer, risk.VelocityJournalVerifier, risk.VelocityNativeIssuer, risk.VelocityNativeVerifier) {
	t.Helper()
	p, keys, c := commandFixture(t, 9, 8)
	secret := bytes.Repeat([]byte{1}, 32)
	layout, err := newCommandLayout("native-test", secret, p, keys)
	if err != nil {
		t.Fatal(err)
	}
	cmd := prepareFixture(t, c, "tenant", "original-attempt", "192.0.2.1")
	plan, err := layout.prepare(cmd, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := risk.NewVelocityReplayIdentity("native-test", secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := replay.Attempt(cmd)
	if err != nil {
		t.Fatal(err)
	}
	b := cmd.Bindings()
	issuer, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lease, err := issuer.Lease(risk.VelocityLeaseBinding{Tenant: b.Tenant, Namespace: replay.Namespace(), Epoch: [16]byte{1}, Generation: 1, Owner: [16]byte{2}, ExpiresAt: b.PreparedAt.Add(time.Minute)}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	facts := risk.VelocityHistoryBinding{ID: strings.Repeat("A", 43), Position: 1, Tenant: b.Tenant, Namespace: replay.Namespace(), Attempt: digest, Fingerprint: b.Fingerprint, Operation: b.Operation, Phase: b.Phase, PolicyVersion: b.PolicyVersion, PreparedAt: b.PreparedAt, RecordedAt: b.PreparedAt, Window: b.Window, Limit: b.Limit, Outcome: risk.VelocityHistoryCommitted}
	for _, target := range b.Targets {
		v := risk.CounterTarget{Dimension: target.Dimension}
		for _, key := range target.Keys {
			v.Keys = append(v.Keys, risk.CounterKey{Version: key.Version, Encoded: key.Encoded})
		}
		facts.Targets = append(facts.Targets, v)
		facts.Snapshot = append(facts.Snapshot, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt, WindowExpiresAt: b.PreparedAt.Add(b.Window)})
	}
	// Durable journal ordering differs from policy target ordering.
	slices.Reverse(facts.Snapshot)
	history, err := issuer.History(lease, facts)
	if err != nil {
		t.Fatal(err)
	}
	return layout, plan, lease, history, issuer, reader, native, verifier
}

func TestOwnedHistoryReconstructsOriginalPlanWithoutCommand(t *testing.T) {
	layout, original, lease, history, _, reader, _, _ := ownedHistoryFixture(t)
	plan, snapshots, err := layout.history(context.Background(), reader, lease, history)
	if err != nil || !reflect.DeepEqual(plan, original) || len(snapshots) != 4 {
		t.Fatal("original authenticated plan not reconstructed", err)
	}
	db := newScriptDB()
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+time.Minute.Microseconds())
	runRecoveryScript(t, db, recoveryFenceScript, plan.keys[:1], []string{"", marker})
	args, err := recoveryArguments(plan, marker, snapshots)
	if err != nil {
		t.Fatal(err)
	}
	if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, args); got[0] != "restored" {
		t.Fatal("history not restored", got)
	}
	writes, state, expiry := db.writes, cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry)
	if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, args); got[0] != "restored" || db.writes != writes || !reflect.DeepEqual(state, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
		t.Fatal("history replay changed counters or expiry")
	}
}

func TestOwnedHistoryRejectsForeignOrUnresolvedFacts(t *testing.T) {
	layout, _, lease, history, issuer, reader, _, _ := ownedHistoryFixture(t)
	_, foreignReader, _, _ := risk.NewVelocityRecoveryAuthorities()
	if _, _, err := layout.history(context.Background(), foreignReader, lease, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign verifier read genuine history", err)
	}
	if _, _, err := layout.history(context.Background(), risk.VelocityJournalVerifier{}, lease, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("unconfigured verifier read genuine history", err)
	}
	if _, _, err := layout.history(context.Background(), reader, risk.VelocityLease{}, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign history admitted")
	}
	for _, outcome := range []risk.VelocityHistoryOutcome{risk.VelocityHistoryPending, risk.VelocityHistoryUnknown} {
		facts, err := reader.History(context.Background(), lease, history)
		if err != nil {
			t.Fatal(err)
		}
		facts.Outcome, facts.Snapshot = outcome, nil
		h, err := issuer.History(lease, facts)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := layout.history(context.Background(), reader, lease, h); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unresolved history reconstructed", err)
		}
	}
	facts, err := reader.History(context.Background(), lease, history)
	if err != nil {
		t.Fatal(err)
	}
	facts.Targets[0].Keys[0].Version = 10
	h, err := issuer.History(lease, facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := layout.history(context.Background(), reader, lease, h); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("unretained original alias admitted", err)
	}
}

func TestOwnedHistoryRequiresCurrentPrimaryOwnership(t *testing.T) {
	layout, _, lease, history, issuer, reader, _, _ := ownedHistoryFixture(t)
	lb, err := reader.Lease(lease)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := reader.History(context.Background(), lease, history)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := issuer.Lease(lb, func(context.Context) error { return errors.New("primary ownership unavailable") })
	if err != nil {
		t.Fatal(err)
	}
	h, err := issuer.History(stale, facts)
	if err != nil {
		t.Fatal(err)
	}
	if plan, snapshot, err := layout.history(context.Background(), reader, stale, h); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || len(plan.keys) != 0 || len(snapshot) != 0 {
		t.Fatal("stale primary ownership exposed native plan", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if plan, snapshot, err := layout.history(ctx, reader, lease, history); !errors.Is(err, context.Canceled) || len(plan.keys) != 0 || len(snapshot) != 0 {
		t.Fatal("cancelled reconstruction exposed native plan", err)
	}
}
