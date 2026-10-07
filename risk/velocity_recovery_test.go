package risk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func recoveryFacts() (risk.VelocityLeaseBinding, risk.VelocityHistoryBinding) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	lease := risk.VelocityLeaseBinding{Tenant: "tenant", Namespace: [32]byte{1}, Epoch: [16]byte{2}, Owner: [16]byte{3}, Generation: 1, ExpiresAt: now.Add(time.Minute)}
	history := risk.VelocityHistoryBinding{ID: strings.Repeat("A", 43), Position: 1, Tenant: lease.Tenant, Namespace: lease.Namespace, Attempt: [32]byte{4}, Fingerprint: strings.Repeat("b", 64), Operation: "identity.profile.get", Phase: risk.BeforeReturn, PolicyVersion: 1, PreparedAt: now, RecordedAt: now, Window: 5 * time.Minute, Limit: 10, Outcome: risk.VelocityHistoryCommitted,
		Targets:  []risk.CounterTarget{{Dimension: risk.TenantDimension, Keys: []risk.CounterKey{{Version: 1, Encoded: "retained-key"}}}},
		Snapshot: []risk.Counter{{Kind: string(risk.TenantDimension), Value: 1, ObservedAt: now, WindowStartedAt: now, WindowExpiresAt: now.Add(5 * time.Minute)}}}
	return lease, history
}

func TestVelocityRecoveryPublicGenuineHolderCannotForgeNativeAuthority(t *testing.T) {
	journal, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, hb := recoveryFacts()
	live := true
	lease, err := journal.Lease(lb, func(context.Context) error {
		if !live {
			return risk.ErrVelocityRecoveryUnavailable
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	history, err := journal.History(lease, hb)
	if err != nil {
		t.Fatal(err)
	}
	// An ordinary holder may construct foreign capabilities but cannot promote
	// genuine history into an acknowledgement accepted by the configured graph.
	foreignJournal, foreignReader, foreignNative, foreignVerifier := risk.NewVelocityRecoveryAuthorities()
	if _, err := foreignNative.Acknowledge(context.Background(), lease, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("genuine holder fabricated native acknowledgement", err)
	}
	if _, err := (risk.VelocityNativeIssuer{}).Acknowledge(context.Background(), lease, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero issuer fabricated acknowledgement", err)
	}
	foreignLease, err := foreignJournal.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	foreignHistory, err := foreignJournal.History(foreignLease, hb)
	if err != nil {
		t.Fatal(err)
	}
	foreignAck, err := foreignNative.Acknowledge(context.Background(), foreignLease, foreignHistory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Applied(context.Background(), lease, foreignAck); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("equivalent foreign graph advanced progress", err)
	}
	if _, err := reader.History(context.Background(), foreignLease, foreignHistory); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign journal history admitted", err)
	}
	if _, err := foreignReader.History(context.Background(), lease, history); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign reader recovered genuine history", err)
	}
	if _, err := journal.History(foreignLease, hb); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign lease rebound to configured journal", err)
	}
	ack, err := native.Acknowledge(context.Background(), lease, history)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignVerifier.Applied(context.Background(), lease, ack); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign verifier accepted configured acknowledgement", err)
	}
	got, err := verifier.Applied(context.Background(), lease, ack)
	if err != nil || !reflect.DeepEqual(got, hb) {
		t.Fatal("configured original acknowledgement rejected", err)
	}
	live = false
	if _, err := verifier.Applied(context.Background(), lease, ack); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) {
		t.Fatal("stale primary custody advanced progress", err)
	}
	// Named struct conversion must not let public callers turn a reader or
	// journal capability into a native issuing capability.
	for _, value := range []any{journal, reader, verifier} {
		if reflect.TypeOf(value).ConvertibleTo(reflect.TypeOf(native)) {
			t.Fatal("public capability conversion manufactures native issuer")
		}
	}
}

func TestVelocityRecoveryPublicFactsRemainOriginalAndUnresolved(t *testing.T) {
	j, r, n, v := risk.NewVelocityRecoveryAuthorities()
	lb, hb := recoveryFacts()
	l, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	h, err := j.History(l, hb)
	if err != nil {
		t.Fatal(err)
	}
	hb.Targets[0].Keys[0].Encoded = "changed"
	hb.Snapshot[0].Value = 99
	b, err := r.History(context.Background(), l, h)
	if err != nil || b.Targets[0].Keys[0].Encoded != "retained-key" || b.Snapshot[0].Value != 1 {
		t.Fatal("input mutation changed original facts", err)
	}
	b.Targets[0].Keys[0].Encoded = "also-changed"
	b.Snapshot[0].Value = 100
	b, err = r.History(context.Background(), l, h)
	if err != nil || b.Targets[0].Keys[0].Encoded != "retained-key" || b.Snapshot[0].Value != 1 {
		t.Fatal("returned mutation changed original facts", err)
	}
	for _, outcome := range []risk.VelocityHistoryOutcome{risk.VelocityHistoryPending, risk.VelocityHistoryUnknown, risk.VelocityHistoryNotCommitted} {
		_, b := recoveryFacts()
		b.Outcome = outcome
		b.Snapshot = nil
		h, err := j.History(l, b)
		if err != nil {
			t.Fatal(err)
		}
		a, err := n.Acknowledge(context.Background(), l, h)
		if outcome != risk.VelocityHistoryNotCommitted {
			if !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) {
				t.Fatal("unresolved history became native acknowledgement", err)
			}
		} else if err != nil {
			t.Fatal("explicit noncommit acknowledgement rejected", err)
		} else if got, err := v.Applied(context.Background(), l, a); err != nil || got.Outcome != outcome {
			t.Fatal("noncommit changed classification", err)
		}
	}
	for _, value := range []any{j, r, n, v, l, h, lb, b} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if s := fmt.Sprintf(format, value); !strings.Contains(s, "redacted") || strings.Contains(s, "retained-key") || strings.Contains(s, "tenant") {
				t.Fatal("recovery capability disclosed facts")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("recovery capability serialized")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("recovery capability text serialized", err)
		}
	}
}

func TestVelocityRecoveryPublicCheckerErrorsDoNotGrantFacts(t *testing.T) {
	j, r, n, v := risk.NewVelocityRecoveryAuthorities()
	lb, hb := recoveryFacts()
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private primary diagnostic")} {
		l, err := j.Lease(lb, func(context.Context) error { return failure })
		if err != nil {
			t.Fatal(err)
		}
		h, err := j.History(l, hb)
		if err != nil {
			t.Fatal(err)
		}
		want := failure
		if failure.Error() == "private primary diagnostic" {
			want = risk.ErrVelocityRecoveryUnavailable
		}
		if b, err := r.History(context.Background(), l, h); !errors.Is(err, want) || b.Position != 0 {
			t.Fatal("failed primary checker returned original facts", err)
		}
		if _, err := n.Acknowledge(context.Background(), l, h); !errors.Is(err, want) {
			t.Fatal("failed primary checker issued native acknowledgement", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	l, err := j.Lease(lb, func(context.Context) error { cancel(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	h, err := j.History(l, hb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.History(ctx, l, h); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during checker ignored", err)
	}
	if _, err := v.Applied(nil, l, risk.VelocityAcknowledgement{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("nil context and zero acknowledgement accepted", err)
	}
}

func TestVelocityRecoveryPublicCanceledAndZeroFailClosed(t *testing.T) {
	j, r, n, v := risk.NewVelocityRecoveryAuthorities()
	lb, hb := recoveryFacts()
	checks := 0
	l, err := j.Lease(lb, func(context.Context) error { checks++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	h, err := j.History(l, hb)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.History(ctx, l, h); !errors.Is(err, context.Canceled) || checks != 0 {
		t.Fatal("canceled read reached primary checker", err)
	}
	if _, err := n.Acknowledge(ctx, l, h); !errors.Is(err, context.Canceled) || checks != 0 {
		t.Fatal("canceled native acknowledgement reached checker", err)
	}
	if _, err := v.Applied(context.Background(), l, risk.VelocityAcknowledgement{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero acknowledgement accepted", err)
	}
	if _, err := (risk.VelocityJournalIssuer{}).Lease(lb, func(context.Context) error { return nil }); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero journal issuer accepted", err)
	}
	if _, err := j.Lease(lb, nil); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("missing primary checker accepted", err)
	}
}

func TestVelocityRecoveryPublicConstructionRejectsCrossedOwners(t *testing.T) {
	j, r, n, v := risk.NewVelocityRecoveryAuthorities()
	_, foreignReader, _, foreignVerifier := risk.NewVelocityRecoveryAuthorities()
	if err := j.ValidateNative(v); err != nil {
		t.Fatal("paired native verifier rejected", err)
	}
	if err := j.ValidateNative(foreignVerifier); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("crossed native owner accepted", err)
	}
	if err := (risk.VelocityJournalIssuer{}).ValidateNative(v); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero primary owner accepted", err)
	}
	read, err := j.Verifier()
	if err != nil || reflect.TypeOf(read) != reflect.TypeOf(r) {
		t.Fatal("primary verifier unavailable", err)
	}
	nativeRead, err := n.JournalVerifier()
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := recoveryFacts()
	l, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := read.Lease(l); err != nil {
		t.Fatal("derived primary verifier lost custody", err)
	}
	if _, err := nativeRead.Lease(l); err != nil {
		t.Fatal("derived native verifier lost custody", err)
	}
	if _, err := foreignReader.Lease(l); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign verifier reads fencing secret", err)
	}
	if _, err := (risk.VelocityJournalIssuer{}).Verifier(); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero issuer derives verifier", err)
	}
	if _, err := (risk.VelocityNativeIssuer{}).JournalVerifier(); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero native issuer derives verifier", err)
	}
}
