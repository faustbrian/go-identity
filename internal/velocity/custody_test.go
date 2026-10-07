package velocity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func leaseFixture(t *testing.T, check func(context.Context) error) Lease {
	t.Helper()
	l, err := NewLease(LeaseBinding{Tenant: "tenant", Namespace: [32]byte{1}, Epoch: [16]byte{2}, Generation: 1, Owner: [16]byte{3}, ExpiresAt: time.Date(2026, 10, 7, 12, 1, 0, 0, time.UTC)}, check)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func historyFixture() HistoryBinding {
	return HistoryBinding{
		ID: strings.Repeat("A", 43), Position: 1, Tenant: "tenant", Namespace: [32]byte{1}, Attempt: [32]byte{4}, Fingerprint: strings.Repeat("b", 64),
		Operation: "identity.otp.send", Phase: "before_credential_or_provider_work", PolicyVersion: 3,
		PreparedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), RecordedAt: time.Date(2026, 10, 7, 12, 0, 0, 1000, time.UTC), Window: 5 * time.Minute, Limit: 10, Outcome: Committed,
		Targets:  []Target{{Dimension: "tenant", Keys: []Key{{Version: 1, Encoded: "retained-key"}}}},
		Snapshot: []Counter{{Kind: "tenant", Value: 1, ObservedAt: time.Date(2026, 10, 7, 12, 0, 0, 2000, time.UTC), StartedAt: time.Date(2026, 10, 7, 12, 0, 0, 2000, time.UTC), ExpiresAt: time.Date(2026, 10, 7, 12, 5, 0, 2000, time.UTC)}},
	}
}

func TestOwnedHistoryAcceptsOriginalStorageOrderOnlyOncePerDimension(t *testing.T) {
	l := leaseFixture(t, func(context.Context) error { return nil })
	b := historyFixture()
	b.Targets = append(b.Targets, Target{Dimension: "subject_or_network", Keys: []Key{{Version: 1, Encoded: "second-key"}}})
	second := b.Snapshot[0]
	second.Kind = "subject_or_network"
	b.Snapshot = append([]Counter{second}, b.Snapshot...)
	h, err := NewHistory(l, b)
	if err != nil || !reflect.DeepEqual(HistoryFacts(h), b) {
		t.Fatal("original journal ordering changed", err)
	}
	b.Snapshot[1].Kind = b.Snapshot[0].Kind
	if _, err := NewHistory(l, b); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate dimension admitted")
	}
	b = historyFixture()
	for _, id := range []string{strings.Repeat("a", 64), strings.Repeat("A", 42), strings.Repeat("A", 42) + "B"} {
		b.ID = id
		if _, err := NewHistory(l, b); !errors.Is(err, ErrInvalid) {
			t.Fatal("noncanonical record identity admitted")
		}
	}
}

func TestOwnedHistoryAndAcknowledgementRequireExactLiveCustody(t *testing.T) {
	live := true
	checks := 0
	l := leaseFixture(t, func(context.Context) error {
		checks++
		if !live {
			return ErrUnavailable
		}
		return nil
	})
	b := historyFixture()
	h, err := NewHistory(l, b)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := Acknowledge(context.Background(), l, h)
	if err != nil || checks != 1 {
		t.Fatal("acknowledged effect lacks authoritative ownership check", err)
	}
	if got, err := Applied(context.Background(), l, ack); err != nil || got.Position != b.Position || !reflect.DeepEqual(got, b) || checks != 2 {
		t.Fatal("applied effect lost original history", err)
	}
	other := leaseFixture(t, func(context.Context) error { return nil })
	if _, err := Acknowledge(context.Background(), other, h); !errors.Is(err, ErrInvalid) {
		t.Fatal("equivalent foreign custody accepted")
	}
	if _, err := Applied(context.Background(), other, ack); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign owner advanced progress")
	}
	live = false
	if _, err := Acknowledge(context.Background(), l, h); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale primary ownership created acknowledgement")
	}
	if got, err := Applied(context.Background(), l, ack); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, HistoryBinding{}) {
		t.Fatal("stale acknowledgement advanced progress")
	}
}

func TestOwnedHistoryCopiesOriginalFactsAndRedacts(t *testing.T) {
	l := leaseFixture(t, func(context.Context) error { return nil })
	b := historyFixture()
	h, err := NewHistory(l, b)
	if err != nil {
		t.Fatal(err)
	}
	b.Targets[0].Keys[0].Encoded = "changed"
	b.Snapshot[0].Value = 99
	first := HistoryFacts(h)
	first.Targets[0].Keys[0].Encoded = "also-changed"
	first.Snapshot[0].Value = 100
	if got := HistoryFacts(h); got.Targets[0].Keys[0].Encoded != "retained-key" || got.Snapshot[0].Value != 1 {
		t.Fatal("caller replaced original facts")
	}
	ack, err := Acknowledge(context.Background(), l, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{l, h, ack, LeaseFacts(l), HistoryFacts(h)} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if s := fmt.Sprintf(format, v); !strings.Contains(s, "redacted") || strings.Contains(s, "retained-key") || strings.Contains(s, "tenant") {
				t.Fatal("owned custody exposed facts")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, ErrSensitive) {
			t.Fatal("owned custody serialized")
		}
	}
}

func TestOwnedCustodyRejectsZeroCancelledAndUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := leaseFixture(t, func(context.Context) error { t.Fatal("cancelled operation reached primary"); return nil })
	h, err := NewHistory(l, historyFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []context.Context{nil, ctx} {
		if _, err := Acknowledge(c, l, h); err == nil {
			t.Fatal("invalid context admitted")
		}
	}
	if _, err := NewLease(LeaseBinding{}, func(context.Context) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero lease admitted")
	}
	if _, err := NewLease(LeaseFacts(l), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing primary checker admitted")
	}
	if _, err := NewHistory(Lease{}, historyFixture()); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero owner admitted")
	}
	if _, err := Acknowledge(context.Background(), l, History{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero history admitted")
	}
	if _, err := Applied(context.Background(), l, Acknowledgement{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero acknowledgement admitted")
	}
	if !reflect.DeepEqual(HistoryFacts(History{}), HistoryBinding{}) || !reflect.DeepEqual(LeaseFacts(Lease{}), LeaseBinding{}) {
		t.Fatal("zero projected positive facts")
	}
}
