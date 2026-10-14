package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

func receiptShape() delivery.ReceiptRecordRequest {
	return delivery.ReceiptRecordRequest{TenantID: "tenant-a", IntentID: delivery.IntentID(strings.Repeat("a", 64)), Provider: "provider", ProviderEventID: "synthetic-event", Generation: 1, Status: delivery.StateDelivered, ObservedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), IdempotencyKey: "synthetic-receipt-0001"}
}

func TestReceiptFingerprintsSeparateScopeEventAndEvidence(t *testing.T) {
	s := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	q := receiptShape()
	event, evidence := s.digests(q)
	for _, mutate := range []func(*delivery.ReceiptRecordRequest){func(q *delivery.ReceiptRecordRequest) { q.TenantID = "other" }, func(q *delivery.ReceiptRecordRequest) { q.Provider = "other" }, func(q *delivery.ReceiptRecordRequest) { q.ProviderEventID = "other" }} {
		changed := q
		mutate(&changed)
		a, b := s.digests(changed)
		if a == event || b == evidence {
			t.Fatal("event namespace or evidence not bound")
		}
	}
	for _, mutate := range []func(*delivery.ReceiptRecordRequest){func(q *delivery.ReceiptRecordRequest) { q.IntentID = delivery.IntentID(strings.Repeat("b", 64)) }, func(q *delivery.ReceiptRecordRequest) { q.Generation++ }, func(q *delivery.ReceiptRecordRequest) { q.Status = delivery.StateRejected }, func(q *delivery.ReceiptRecordRequest) { q.ObservedAt = q.ObservedAt.Add(time.Nanosecond) }} {
		changed := q
		mutate(&changed)
		a, b := s.digests(changed)
		if a != event || b == evidence {
			t.Fatal("changed evidence replaced event identity or escaped its fingerprint")
		}
	}
	q.IdempotencyKey = "another-command-key"
	a, b := s.digests(q)
	if a != event || b != evidence {
		t.Fatal("kernel command identity became provider event identity")
	}
	for _, changed := range []receiptStore{{deployment: "other", namespaceKey: s.namespaceKey}, {deployment: s.deployment, namespaceKey: [32]byte{2}}} {
		a, b := changed.digests(q)
		if a == event || b == evidence {
			t.Fatal("deployment/key namespace not bound")
		}
	}
}

func TestBorrowedReceiptInvalidInputAndCancelledContext(t *testing.T) {
	s := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	q := receiptShape()
	sql := cancellationSQL{scan: func(context.Context, string, []any, ...any) error { t.Fatal("invalid input reached SQL"); return nil }, exec: func(context.Context, string, ...any) error { t.Fatal("invalid input reached SQL"); return nil }}
	for _, request := range []delivery.ReceiptRecordRequest{{}, {TenantID: "tenant-a", IntentID: "not-a-canonical-effect"}} {
		if out, err := s.recordIn(context.Background(), sql, request, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) || out != (delivery.ReceiptRecordResult{}) {
			t.Fatal("invalid request admitted", err)
		}
	}
	for _, receiver := range []*receiptStore{nil, {}, {deployment: "test"}, {deployment: "", namespaceKey: [32]byte{1}}} {
		if out, err := receiver.recordIn(context.Background(), sql, q, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) || out != (delivery.ReceiptRecordResult{}) {
			t.Fatal("invalid store admitted", err)
		}
	}
	if _, err := s.recordIn(nil, sql, q, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.recordIn(ctx, sql, q, "user-a"); !errors.Is(err, context.Canceled) || out != (delivery.ReceiptRecordResult{}) {
		t.Fatal("cancelled receipt reached storage", err)
	}
}
