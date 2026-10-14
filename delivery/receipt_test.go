package delivery_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	delivery "github.com/faustbrian/go-identity/delivery"
)

func TestReceiptDecisionMonotonicAndFenced(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	evidence := delivery.ReceiptRecordRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Provider: "provider", ProviderEventID: "event", Generation: 2, Status: delivery.StateDelivered, ObservedAt: now, IdempotencyKey: "synthetic-receipt-0001"}
	snapshot := delivery.ReceiptSnapshot{State: delivery.StateOutcomeUnknown, Generation: 2}
	got, err := delivery.DecideReceipt(snapshot, evidence)
	if err != nil || got.State != delivery.StateDelivered || !got.Advanced || !got.ErasePayload {
		t.Fatalf("authenticated delivery must settle unknown: %+v, %v", got, err)
	}
	snapshot.Generation = 3
	if got, err := delivery.DecideReceipt(snapshot, evidence); !errors.Is(err, delivery.ErrConflict) || got != (delivery.ReceiptDecision{}) {
		t.Fatal("old generation must not settle a replacement attempt", got, err)
	}
	snapshot.Generation = 2
	snapshot.State = delivery.StateDelivered
	snapshot.ObservedAt = now
	evidence.Status = delivery.StateBounced
	evidence.ObservedAt = now.Add(time.Second)
	if got, err := delivery.DecideReceipt(snapshot, evidence); !errors.Is(err, delivery.ErrConflict) || got != (delivery.ReceiptDecision{}) {
		t.Fatal("conflicting terminal evidence requires operator resolution", got, err)
	}
	evidence.ObservedAt = now.Add(-time.Second)
	got, err = delivery.DecideReceipt(snapshot, evidence)
	if err != nil || got.State != snapshot.State || got.Advanced || !got.ErasePayload {
		t.Fatal("earlier callback must not reverse current evidence", got, err)
	}
}

func TestReceiptDecisionClosedTransitionMatrix(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	// Explicit independent expectations: local queue/terminal states cannot be
	// converted to an invented provider outcome. Unknown/accepted never admit retry.
	allowed := map[delivery.DeliveryState][]delivery.DeliveryState{
		delivery.StateAttempting:     {delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateOutcomeUnknown},
		delivery.StateAccepted:       {delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateOutcomeUnknown},
		delivery.StateDelivered:      {delivery.StateAccepted, delivery.StateDelivered, delivery.StateOutcomeUnknown},
		delivery.StateRejected:       {delivery.StateAccepted, delivery.StateRejected, delivery.StateOutcomeUnknown},
		delivery.StateBounced:        {delivery.StateAccepted, delivery.StateBounced, delivery.StateOutcomeUnknown},
		delivery.StateCancelled:      {delivery.StateAccepted, delivery.StateCancelled, delivery.StateOutcomeUnknown},
		delivery.StateOutcomeUnknown: {delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateCancelled, delivery.StateOutcomeUnknown},
		delivery.StateRetryWait:      {delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateOutcomeUnknown},
		delivery.StateExpired:        {delivery.StateAccepted, delivery.StateOutcomeUnknown},
		delivery.StateExhausted:      {delivery.StateAccepted, delivery.StateOutcomeUnknown},
		delivery.StateSuperseded:     {delivery.StateAccepted, delivery.StateOutcomeUnknown},
	}
	terminal := map[delivery.DeliveryState]bool{delivery.StateDelivered: true, delivery.StateRejected: true, delivery.StateBounced: true, delivery.StateCancelled: true, delivery.StateExpired: true, delivery.StateExhausted: true, delivery.StateSuperseded: true}
	for state := delivery.StateQueued; state <= delivery.StateSuperseded; state++ {
		for _, status := range []delivery.DeliveryState{delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateCancelled, delivery.StateOutcomeUnknown} {
			evidence := validReceipt(now)
			evidence.Status = status
			current := delivery.ReceiptSnapshot{State: state, Generation: 2, ObservedAt: now.Add(-time.Second)}
			got, err := delivery.DecideReceipt(current, evidence)
			legal := false
			for _, candidate := range allowed[state] {
				legal = legal || candidate == status
			}
			if !legal {
				if !errors.Is(err, delivery.ErrConflict) || got != (delivery.ReceiptDecision{}) {
					t.Errorf("state %d evidence %d: want zero conflict, got %+v %v", state, status, got, err)
				}
				continue
			}
			wantState := status
			if terminal[state] || state == delivery.StateAccepted && status == delivery.StateOutcomeUnknown {
				wantState = state
			}
			if err != nil || got.State != wantState || got.Advanced != (wantState != state) || got.ErasePayload != terminal[wantState] {
				t.Errorf("state %d evidence %d: wrong monotonic result %+v %v", state, status, got, err)
			}
			if got.State == delivery.StateRetryWait || got.State == delivery.StateAttempting {
				t.Error("receipt decision invented retry/send permission")
			}
		}
	}
}

func validReceipt(now time.Time) delivery.ReceiptRecordRequest {
	return delivery.ReceiptRecordRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Provider: "provider", ProviderEventID: "event", Generation: 2, Status: delivery.StateDelivered, ObservedAt: now, IdempotencyKey: "synthetic-receipt-0001"}
}

func TestReceiptDecisionObservationOrdering(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	current := delivery.ReceiptSnapshot{State: delivery.StateDelivered, Generation: 2, ObservedAt: now}
	evidence := validReceipt(now)
	for _, when := range []time.Time{now.Add(-time.Second), now, now.Add(time.Second)} {
		evidence.ObservedAt = when
		got, err := delivery.DecideReceipt(current, evidence)
		wantTime := now
		if when.After(now) {
			wantTime = when
		}
		if err != nil || got.Advanced || !got.ErasePayload || got.State != delivery.StateDelivered || !got.ObservedAt.Equal(wantTime) {
			t.Fatal("duplicate delivery did not preserve terminal outcome and required erasure", got, err)
		}
	}
	evidence.Status = delivery.StateAccepted
	evidence.ObservedAt = now
	if got, err := delivery.DecideReceipt(current, evidence); !errors.Is(err, delivery.ErrConflict) || got != (delivery.ReceiptDecision{}) {
		t.Fatal("conflicting same-instant observation admitted", got, err)
	}
	evidence.ObservedAt = now.Add(time.Second)
	got, err := delivery.DecideReceipt(current, evidence)
	if err != nil || got.Advanced || !got.ObservedAt.Equal(now) {
		t.Fatal("non-progress evidence replaced authoritative observation watermark", got, err)
	}
}

func TestReceiptDecisionInvalidInputs(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	bad := []func(*delivery.ReceiptRecordRequest){
		func(r *delivery.ReceiptRecordRequest) { r.TenantID = "" },
		func(r *delivery.ReceiptRecordRequest) { r.IntentID = "short" },
		func(r *delivery.ReceiptRecordRequest) { r.Provider = "UPPER" },
		func(r *delivery.ReceiptRecordRequest) { r.Provider = strings.Repeat("x", 65) },
		func(r *delivery.ReceiptRecordRequest) { r.ProviderEventID = strings.Repeat("x", 257) },
		func(r *delivery.ReceiptRecordRequest) { r.ProviderEventID = "event\n" },
		func(r *delivery.ReceiptRecordRequest) { r.Generation = 0 },
		func(r *delivery.ReceiptRecordRequest) { r.Status = delivery.StateQueued },
		func(r *delivery.ReceiptRecordRequest) { r.Status = delivery.StateTransientFailure },
		func(r *delivery.ReceiptRecordRequest) { r.ObservedAt = time.Time{} },
		func(r *delivery.ReceiptRecordRequest) { r.ObservedAt = now.In(time.FixedZone("offset", 3600)) },
		func(r *delivery.ReceiptRecordRequest) { r.IdempotencyKey = "short" },
	}
	for n, mutate := range bad {
		evidence := validReceipt(now)
		mutate(&evidence)
		got, err := delivery.DecideReceipt(delivery.ReceiptSnapshot{State: delivery.StateOutcomeUnknown, Generation: 2}, evidence)
		if !errors.Is(evidence.Validate(), delivery.ErrInvalidInput) || !errors.Is(err, delivery.ErrInvalidInput) || got != (delivery.ReceiptDecision{}) {
			t.Fatal("invalid receipt admitted", n, got, err)
		}
	}
	for _, current := range []delivery.ReceiptSnapshot{{}, {State: delivery.StateTransientFailure, Generation: 2}, {State: delivery.StateOutcomeUnknown, Generation: 0}, {State: delivery.StateOutcomeUnknown, Generation: 2, ObservedAt: now.In(time.FixedZone("offset", 3600))}} {
		got, err := delivery.DecideReceipt(current, validReceipt(now))
		if !errors.Is(err, delivery.ErrInvalidInput) || got != (delivery.ReceiptDecision{}) {
			t.Fatal("invalid authoritative snapshot admitted", got, err)
		}
	}
}

func FuzzReceiptDecision(f *testing.F) {
	f.Add(uint8(delivery.StateOutcomeUnknown), uint8(delivery.StateDelivered), uint32(2), uint32(2), int64(1), "provider", "event")
	f.Add(uint8(delivery.StateDelivered), uint8(delivery.StateBounced), uint32(2), uint32(1), int64(-1), "provider", "event")
	f.Add(uint8(0), uint8(255), uint32(0), uint32(0), int64(0), "", "")
	f.Add(uint8(delivery.StateAttempting), uint8(delivery.StateDelivered), uint32(2), uint32(2), int64(-1), "provider", "event")
	f.Fuzz(func(t *testing.T, state, status uint8, actual, expected uint32, offset int64, provider, event string) {
		now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
		evidence := validReceipt(now.Add(time.Duration(offset%1000) * time.Second))
		evidence.Status = delivery.DeliveryState(status)
		evidence.Generation = expected
		evidence.Provider, evidence.ProviderEventID = provider, event
		current := delivery.ReceiptSnapshot{State: delivery.DeliveryState(state), Generation: actual, ObservedAt: now}
		got, err := delivery.DecideReceipt(current, evidence)
		if err != nil {
			if got != (delivery.ReceiptDecision{}) {
				t.Fatal("error leaked usable decision")
			}
			return
		}
		if actual != expected || actual == 0 || got.Advanced && (got.State == delivery.StateAttempting || got.State == delivery.StateRetryWait || got.State == delivery.StateQueued) {
			t.Fatal("receipt admitted stale generation or new send", got)
		}
		if got.Advanced != (got.State != current.State) {
			t.Fatal("incorrect state-change marker", got)
		}
	})
}
