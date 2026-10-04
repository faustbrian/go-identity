package postgres

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/delivery"
)

func TestDeliveryStatusConservesDurableAndEffectiveStates(t *testing.T) {
	accepted, bounced := int16(delivery.StateAccepted), int16(delivery.StateBounced)
	for _, tc := range []struct {
		name     string
		snapshot deliveryStatus
		result   delivery.StatusGetResult
	}{
		{"queued", deliveryStatus{state: "planned"}, delivery.StatusGetResult{State: delivery.StateQueued}},
		{"queued-expired", deliveryStatus{state: "planned", expired: true}, delivery.StatusGetResult{State: delivery.StateExpired, Terminal: true}},
		{"noop", deliveryStatus{state: "cancelled", noop: true}, delivery.StatusGetResult{State: delivery.StateQueued}},
		{"noop-expired", deliveryStatus{state: "cancelled", noop: true, expired: true}, delivery.StatusGetResult{State: delivery.StateExpired, Terminal: true}},
		{"attempting", deliveryStatus{state: "submitted", generation: 1, live: true}, delivery.StatusGetResult{State: delivery.StateAttempting, AttemptGeneration: 1}},
		{"lost-lease", deliveryStatus{state: "submitted", generation: 1}, delivery.StatusGetResult{State: delivery.StateOutcomeUnknown, AttemptGeneration: 1}},
		{"accepted", deliveryStatus{state: "submitted", generation: 1, outcome: &accepted, reference: true}, delivery.StatusGetResult{State: delivery.StateAccepted, AttemptGeneration: 1, ProviderReferencePresent: true}},
		{"retry-wait", deliveryStatus{state: "retry-wait", generation: 1}, delivery.StatusGetResult{State: delivery.StateRetryWait, AttemptGeneration: 1}},
		{"retry-expired", deliveryStatus{state: "retry-wait", generation: 1, expired: true}, delivery.StatusGetResult{State: delivery.StateExpired, AttemptGeneration: 1, Terminal: true}},
		{"unknown", deliveryStatus{state: "outcome-unknown", generation: 1}, delivery.StatusGetResult{State: delivery.StateOutcomeUnknown, AttemptGeneration: 1}},
		{"delivered", deliveryStatus{state: "confirmed", generation: 1}, delivery.StatusGetResult{State: delivery.StateDelivered, AttemptGeneration: 1, Terminal: true}},
		{"rejected", deliveryStatus{state: "rejected", generation: 1}, delivery.StatusGetResult{State: delivery.StateRejected, AttemptGeneration: 1, Terminal: true}},
		{"bounced", deliveryStatus{state: "rejected", generation: 1, outcome: &bounced}, delivery.StatusGetResult{State: delivery.StateBounced, AttemptGeneration: 1, Terminal: true}},
		{"cancelled", deliveryStatus{state: "cancelled"}, delivery.StatusGetResult{State: delivery.StateCancelled, Terminal: true}},
		{"expired", deliveryStatus{state: "expired"}, delivery.StatusGetResult{State: delivery.StateExpired, Terminal: true}},
		{"exhausted", deliveryStatus{state: "exhausted", generation: 4294967295}, delivery.StatusGetResult{State: delivery.StateExhausted, AttemptGeneration: 4294967295, Terminal: true}},
		{"superseded", deliveryStatus{state: "superseded"}, delivery.StatusGetResult{State: delivery.StateSuperseded, Terminal: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.snapshot.result()
			if err != nil || got != tc.result {
				t.Fatal("durable status changed meaning", err, got)
			}
		})
	}
}

func TestDeliveryStatusRejectsUnattributableMetadata(t *testing.T) {
	rejected := int16(delivery.StateRejected)
	for _, snapshot := range []deliveryStatus{
		{}, {state: "unsupported"}, {state: "planned", generation: -1}, {state: "planned", generation: 4294967296},
		{state: "planned", generation: 1}, {state: "planned", outcome: &rejected}, {state: "planned", live: true}, {state: "planned", reference: true},
		{state: "planned", noop: true}, {state: "cancelled", noop: true, generation: 1}, {state: "cancelled", noop: true, outcome: &rejected},
		{state: "cancelled", noop: true, live: true}, {state: "cancelled", noop: true, reference: true},
		{state: "submitted"}, {state: "submitted", generation: 1, outcome: &rejected}, {state: "submitted", generation: 1, outcome: &rejected, live: true},
	} {
		got, err := snapshot.result()
		if !errors.Is(err, delivery.ErrUnavailable) || got != (delivery.StatusGetResult{}) {
			t.Fatal("unattributable metadata fabricated status", err)
		}
	}
}
