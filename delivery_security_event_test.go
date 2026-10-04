package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func TestDeliverySecurityEventPreservesWorkerAttribution(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	builder, err := NewIdentitySecurityEventV1(testWall(now))
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	input := DeliverySecurityEventInput{Transition: DeliverySecurityAttempt, OccurredAt: now,
		TenantID: "tenant-a", IntentID: strings.Repeat("a", 64), CommandID: id,
		WorkerActorID: "worker-service", CorrelationID: "worker-correlation", PolicyID: "policy",
		PolicyVersion: 3, ProviderVersion: 5, BeforeVersion: 1, AfterVersion: 2}
	for _, item := range []struct {
		transition     DeliverySecurityTransition
		action, result string
	}{
		{DeliverySecurityAttempt, "identity.delivery.attempt", ""},
		{DeliverySecurityAccepted, "identity.delivery.attempt", "accepted"},
		{DeliverySecurityConfirmed, "identity.delivery.confirm", "accepted"},
		{DeliverySecurityRejected, "identity.delivery.reject", "denied"},
		{DeliverySecurityRetry, "identity.delivery.attempt", "unavailable"},
		{DeliverySecurityUnknown, "identity.delivery.mark_unknown", "ambiguous"},
		{DeliverySecurityLeaseLost, "identity.delivery.mark_unknown", ""},
		{DeliverySecurityCancelled, "identity.delivery.cancel", ""},
		{DeliverySecurityExpired, "identity.delivery.attempt", ""},
		{DeliverySecurityExhausted, "identity.delivery.attempt", ""},
		{DeliverySecurityPayloadErased, "identity.delivery.attempt", ""},
		{DeliverySecurityReleased, "identity.delivery.attempt", ""},
	} {
		input.Transition = item.transition
		r, err := builder.BuildDelivery(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := audit.CanonicalJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		attrs := parsed.Attributes()
		if parsed.Action() != item.action || parsed.Outcome() != audit.OutcomeSucceeded || parsed.Actor().Kind() != audit.ActorSystem || parsed.Actor().ID() != "worker-service" || parsed.Subject().Type() != "delivery_intent" || parsed.Subject().ID() != input.IntentID || parsed.Policy().Version != "3" || parsed.Context().TenantID() != "tenant-a" || parsed.Context().CausationID() != string(id) || attrs["command.id"] != string(id) || attrs["retention.class"] != "protected" || attrs["aggregate.before_version"] != "1" || attrs["aggregate.after_version"] != "2" || attrs["provider.version"] != "5" || attrs["provider.result"] != item.result || !r.RedactionApplied() || !parsed.Changes().Redacted() {
			t.Fatal("protected worker attribution changed")
		}
	}
	for _, change := range []func(*DeliverySecurityEventInput){
		func(i *DeliverySecurityEventInput) { i.Transition = 255 },
		func(i *DeliverySecurityEventInput) { i.WorkerActorID = "private@example.test" },
		func(i *DeliverySecurityEventInput) { i.IntentID = "plaintext@example.test" },
		func(i *DeliverySecurityEventInput) { i.CommandID = "" },
		func(i *DeliverySecurityEventInput) { i.ProviderVersion = 0 },
		func(i *DeliverySecurityEventInput) { i.PolicyVersion = 0 },
		func(i *DeliverySecurityEventInput) { i.AfterVersion = i.BeforeVersion },
		func(i *DeliverySecurityEventInput) { i.BeforeVersion = ^uint64(0) },
	} {
		bad := input
		change(&bad)
		if _, err := builder.BuildDelivery(context.Background(), bad); !errors.Is(err, ErrInvalidSecurityEvent) {
			t.Fatal("unsafe delivery audit accepted", err)
		}
	}
}
