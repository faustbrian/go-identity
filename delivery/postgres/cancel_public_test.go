package postgres

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

func TestCancellationReasonRetainsExactConfidentialIntent(t *testing.T) {
	r := CancelCommandRequest{Binding: identity.CommandBinding{ActorID: "actor", TenantID: "tenant", RecordID: "intent"}, ExpectedStatusVersion: 1, Request: delivery.CancelRequest{Reason: "synthetic-private-reason"}}
	key := [32]byte{1}
	want := cancellationReason(key, r)
	if want == ([32]byte{}) || cancellationReason(key, r) != want {
		t.Fatal("confidential cancellation intent not stable")
	}
	changed := []CancelCommandRequest{r, r, r, r}
	changed[0].Request.Reason += "changed"
	changed[1].ExpectedStatusVersion++
	changed[2].Request.ExpectedGeneration++
	changed[3].Binding.ActorID = "other-actor"
	for _, q := range changed {
		if cancellationReason(key, q) == want {
			t.Fatal("changed confidential intent retained original fingerprint")
		}
	}
	if cancellationReason([32]byte{2}, r) == want {
		t.Fatal("namespace key did not protect confidential intent")
	}
}

func TestCancellationScopeRejectsReservedAttributeOverrides(t *testing.T) {
	for index := range 4 {
		q := authorization.DecisionContext{}
		attrs := authorization.Attributes{"delivery.intent": authorization.StringValue("foreign")}
		switch index {
		case 0:
			q.Request.Subject.Attributes = attrs
		case 1:
			q.Request.Resource.Attributes = attrs
		case 2:
			q.Request.Environment.Attributes = attrs
		case 3:
			q.Request.Attributes = attrs
		}
		if _, err := cancellationScope(q, "intent"); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("caller overrode trusted cancellation target", err)
		}
	}
	q := authorization.DecisionContext{Request: authorization.Request{Resource: authorization.Resource{Attributes: authorization.Attributes{"existing": authorization.StringValue("safe")}}}}
	owned, err := cancellationScope(q, "intent")
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := owned.Request.Resource.Attributes["delivery.intent"].String(); value != "intent" || len(q.Request.Resource.Attributes) != 1 {
		t.Fatal("owned target not bound or caller map mutated")
	}
}
