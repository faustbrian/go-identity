package postgres

import (
	"context"
	"testing"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestIntentPreparationAuthenticatesFrozenOriginalScope(t *testing.T) {
	codec, b, payload := custodyFixture(t)
	s, err := newIntentStore("test", codec, map[uint64]providerProfile{1: {name: "test-provider", policyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	b.Intent.EffectID = deliveryEffectID(b.Deployment, b.Command, b.Intent.EffectIndex)
	frozen, first, err := codec.seal(context.Background(), b, payload, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	plan := identitypostgres.DeliveryPlan{Contributor: s.Descriptor(), Intents: []identitypostgres.DeliveryIntentPlan{frozen.Intent}}
	if err := s.ValidateDeliveryPlan(b.Command, plan); err != nil {
		t.Fatal(err)
	}
	prepared, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{first})
	if err != nil || len(prepared) != 1 || prepared[0].binding.NoOpEquivalent {
		t.Fatal("owned preparation", err)
	}
	_, randomized, err := codec.seal(context.Background(), b, payload, "envelope-b")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{randomized})
	if err != nil || string(prepared[0].aad) != string(again[0].aad) {
		t.Fatal("randomness changed logical admission", err)
	}
	// Persistence validation must not decrypt or invoke the key provider.
	codec.service = nil
	if _, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{first}); err != nil {
		t.Fatal(err)
	}
	changed := b.Command
	changed.ActorID = "other-actor"
	if _, err := s.prepare(changed, plan, []identitypostgres.DeliveryEnvelope{first}); err == nil {
		t.Fatal("foreign actor admitted")
	}
	plan.Intents[0].EffectID = "caller-selected"
	if err := s.ValidateDeliveryPlan(b.Command, plan); err == nil {
		t.Fatal("caller effect identity admitted")
	}
}

func TestIntentPreparationPreservesAuthenticatedNoOp(t *testing.T) {
	codec, b, payload := custodyFixture(t)
	b.NoOpEquivalent = true
	b.Intent.EffectID = deliveryEffectID(b.Deployment, b.Command, b.Intent.EffectIndex)
	frozen, envelope, err := codec.seal(context.Background(), b, payload, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[uint64]providerProfile{1: {name: "test-provider", policyVersion: 1}}
	s, err := newIntentStore("test", codec, profiles)
	if err != nil {
		t.Fatal(err)
	}
	profiles[1] = providerProfile{name: "other", policyVersion: 9}
	plan := identitypostgres.DeliveryPlan{Contributor: s.Descriptor(), Intents: []identitypostgres.DeliveryIntentPlan{frozen.Intent}}
	prepared, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{envelope})
	if err != nil || len(prepared) != 1 || !prepared[0].binding.NoOpEquivalent {
		t.Fatal("lost authenticated no-op", err)
	}
	envelope.Ciphertext[9] ^= 1
	if _, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{envelope}); err == nil {
		t.Fatal("tampered custody admitted")
	}
	if _, err := s.prepare(b.Command, plan, nil); err == nil {
		t.Fatal("missing custody admitted")
	}
}
