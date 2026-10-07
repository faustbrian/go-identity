package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func checkpointFixture(t testing.TB, noOp bool) (*Contributor, PreparedDelivery, payloadBinding, payload) {
	t.Helper()
	codec, b, message := custodyFixture(t)
	b.NoOpEquivalent = noOp
	b.Intent.EffectID = deliveryEffectID(b.Deployment, b.Command, b.Intent.EffectIndex)
	bound, v, err := codec.seal(context.Background(), b, message, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	store, err := newIntentStore(b.Deployment, codec, map[uint64]providerProfile{1: {name: b.Provider, policyVersion: b.PolicyVersion}})
	if err != nil {
		t.Fatal(err)
	}
	c := &Contributor{store: store, current: 1, envelopeKey: "envelope-a"}
	id, err := identity.ParseIdentifierID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatal(err)
	}
	p := PreparedDelivery{state: &preparedDelivery{owner: c, binding: b.Command, plan: identitypostgres.DeliveryPlan{Contributor: c.Descriptor(), Intents: []identitypostgres.DeliveryIntentPlan{bound.Intent}}, envelopes: []identitypostgres.DeliveryEnvelope{v}, recipients: []recipientFence{{id: id, version: 2, authority: 3}}}}
	return c, p, bound, message
}

func FuzzPreparationCheckpoint(f *testing.F) {
	c, p, b, _ := checkpointFixture(f, false)
	wire, err := c.CheckpointPreparation(context.Background(), p, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte("IDDP1"))
	f.Fuzz(func(t *testing.T, input []byte) {
		r, err := c.RestorePreparation(context.Background(), b.Command, 1, input)
		if err != nil {
			if r.state != nil {
				t.Fatal("failed parse exposed usable prefix")
			}
			return
		}
		again, err := c.CheckpointPreparation(context.Background(), r, 1)
		if err != nil || !bytes.Equal(again, input) {
			t.Fatal("accepted noncanonical custody", err)
		}
	})
}

func TestPreparationCheckpointConservesPayloadAndFences(t *testing.T) {
	for _, noOp := range []bool{false, true} {
		c, p, b, message := checkpointFixture(t, noOp)
		wire, err := c.CheckpointPreparation(context.Background(), p, 1)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.RestorePreparation(context.Background(), b.Command, 1, wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.state.recipients, r.state.recipients) || !reflect.DeepEqual(p.state.envelopes, r.state.envelopes) {
			t.Fatal("restart lost original fences or encrypted payload")
		}
		got, err := c.store.codec.open(context.Background(), b, r.state.envelopes[0])
		if err != nil || !reflect.DeepEqual(got, message) {
			t.Fatal("original queued plaintext changed", err)
		}
		// Caller storage changes cannot mutate restored custody.
		clear(wire)
		if !bytes.Equal(p.state.envelopes[0].Ciphertext, r.state.envelopes[0].Ciphertext) {
			t.Fatal("restored ciphertext aliases caller storage")
		}
	}
}

func TestPreparationCheckpointAuthenticatedMalformedFrames(t *testing.T) {
	c, p, b, _ := checkpointFixture(t, false)
	wire, err := c.CheckpointPreparation(context.Background(), p, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func([]byte) []byte{
		func(v []byte) []byte { binary.BigEndian.PutUint16(v[17:19], 17); return v },
		func(v []byte) []byte { binary.BigEndian.PutUint32(v[19:23], ^uint32(0)); return v },
		func(v []byte) []byte { return append(v, 0) },
		func(v []byte) []byte { return v[:len(v)-1] },
		func(v []byte) []byte { binary.BigEndian.PutUint16(v[len(v)-2-4-26-16:], 17); return v },
		func(v []byte) []byte { clear(v[len(v)-16 : len(v)-8]); return v },
	} {
		body := change(bytes.Clone(wire[:len(wire)-32]))
		mac := custodyMAC(c.store.codec.keys[1], "identity-delivery-preparation-v1", []byte(c.store.deployment), body)
		if r, err := c.RestorePreparation(context.Background(), b.Command, 1, append(body, mac[:]...)); err == nil || r.state != nil {
			t.Fatal("authenticated malformed checkpoint restored")
		}
	}
}
