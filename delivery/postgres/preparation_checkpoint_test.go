package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func TestPreparationCheckpointRestoresOriginalEncryptedEffect(t *testing.T) {
	c, config, binding, input := publicStagingFixture(t)
	prepared, err := c.Prepare(context.Background(), binding, []deliverypostgres.IntentInput{input})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.CheckpointPreparation(context.Background(), prepared, 7)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(input.Rendered.Body)) || bytes.Contains(wire, []byte(input.Recipient.Address)) {
		t.Fatal("checkpoint exposed plaintext")
	}
	// A new service/contributor models process restart, not reuse of opaque memory.
	provider, err := keyring.New(map[string][]byte{"envelope-a": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := deliverypostgres.NewContributor(config, service)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := fresh.RestorePreparation(context.Background(), binding, 7, wire)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := prepared.Plan()
	after, err := restored.Plan()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("restart changed original plan", err)
	}
	// Exact ciphertext identity must survive; no resealing or refreshed expiry.
	again, err := fresh.CheckpointPreparation(context.Background(), restored, 7)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("restart changed original custody", err)
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[0] ^= 1 },
		func(b []byte) { b[len(b)/2] ^= 1 },
		func(b []byte) { b[len(b)-1] ^= 1 },
	} {
		bad := bytes.Clone(wire)
		change(bad)
		if _, err := fresh.RestorePreparation(context.Background(), binding, 7, bad); err == nil {
			t.Fatal("corrupt custody restored")
		}
	}
	if _, err := fresh.RestorePreparation(context.Background(), binding, 8, wire); err == nil {
		t.Fatal("changed original generation accepted")
	}
	other := binding
	other.TenantID = "other-tenant"
	if _, err := fresh.RestorePreparation(context.Background(), other, 7, wire); err == nil {
		t.Fatal("cross-tenant custody restored")
	}
	for _, change := range []func(){
		func() { other = binding; other.ActorID = "other-actor" },
		func() { other = binding; other.OperationID = "identity.user.update" },
		func() { other = binding; other.PolicyVersion++ },
		func() { other = binding; other.RecordID = "other-record" },
	} {
		change()
		if _, err := fresh.RestorePreparation(context.Background(), other, 7, wire); err == nil {
			t.Fatal("changed command binding accepted")
		}
	}
	foreignConfig := config
	foreignConfig.Deployment = "foreign"
	foreign, err := deliverypostgres.NewContributor(foreignConfig, service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.RestorePreparation(context.Background(), binding, 7, wire); err == nil {
		t.Fatal("cross-deployment custody restored")
	}
	if _, err := fresh.CheckpointPreparation(context.Background(), restored, 8); err == nil {
		t.Fatal("restored provenance was rewritten")
	}
	for n := 0; n < len(wire); n++ {
		if _, err := fresh.RestorePreparation(context.Background(), binding, 7, wire[:n]); err == nil {
			t.Fatal("truncated custody restored")
		}
	}
	config.CurrentDigestKeyVersion = 2
	config.RetainedDigestKeys[2] = [32]byte{4}
	rotated, err := deliverypostgres.NewContributor(config, service)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rotated.RestorePreparation(context.Background(), binding, 7, wire)
	if err != nil {
		t.Fatal("retained key unavailable after rotation", err)
	}
	again, err = rotated.CheckpointPreparation(context.Background(), r, 7)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("active key rotation changed checkpoint", err)
	}
	config.ProviderProfiles[1] = deliverypostgres.ProviderProfile{Provider: "changed", PolicyVersion: 2}
	changed, _ := deliverypostgres.NewContributor(config, service)
	if _, err := changed.RestorePreparation(context.Background(), binding, 7, wire); err == nil {
		t.Fatal("changed retained provider profile accepted")
	}
	config.ProviderProfiles[1] = deliverypostgres.ProviderProfile{Provider: "test-provider", PolicyVersion: 1}
	delete(config.RetainedDigestKeys, 1)
	missing, _ := deliverypostgres.NewContributor(config, service)
	if _, err := missing.RestorePreparation(context.Background(), binding, 7, wire); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing retained key did not fail closed", err)
	}
}

func TestPreparationCheckpointConcurrentGenerationAndCancellation(t *testing.T) {
	c, _, b, input := publicStagingFixture(t)
	p, err := c.Prepare(context.Background(), b, []deliverypostgres.IntentInput{input})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CheckpointPreparation(ctx, p, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled checkpoint accepted", err)
	}
	var group sync.WaitGroup
	results := make(chan uint64, 16)
	for i := uint64(1); i <= 16; i++ {
		group.Add(1)
		go func(g uint64) {
			defer group.Done()
			if _, err := c.CheckpointPreparation(context.Background(), p, g); err == nil {
				results <- g
			}
		}(i)
	}
	group.Wait()
	close(results)
	var winner uint64
	for g := range results {
		if winner != 0 && winner != g {
			t.Fatal("copies fixed conflicting original generations")
		}
		winner = g
	}
	if winner == 0 {
		t.Fatal("no generation selected")
	}
	wire, err := c.CheckpointPreparation(context.Background(), p, winner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestorePreparation(ctx, b, winner, wire); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled restore accepted", err)
	}
	if _, err := c.CheckpointPreparation(nil, p, winner); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := c.CheckpointPreparation(context.Background(), deliverypostgres.PreparedDelivery{}, 1); err == nil {
		t.Fatal("zero preparation accepted")
	}
	if _, err := c.RestorePreparation(nil, b, winner, wire); err == nil {
		t.Fatal("nil restore context accepted")
	}
	if _, err := c.RestorePreparation(context.Background(), b, 0, wire); err == nil {
		t.Fatal("zero provenance accepted")
	}
}
