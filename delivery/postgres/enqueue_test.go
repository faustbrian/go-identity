package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestNativeEnqueuePreparationBoundsAndCancellation(t *testing.T) {
	c, _, b, input := publicStagingFixture(t)
	op := deliverypostgres.EnqueueOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	for _, field := range []string{"tenant", "command"} {
		t.Run(field, func(t *testing.T) {
			bad := b
			if field == "tenant" {
				bad.TenantID = identity.TenantID(strings.Repeat("x", 65536))
			} else {
				bad.CommandID = identity.CommandID(strings.Repeat("x", 65536))
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := c.PrepareEnqueue(ctx, bad, []deliverypostgres.IntentInput{input}); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled preparation inspected malformed binding", err)
			}
			if _, err := c.PrepareEnqueue(context.Background(), bad, []deliverypostgres.IntentInput{input}); !errors.Is(err, delivery.ErrInvalidInput) {
				t.Fatal("oversized binding admitted", err)
			}
		})
	}
}

func TestNativeEnqueueFreezesEveryPreparedEffect(t *testing.T) {
	c, _, b, input := publicStagingFixture(t)
	op := deliverypostgres.EnqueueOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	second := input
	second.EffectIndex = 9
	prepared, err := c.PrepareEnqueue(context.Background(), b, []deliverypostgres.IntentInput{input, second})
	if err != nil {
		t.Fatal(err)
	}
	command, err := prepared.EnqueueCommand()
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := command.Feature()
	plan, err := prepared.Plan()
	if err != nil || !ok || spec.Operation != op || len(spec.Fields) != 16 || spec.Binding.RecordID != plan.Intents[0].EffectID {
		t.Fatal("native command omitted the primary record/effects", err)
	}
	for n, field := range []identity.FeatureField{spec.Fields[0], spec.Fields[8]} {
		if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 || [32]byte(field.Value.Bytes) != plan.Intents[n].IntentDigest {
			t.Fatal("native command did not retain confidential logical identity")
		}
	}
	spec.Fields[0].Value.Bytes[0] ^= 1
	again, _ := command.Feature()
	if [32]byte(again.Fields[0].Value.Bytes) != plan.Intents[0].IntentDigest {
		t.Fatal("caller altered retained command")
	}
	native, err := deliverypostgres.NewEnqueueContributor(c)
	if err != nil {
		t.Fatal(err)
	}
	var phase identitypostgres.FeatureExecutionContributor = native
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := phase.ApplyFeature(cancelled, identitypostgres.Work{}, command); !errors.Is(err, context.Canceled) {
		t.Fatal("native phase lost caller cancellation", err)
	}
	if _, err := phase.ApplyFeature(context.Background(), identitypostgres.Work{}, command); err == nil {
		t.Fatal("zero Work granted enqueue phase authority")
	}
	if phase.Descriptor() == c.Descriptor() || len(phase.FeatureOperations()) != 1 || phase.FeatureOperations()[0] != op {
		t.Fatal("native execution duplicated encrypted-effect phase identity")
	}
	var zero deliverypostgres.PreparedDelivery
	if _, err := zero.EnqueueCommand(); err == nil {
		t.Fatal("zero custody created native command")
	}
	if _, err := deliverypostgres.NewEnqueueContributor(nil); err == nil {
		t.Fatal("nil custody owner registered")
	}
	b.RecordID = "caller-selected"
	if _, err := c.PrepareEnqueue(context.Background(), b, []deliverypostgres.IntentInput{input}); err == nil {
		t.Fatal("caller-selected primary record admitted")
	}
}
