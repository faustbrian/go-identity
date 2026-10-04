//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestPersistedCustodyRestoresAfterRestart(t *testing.T) {
	ctx, pool := intentDatabase(t)
	s, original := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, original)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{original}, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit failed")
	}
	// A new codec has no original in-memory command or prepared-intent holder.
	// Only retained keys and committed database bytes survive restart/rotation.
	restarted, err := newPayloadCodec(s.codec.service, map[uint32][32]byte{1: {3}, 2: {4}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var aad []byte
	var envelope identitypostgres.DeliveryEnvelope
	if err := pool.QueryRow(ctx, `SELECT binding_aad,effect_index,envelope_key_id,ciphertext FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, original.binding.Deployment, string(original.binding.Command.TenantID), original.binding.Intent.EffectID).Scan(&aad, &envelope.EffectIndex, &envelope.KeyID, &envelope.Ciphertext); err != nil {
		t.Fatal("persisted custody read failed")
	}
	// Authentication is local; it must not depend on decrypting while locked.
	service := restarted.service
	restarted.service = nil
	b, err := restarted.restore(aad, envelope)
	if err != nil || !reflect.DeepEqual(b, original.binding) {
		t.Fatal("committed original binding not restored", err)
	}
	restarted.service = service
	got, err := restarted.open(ctx, b, envelope)
	if err != nil {
		t.Fatal("committed payload not restored", err)
	}
	want, err := s.codec.open(context.Background(), original.binding, original.envelope)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("restored payload changed")
	}
	changed := bytes.Clone(aad)
	position := bytes.Index(changed, []byte("tenant-a"))
	if position < 0 {
		t.Fatal("tenant fixture absent")
	}
	changed[position] = 'x'
	if _, err := restarted.restore(changed, envelope); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("changed persisted scope authenticated", err)
	}
}
