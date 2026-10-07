package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestVelocityReplayZeroAndRedaction(t *testing.T) {
	var recovery VelocityRecovery
	if page, err := recovery.ReadPage(context.Background(), VelocityRecoveryLease{}, VelocityReplayCursor{}, 1); err == nil || page.state != nil {
		t.Fatal("zero accepted")
	}
	var page VelocityReplayPage
	if page.Records() != nil || page.Next().state != nil || (VelocityReplayRecord{}).Projection().ID != "" {
		t.Fatal("zero exposed state")
	}
	for _, value := range []any{VelocityReplayProjection{ID: "secret-identity"}, VelocityReplayRecord{state: &velocityReplayRecord{projection: VelocityReplayProjection{ID: "secret-identity"}}}, VelocityReplayCursor{}, page} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("sensitive replay serializable")
		}
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") || strings.Contains(fmt.Sprintf("%#v", value), "secret-identity") {
			t.Fatal("replay diagnostics disclosed history")
		}
	}
}

// PG-COPY-01/PG-SECRET-01: projections never mutate retained history or grant
// serializable custody, including the newly available original keyed facts.
func TestVelocityReplayOriginalBindingCopy(t *testing.T) {
	original := VelocityReplayProjection{Tenant: "private-tenant", Namespace: [32]byte{1}, AttemptDigest: [32]byte{2}, Fingerprint: strings.Repeat("a", 64)}
	record := VelocityReplayRecord{state: &velocityReplayRecord{projection: original}}
	copy := record.Projection()
	copy.Namespace[0] ^= 1
	copy.AttemptDigest[0] ^= 1
	copy.Fingerprint = "changed"
	copy.Tenant = "changed"
	got := record.Projection()
	if got.Tenant != original.Tenant || got.Namespace != original.Namespace || got.AttemptDigest != original.AttemptDigest || got.Fingerprint != original.Fingerprint {
		t.Fatal("projection mutated original replay identity")
	}
	zero := (VelocityReplayRecord{}).Projection()
	if zero.Tenant != "" || zero.Namespace != [32]byte{} || zero.AttemptDigest != [32]byte{} || zero.Fingerprint != "" {
		t.Fatal("zero exposed original binding")
	}
	for _, value := range []any{original, record} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("serialized original binding")
		}
		if text := fmt.Sprintf("%#v", value); !strings.Contains(text, "redacted") || strings.Contains(text, original.Tenant) || strings.Contains(text, original.Fingerprint) {
			t.Fatal("original binding in diagnostics")
		}
	}
}
