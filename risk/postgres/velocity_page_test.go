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
