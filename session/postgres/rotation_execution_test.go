package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestRotationExecutorRejectsZeroCompositionAndRequest(t *testing.T) {
	if _, err := NewRotationExecutor(nil, RotationExecutorConfig{}); err == nil {
		t.Fatal("zero config admitted")
	}
	for _, executor := range []*RotationExecutor{nil, {}} {
		if out, err := executor.ExecuteRotation(context.Background(), session.RotationRequest{}); err == nil || out.Session != (session.Session{}) || out.Receipt.Binding.CommandID != "" {
			t.Fatal("zero execution admitted")
		}
		if out, err := executor.RecoverRotation(context.Background(), session.RotationRequest{}); err == nil || out.Session != (session.Session{}) || out.Receipt.Binding.CommandID != "" {
			t.Fatal("zero recovery admitted")
		}
		if out, err := executor.RecoverRotationCommand(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || out.Binding.CommandID != "" || out.Feature != nil {
			t.Fatal("zero restart recovery admitted")
		}
	}
	for _, value := range []any{RotationExecutor{}, RotationExecutorConfig{Execution: IssueExecutorConfig{PolicyID: "private-policy"}}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("runtime configuration exported")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), "private-policy") {
			t.Fatal("runtime configuration diagnostic leaked")
		}
	}
}
