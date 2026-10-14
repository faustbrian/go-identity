package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestExecutorRejectsInvalidCompositionAndZeroUse(t *testing.T) {
	if _, err := NewExecutor(ExecutorConfig{}); !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("zero composition admitted", err)
	}
	var executor Executor
	if _, err := executor.Resolve(context.Background(), risk.EvidenceIntent{}); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("zero executor resolved", err)
	}
	if _, err := executor.Execute(context.Background(), risk.EvidenceIssue{}); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("zero executor executed", err)
	}
}

func TestExecutorDiagnosticsCannotExposeTrustedComposition(t *testing.T) {
	for _, value := range []any{Executor{}, ExecutorConfig{PolicyID: "private-policy"}} {
		if strings.Contains(fmt.Sprintf("%#v", value), "private-policy") {
			t.Fatal("trusted policy exposed")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("runtime composition serialized")
		}
	}
	if _, err := (Executor{}).MarshalText(); err == nil {
		t.Fatal("executor text serialization")
	}
	if _, err := (ExecutorConfig{}).MarshalText(); err == nil {
		t.Fatal("executor configuration text serialization")
	}
}
