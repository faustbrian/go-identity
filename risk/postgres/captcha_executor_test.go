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

func TestCaptchaExecutorRejectsZeroAndProtectsDiagnostics(t *testing.T) {
	if _, err := NewCaptchaExecutor(CaptchaExecutorConfig{}); !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("zero composition admitted", err)
	}
	var executor CaptchaExecutor
	if _, err := executor.Resolve(context.Background(), risk.CaptchaEvidenceIntent{}); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("zero executor resolved", err)
	}
	if _, err := executor.Execute(context.Background(), risk.CaptchaEvidenceIssue{}); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("zero executor executed", err)
	}
	for _, value := range []any{executor, CaptchaExecutorConfig{Flow: risk.FlowContextInput{Session: "restricted-session"}}} {
		if strings.Contains(fmt.Sprintf("%#v", value), "restricted-session") {
			t.Fatal("flow disclosed in diagnostics")
		}
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("composition serialized", err)
		}
	}
}
