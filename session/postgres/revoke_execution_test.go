package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOwnedRevokeExecutorRejectsMissingComposition(t *testing.T) {
	if executor, err := NewRevokeOneExecutor(nil, RevokeOneExecutorConfig{}); err == nil || executor != nil {
		t.Fatal("zero composition accepted")
	}
	var executor *RevokeOneExecutor
	if result, err := executor.ExecuteRevokeOne(context.Background(), session.RevokeOneRequest{}); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero executor executed")
	}
}
