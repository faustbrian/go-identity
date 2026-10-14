package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOwnedRevokeSetRejectsMissingComposition(t *testing.T) {
	if executor, err := NewRevokeSetExecutor(nil, RevokeSetExecutorConfig{}); err == nil || executor != nil {
		t.Fatal("zero bulk executor accepted")
	}
	var executor *RevokeSetExecutor
	if result, err := executor.ExecuteRevokeSet(context.Background(), session.RevokeSetRequest{}); err == nil || result.Receipt.Outcome != identity.CommitOutcomeInvalid || result.RevokedCount != 0 {
		t.Fatal("zero bulk executor executed")
	}
	if service, err := NewSetRevocationService(nil, SetRevocationServiceConfig{}); err == nil || service != nil {
		t.Fatal("zero bulk service accepted")
	}
}
