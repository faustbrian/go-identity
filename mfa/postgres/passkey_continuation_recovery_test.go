package mfapostgres

import (
	"context"
	"errors"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasskeyContinuationRecoveryRequiresOriginalWork(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		status, err := RecoverPasskeyContinuation(ctx, kernel.RecoveryWork{}, nil)
		if err == nil || status != kernel.RecoveryUnknown {
			t.Fatal("unowned recovery classified a historical effect")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := RecoverPasskeyContinuation(ctx, kernel.RecoveryWork{}, nil)
	if status != kernel.RecoveryUnknown || !errors.Is(err, context.Canceled) {
		t.Fatal("recovery lost cancellation or produced outcome evidence", err)
	}
}
