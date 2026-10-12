package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestMFACompletionRecordCannotSubstituteProtectedTOTPTransition(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, _, _, err := mfapg.RequireRecordedTOTPCompletion(ctx, kernel.Work{}, nil, identity.Command{}, mfapg.LockedTOTPCompletion{}); err == nil {
			t.Fatal("scalar session data or zero work substituted recorded factor")
		}
	}
}
