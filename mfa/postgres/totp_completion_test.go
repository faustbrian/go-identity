package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestTOTPCompletionRequiresExactProtectedCustody(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := LockTOTPCompletion(ctx, kernel.Work{}, nil, identity.Command{}, TOTPFactorSnapshot{}); err == nil {
			t.Fatal("zero protected work admitted completion")
		}
		if err := RecordTOTPCompletion(ctx, kernel.Work{}, nil, LockedTOTPCompletion{}, 0); err == nil {
			t.Fatal("scalar counter became completion authority")
		}
	}
	if _, _, err := (LockedTOTPCompletion{}).VerificationState(); err == nil {
		t.Fatal("zero completion exposed factor state")
	}
}
