package mfapostgres

import (
	"context"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestTOTPAttemptRequiresNativeLiveCustody(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := LockTOTPAttempt(ctx, kernel.MFATOTPAttemptWork{}, nil, TOTPFactorSnapshot{}); err == nil {
			t.Fatal("zero or foreign work locked factor authority")
		}
		if err := RecordTOTPAttemptDenial(ctx, kernel.MFATOTPAttemptWork{}, nil, LockedTOTPAttempt{}); err == nil {
			t.Fatal("zero attempt spent continuation budget")
		}
		if err := RecordMissingTOTPAttemptDenial(ctx, kernel.MFATOTPAttemptWork{}, nil, "AgICAgICAgICAgICAgICAg"); err == nil {
			t.Fatal("zero attempt charged a missing factor")
		}
	}
	if _, _, err := (LockedTOTPAttempt{}).VerificationState(); err == nil {
		t.Fatal("zero attempt disclosed verification state")
	}
}
