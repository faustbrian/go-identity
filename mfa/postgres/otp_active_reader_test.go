package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestActiveOTPReadRequiresOwnedCurrentSessionCustody(t *testing.T) {
	for _, reader := range []*OTPFactorReader{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			snapshot, err := reader.ReadForStepUp(ctx, session.GetResult{Authenticated: true}, "AAAAAAAAAAAAAAAAAAAAAQ")
			if err == nil || snapshot.custody != nil {
				t.Fatal("structural authenticated flag produced active OTP custody")
			}
		}
	}
	if _, err := (OTPActiveFactorSnapshot{}).Metadata(); err == nil {
		t.Fatal("empty snapshot fabricated active OTP factor/session metadata")
	}
	if _, err := (OTPActiveFactorSnapshot{}).Recipient(); err == nil {
		t.Fatal("empty snapshot fabricated an active OTP destination")
	}
}
