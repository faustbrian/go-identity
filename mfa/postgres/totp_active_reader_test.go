package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestActiveTOTPReadRequiresOwnedCurrentSessionCustody(t *testing.T) {
	for _, reader := range []*TOTPFactorReader{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			snapshot, err := reader.ReadForStepUp(ctx, session.GetResult{Authenticated: true}, "AAAAAAAAAAAAAAAAAAAAAQ")
			if err == nil || snapshot.custody != nil {
				t.Fatal("structural authenticated flag produced active factor custody")
			}
		}
	}
	if _, err := (TOTPActiveFactorSnapshot{}).Metadata(); err == nil {
		t.Fatal("empty snapshot fabricated factor/session metadata")
	}
}
