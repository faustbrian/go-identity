package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMFAConsumedPreAuthRequiresOriginalNativeCustody(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := RequireMFAConsumedPreAuth(ctx, kernel.Work{}, nil, identity.Command{}, Config{Schema: "session_store", MaximumDuration: time.Second}, session.PreAuthTransaction{}, "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned browser metadata admitted MFA")
		}
		if err := RequireMFAConsumedPreAuthAttempt(ctx, kernel.MFATOTPAttemptWork{}, nil, Config{Schema: "session_store", MaximumDuration: time.Second}, session.PreAuthTransaction{}, "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned counted attempt admitted browser metadata")
		}
	}
}
