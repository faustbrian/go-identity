package mfapostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOTPCompletionAttemptRequiresNativeLockedCustody(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context()} {
		locked, err := LockOTPCompletionAttempt(ctx, kernel.MFAOTPAttemptWork{}, nil)
		if err == nil || locked.custody != nil {
			t.Fatal("unowned OTP completion obtained shared-budget locks")
		}
		if RecordOTPCompletionAttemptDenial(ctx, kernel.MFAOTPAttemptWork{}, nil, locked) == nil {
			t.Fatal("unowned OTP completion charged shared budget")
		}
	}
	for _, value := range []any{LockedOTPCompletionAttempt{}} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("OTP shared-budget callback disclosed original custody")
		}
	}
}
