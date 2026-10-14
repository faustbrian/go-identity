package mfapostgres

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOTPCompletionCannotUseAbsentOrReturnedCustody(t *testing.T) {
	for _, locked := range []LockedOTPCompletion{{}, {custody: func() *lockedOTPCompletion { return nil }}, {custody: func() *lockedOTPCompletion { return &lockedOTPCompletion{} }}} {
		if _, _, err := locked.VerificationState(); err == nil {
			t.Fatal("absent/returned custody became successful OTP state")
		}
		if err := RecordOTPCompletion(t.Context(), kernel.Work{}, nil, identity.Command{}, locked); err == nil {
			t.Fatal("absent/returned custody completed a child")
		}
		if _, _, _, err := RequireRecordedOTPCompletion(t.Context(), kernel.Work{}, nil, identity.Command{}, locked); err == nil {
			t.Fatal("absent/returned custody supplied recorded authentication")
		}
		if _, err := json.Marshal(locked); err == nil {
			t.Fatal("native OTP completion custody was serialized")
		}
		if !strings.Contains(fmt.Sprintf("%#v", locked), "redacted") {
			t.Fatal("native OTP completion custody was formatted")
		}
	}
}
