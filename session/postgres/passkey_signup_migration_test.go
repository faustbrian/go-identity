package postgres

import (
	"context"
	"testing"
)

func TestPasskeySignupIssuanceMigrationRequiresSelectedHistory(t *testing.T) {
	valid := PasskeySignupMigrationSource{Schema: "session_store", Version: 72, PreviousConstraint: "session_issuances_purpose_passkey_v1"}
	steps, err := valid.Load(t.Context())
	if err != nil || len(steps) != 1 || steps[0].Version() != 72 || steps[0].DownSQL() != "" {
		t.Fatal("missing forward-only passkey signup migration", err)
	}
	for _, bad := range []PasskeySignupMigrationSource{{}, {Schema: "identity", Version: 72, PreviousConstraint: valid.PreviousConstraint}, {Schema: "session_store", Version: 72, PreviousConstraint: "arbitrary_constraint"}, {Schema: "session_store", Version: 72, PreviousConstraint: "session_issuances_purpose_passkey_signup_v1"}} {
		if out, err := bad.Load(t.Context()); err == nil || out != nil {
			t.Fatal("unknown or invalid signup history admitted")
		}
	}
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := valid.Load(cancelled); err == nil {
		t.Fatal("migration cancellation ignored")
	}
}
