package postgres

import (
	"context"
	"testing"
)

func TestOAuthSigninMigrationRequiresExplicitExpansionAndValidation(t *testing.T) {
	valid := OAuthSigninMigrationSource{Schema: "session_store", Version: 81, ValidationVersion: 82, PreviousConstraint: "session_issuances_purpose_v4"}
	steps, err := valid.Load(t.Context())
	if err != nil || len(steps) != 2 || steps[0].Version() != 81 || steps[1].Version() != 82 || steps[0].DownSQL() != "" || steps[1].DownSQL() != "" {
		t.Fatal("forward schema/validation steps missing", err)
	}
	for _, source := range []OAuthSigninMigrationSource{{}, {Schema: "identity", Version: 81, ValidationVersion: 82, PreviousConstraint: valid.PreviousConstraint}, {Schema: "session_store", Version: 81, ValidationVersion: 81, PreviousConstraint: valid.PreviousConstraint}, {Schema: "session_store", Version: 81, PreviousConstraint: valid.PreviousConstraint}, {Schema: "session_store", Version: 81, ValidationVersion: 82, PreviousConstraint: "arbitrary_check"}} {
		if steps, err := source.Load(t.Context()); err == nil || steps != nil {
			t.Fatal("unknown history/validation order admitted")
		}
	}
	if _, err := valid.Load(nil); err == nil {
		t.Fatal("nil migration context admitted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := valid.Load(cancelled); err == nil {
		t.Fatal("cancelled migration admitted")
	}
}
