package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasskeyIssuanceMigrationRequiresExactSelectedHistory(t *testing.T) {
	valid := PasskeySigninMigrationSource{Schema: "session_store", Version: 71, PreviousConstraint: "session_issuances_purpose_v4"}
	steps, err := valid.Load(t.Context())
	if err != nil || len(steps) != 1 || steps[0].Version() != 71 || steps[0].DownSQL() != "" || steps[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("invalid forward passkey migration", err)
	}
	for _, bad := range []PasskeySigninMigrationSource{{}, {Schema: "identity", Version: 71, PreviousConstraint: valid.PreviousConstraint}, {Schema: "session_store", Version: 71, PreviousConstraint: "caller_supplied_check"}, {Schema: "session_store", Version: 71, PreviousConstraint: "session_issuances_purpose_passkey_v1"}} {
		if out, err := bad.Load(t.Context()); err == nil || out != nil {
			t.Fatal("unknown or invalid predecessor admitted")
		}
	}
	if _, err := valid.Load(nil); err == nil {
		t.Fatal("nil migration context admitted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := valid.Load(canceled); err == nil {
		t.Fatal("canceled migration admitted")
	}
}
