package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// The same session owner must revoke every session for phone recovery. This
// closed scope grants no recovery permission or successful-factor assertion.
func TestPhonePasswordResetSelectsCanonicalAllSessionEffect(t *testing.T) {
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{OperationID: op.OperationID}
	life := kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 7, AfterVersion: 8}
	if !resetSessionScope(b, op, life) {
		t.Fatal("canonical phone reset cannot select the existing all-session revoker")
	}
	for _, mode := range []string{"owner", "schema", "version", "binding", "event", "successor"} {
		t.Run(mode, func(t *testing.T) {
			other, binding, transition := op, b, life
			switch mode {
			case "owner":
				other.Owner = "identity/password"
			case "schema":
				other.SchemaID = "password-reset-complete"
			case "version":
				other.SchemaVersion++
			case "binding":
				binding.OperationID = "identity.password.reset-complete"
			case "event":
				transition.EventType = "password.changed.v1"
			case "successor":
				transition.AfterVersion++
			}
			if resetSessionScope(binding, other, transition) {
				t.Fatal("foreign reset selected session revocation")
			}
		})
	}
}

func TestPhonePasswordResetSessionMigrationRejectsInvalidAndCancelledInputs(t *testing.T) {
	valid := PhonePasswordResetMigrationSource{Schema: "session_store", Version: 204}
	forward, err := valid.Load(context.Background())
	if err != nil || len(forward) != 1 || forward[0].Version() != valid.Version || forward[0].DownSQL() != "" {
		t.Fatal("forward session purpose extension unavailable", err)
	}
	for _, invalid := range []PhonePasswordResetMigrationSource{{}, {Schema: "identity", Version: 204}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(^uint64(0))}} {
		if result, err := invalid.Load(context.Background()); err == nil || result != nil {
			t.Fatal("invalid session migration returned partial history")
		}
	}
	if result, err := valid.Load(nil); err == nil || result != nil {
		t.Fatal("nil context returned partial session history")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := valid.Load(ctx); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("session migration discarded cancellation", err)
	}
}
