package postgres

import (
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestAnonymousUpgradeCountersBindGuestNotPermanentTarget(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := protectedCommand(t, "counter-tenant").Feature()
	guest, _ := identity.NewSubjectID()
	spec.Operation = identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.RecordID = spec.Operation.OperationID, spec.Operation.SchemaID, string(guest)
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	command, err := identity.NewFeatureSessionCommand(spec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: string(guest), Session: "guest-original-session", Network: "192.0.2.1"}
	prepared, plan, err := r.PrepareCommandCounters(command, subject, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal("actual guest upgrade counter preparation", err)
	}
	if err = r.ValidateCommandCounters(prepared, plan); err != nil {
		t.Fatal("guest-bound plan cannot be restored", err)
	}
	for _, user := range []string{"subject", "other-guest"} {
		changed := subject
		changed.User = user
		if _, _, err = r.PrepareCommandCounters(command, changed, time.Now().UTC().Truncate(time.Microsecond)); err == nil {
			t.Fatal("upgrade counter accepted wrong guest")
		}
	}
	safe, _ := prepared.Feature()
	safe.Binding.RecordID = "another-guest"
	foreign, err := identity.NewFeatureSessionCommand(safe, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if r.ValidateCommandCounters(foreign, plan) == nil {
		t.Fatal("guest counter transferred across records")
	}
}
