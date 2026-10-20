package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This tests the storage owner's closed original-action relation, not cookie
// authentication, current database state, reservation or recovery permission.
func TestPhoneResetPreAuthUseRetainsOriginalRequestAndExactCompletion(t *testing.T) {
	legacy := testPreAuth(t, time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC))
	spec, err := legacy.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	spec.Binding.Intent.Action = "identity.phone.password-reset-request"
	spec.Binding.Intent.Remember = session.RememberPolicy{}
	spec.Binding.Intent.IdentifierBinding = [32]byte{3}
	original, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ = original.Bindings()
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	command := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: spec.Binding.Intent.TenantID, UserID: "user-a", ActorID: "server", ActorKind: authorization.SubjectServiceAccount, RecordID: "password-a", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: spec.Binding.Intent.PolicyID, PolicyVersion: spec.Binding.Intent.PolicyVersion, CorrelationID: "AgICAgICAgICAgICAgICAg"}
	if err := command.ValidateFor(op); err != nil {
		t.Fatal("invalid complete scope fixture", err)
	}
	use := PreAuthUse{Command: command, Fingerprint: [32]byte{4}, Generation: 1}
	if !use.valid(spec) {
		t.Fatal("original phone request flow cannot be consumed by its exact completion")
	}
	if got, _ := original.Bindings(); got != spec || got.Binding.Intent.Action != "identity.phone.password-reset-request" {
		t.Fatal("completion renewed or rewrote original flow")
	}
	for name, mutate := range map[string]func(*PreAuthUse){
		"request cannot consume": func(u *PreAuthUse) { u.Command.OperationID = "identity.phone.password-reset-request" },
		"email reset":            func(u *PreAuthUse) { u.Command.OperationID = "identity.password.reset-complete" },
		"schema alias":           func(u *PreAuthUse) { u.Command.SchemaID = "alias" },
		"future schema":          func(u *PreAuthUse) { u.Command.SchemaVersion++ },
		"foreign tenant":         func(u *PreAuthUse) { u.Command.TenantID = "other" },
		"foreign policy":         func(u *PreAuthUse) { u.Command.PolicyID = "other" },
		"foreign revision":       func(u *PreAuthUse) { u.Command.PolicyVersion-- },
		"absent user":            func(u *PreAuthUse) { u.Command.UserID = "" },
		"absent credential":      func(u *PreAuthUse) { u.Command.RecordID = "" },
		"absent fingerprint":     func(u *PreAuthUse) { u.Fingerprint = [32]byte{} },
		"absent generation":      func(u *PreAuthUse) { u.Generation = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := use
			mutate(&bad)
			if bad.valid(spec) {
				t.Fatal("foreign or incomplete completion acquired original flow")
			}
		})
	}
	login, _ := legacy.Bindings()
	if use.valid(login) {
		t.Fatal("phone reset acquired a session-issuing flow")
	}
	ordinary := use
	ordinary.Command.OperationID = login.Binding.Intent.Action
	if !ordinary.valid(login) {
		t.Fatal("existing same-action login relation changed")
	}
}
