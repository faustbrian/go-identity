package passwordpostgres

import (
	"context"
	"testing"
)

// These signed-original custody checks prove framing and substitution denial,
// not live authentication or protected proof consumption. The complete native
// passkey journey must exercise those owners against the real primary database.
func TestPasskeyEnrollmentActionPrimaryRetainsExactSelfCustody(t *testing.T) {
	testPasskeyActionPrimarySelfCustody(t, []string{"identity.passkey.register-options", "identity.passkey.register-verify"})
}

func TestPasskeyUpdateActionPrimaryRetainsExactSelfCustody(t *testing.T) {
	testPasskeyActionPrimarySelfCustody(t, []string{"identity.passkey.update"})
}

func TestPasskeyDeletionActionPrimaryRetainsExactSelfCustody(t *testing.T) {
	testPasskeyActionPrimarySelfCustody(t, []string{"identity.passkey.delete"})
}

func testPasskeyActionPrimarySelfCustody(t *testing.T, actions []string) {
	t.Helper()
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			source, request, fields, binding := phonePrimaryFixture(t, action)
			admission, err := source.Restore(context.Background(), request, fields)
			if err != nil {
				t.Fatal("passkey enrollment rejected original signed primary custody", err)
			}
			command, err := admission.Command(binding, nil)
			if err != nil {
				t.Fatal("passkey enrollment cannot bind its native command", err)
			}
			if _, err := source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken); err != nil {
				t.Fatal("original passkey enrollment command lost its custody", err)
			}
			for name, mutate := range map[string]func(*ActionPrimaryRequest){
				"target-override":      func(r *ActionPrimaryRequest) { r.TargetSubjectID = "target" },
				"explicit-self-target": func(r *ActionPrimaryRequest) { r.TargetSubjectID = "user" },
				"other-action": func(r *ActionPrimaryRequest) {
					r.Proof.Action = "identity.passkey.register-options"
					if action == r.Proof.Action {
						r.Proof.Action = "identity.passkey.register-verify"
					}
				},
				"foreign-audience": func(r *ActionPrimaryRequest) { r.Proof.Proof.Audience = "foreign" },
				"other-session":    func(r *ActionPrimaryRequest) { r.Proof.SessionVersion++ },
				"foreign-tenant":   func(r *ActionPrimaryRequest) { r.TenantID = "foreign" },
			} {
				t.Run(name, func(t *testing.T) {
					r := request
					mutate(&r)
					if _, err := source.Restore(context.Background(), r, fields); err == nil {
						t.Fatal("substituted passkey enrollment custody accepted")
					}
				})
			}
			foreign := binding
			foreign.SchemaID = "mfa-enrollment"
			if _, err := admission.Command(foreign, nil); err == nil {
				t.Fatal("passkey enrollment accepted a neighboring native schema")
			}
			foreign = binding
			foreign.UserID = "target"
			if _, err := admission.Command(foreign, nil); err == nil {
				t.Fatal("passkey enrollment acquired another subject")
			}
		})
	}
}

func TestPasskeyActionPrimaryDoesNotSelectOtherOperations(t *testing.T) {
	for _, action := range []string{"identity.passkey.signin-options", "identity.passkey.signin-verify", "identity.passkey.update-other", "identity.passkey.delete-other"} {
		source, request, fields, _ := phonePrimaryFixture(t, action)
		if _, err := source.Restore(context.Background(), request, fields); err == nil {
			t.Fatal("enrollment selection admitted an unrelated passkey operation")
		}
	}
}
