package passwordpostgres

import (
	"context"
	"github.com/faustbrian/go-identity/password"
	"testing"
)

func TestOrganizationLifecycleMigrationRetainsSelectedPredecessors(t *testing.T) {
	base := PhoneChangeReauthenticationMigrationSource{Base: PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}, Version: 72}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := OrganizationLifecycleReauthenticationMigrationSource{Base: base, Version: 73}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("lifecycle suffix rejected", err)
	}
	for i, step := range original {
		if history[i] != step {
			t.Fatal("installed predecessor changed")
		}
	}
	if history[len(original)].DownSQL() != "" {
		t.Fatal("lifecycle suffix has destructive rollback")
	}
	if _, err = (OrganizationLifecycleReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 73}).Load(context.Background()); err != password.ErrPasswordWork {
		t.Fatal("missing action history admitted", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err = source.Load(ctx); err != context.Canceled {
		t.Fatal("migration cancellation lost", err)
	}
}

// Synthetic signed-original custody tests closed framing only. Genuine live
// session authentication and protected proof consumption require native tests.
func TestOrganizationLifecycleActionPrimaryRetainsExactSelfAuthority(t *testing.T) {
	for _, action := range []string{"identity.organization.archive", "identity.organization.restore"} {
		t.Run(action, func(t *testing.T) {
			source, request, fields, binding := phonePrimaryFixture(t, action)
			binding.SchemaID = "organization-lifecycle"
			admission, err := source.Restore(context.Background(), request, fields)
			if err != nil {
				t.Fatal("lifecycle owner rejected original signed custody", err)
			}
			command, err := admission.Command(binding, nil)
			if err != nil {
				t.Fatal("lifecycle command framing rejected", err)
			}
			if _, err = source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken); err != nil {
				t.Fatal("restart lost original self-only proof", err)
			}
			for name, mutate := range map[string]func(*ActionPrimaryRequest){
				"administrative-target": func(r *ActionPrimaryRequest) { r.TargetSubjectID = "target" },
				"explicit-self-target":  func(r *ActionPrimaryRequest) { r.TargetSubjectID = "user" },
				"wrong-action":          func(r *ActionPrimaryRequest) { r.Proof.Action = "identity.organization.owner-transfer" },
				"wrong-audience":        func(r *ActionPrimaryRequest) { r.Proof.Proof.Audience = "foreign" },
				"wrong-session":         func(r *ActionPrimaryRequest) { r.Proof.SessionVersion++ },
				"wrong-tenant":          func(r *ActionPrimaryRequest) { r.TenantID = "foreign" },
			} {
				t.Run(name, func(t *testing.T) {
					r := request
					mutate(&r)
					if _, err := source.Restore(context.Background(), r, fields); err == nil {
						t.Fatal("substituted lifecycle proof accepted")
					}
				})
			}
			foreign := binding
			foreign.UserID = "target"
			if _, err = admission.Command(foreign, nil); err == nil {
				t.Fatal("self-only lifecycle acquired target authority")
			}
			foreign = binding
			foreign.SchemaID = "organization-membership"
			if _, err = admission.Command(foreign, nil); err == nil {
				t.Fatal("lifecycle accepted owner-transfer schema")
			}
		})
	}
	for _, action := range []string{"identity.organization.delete", "identity.organization.create"} {
		source, r, fields, _ := phonePrimaryFixture(t, action)
		if _, err := source.Restore(context.Background(), r, fields); err == nil {
			t.Fatal("unselected lifecycle action accepted")
		}
	}
}
