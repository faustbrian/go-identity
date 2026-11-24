package reference

import (
	"slices"
	"testing"

	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferenceSAMLRoleSyncRequiresOrganizationRoles(t *testing.T) {
	c := StoreConfiguration{
		EnterpriseSAML: &EnterpriseSAMLConfiguration{RoleSync: &ssopg.StaticSAMLRoleMapping{}},
		Session:        &SessionConfiguration{CSRFKeys: []session.CSRFKey{{}}},
		Organization:   &OrganizationConfiguration{}, OTP: &OTPSendConfiguration{},
	}
	c.EnterpriseSAML.Login.RequestKeys.Namespace = "saml-signin"
	if err := validateEnterpriseSAMLSelection(c); err == nil {
		t.Fatal("selected SAML role sync accepted a graph without organization permission ownership")
	}
	c.Organization.Core.DynamicRoles.Version = 1
	if err := validateEnterpriseSAMLSelection(c); err != nil {
		t.Fatal("selected SAML role sync rejected organization permission ownership", err)
	}
	c.EnterpriseSAML.RoleSync = nil
	c.Organization.Core.DynamicRoles.Version = 0
	if err := validateEnterpriseSAMLSelection(c); err != nil {
		t.Fatal("unselected SAML role sync made dynamic roles required", err)
	}
}

func TestReferenceSAMLRoleSyncPreservesInstalledMigrationPrefixes(t *testing.T) {
	enterprise := &enterpriseSAMLState{sessionSchema: "session_store"}
	stores := StoreSet{state: &storeState{features: &featureState{enterpriseSAML: enterprise}}}
	before, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(before, func(h migrationHistory) bool { return h.namespace == "identity_organization_provider_roles" }) {
		t.Fatal("unselected SAML role sync installed provider grants")
	}
	providerPrefix := slices.IndexFunc(before, func(h migrationHistory) bool { return h.namespace == "identity_enterprise_oidc" })
	if providerPrefix < 0 || len(before[providerPrefix].history) != 6 {
		t.Fatal("unselected SAML role sync changed the six-step installed provider prefix")
	}
	enterprise.roleSync = true
	after, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	roles := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == "identity_organization_provider_roles" })
	providers := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == "identity_enterprise_oidc" })
	if roles < 0 || providers <= roles || len(after[roles].history) != 2 || len(after[providers].history) != 7 {
		t.Fatal("SAML role sync did not install the existing organization grant/projector history before provider trigger 7")
	}
	for _, original := range before {
		index := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == original.namespace })
		if index < 0 || len(after[index].history) < len(original.history) {
			t.Fatalf("SAML role sync lost the installed %s history", original.namespace)
		}
		for i, step := range original.history {
			if step.Version() != after[index].history[i].Version() || step.Checksum() != after[index].history[i].Checksum() {
				t.Fatalf("SAML role sync rewrote the installed %s migration %d", original.namespace, step.Version())
			}
		}
	}
	for _, expected := range []struct {
		index  int
		source migrations.Source
	}{
		{roles, organizationpg.ProviderRoleGrantMigrationSource{Version: 1}},
		{roles, organizationpg.ProviderRoleSourceProjectionMigrationSource{Version: 2}},
		{providers, ssopg.ProviderRoleSourceMigrationSource{Version: 7}},
	} {
		native, err := expected.source.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range native {
			index := slices.IndexFunc(after[expected.index].history, func(candidate migrations.Migration) bool { return candidate.Version() == step.Version() })
			if index < 0 || after[expected.index].history[index].Checksum() != step.Checksum() {
				t.Fatalf("SAML role sync did not reuse native migration %d exactly", step.Version())
			}
		}
	}
}

func TestReferenceSAMLAndOIDCRoleSyncShareMigrationHistories(t *testing.T) {
	features := &featureState{enterpriseOIDC: &enterpriseOIDCState{sessionSchema: "session_store", roleSync: true}}
	stores := StoreSet{state: &storeState{features: features}}
	baseline, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []struct {
		name string
		oidc *enterpriseOIDCState
	}{
		{"SAML only", nil},
		{"SAML and OIDC without OIDC roles", &enterpriseOIDCState{sessionSchema: "session_store"}},
		{"SAML and OIDC", features.enterpriseOIDC},
	} {
		t.Run(selection.name, func(t *testing.T) {
			features.enterpriseOIDC = selection.oidc
			features.enterpriseSAML = &enterpriseSAMLState{sessionSchema: "session_store", roleSync: true}
			selected, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(selected) != len(baseline) {
				t.Fatal("selecting SAML changed or duplicated the shared native migration histories")
			}
			for i, original := range baseline {
				if selected[i].namespace != original.namespace || len(selected[i].history) != len(original.history) {
					t.Fatalf("selecting SAML changed shared history %s", original.namespace)
				}
				for j, step := range original.history {
					if selected[i].history[j].Version() != step.Version() || selected[i].history[j].Checksum() != step.Checksum() {
						t.Fatalf("selecting SAML changed shared migration %s/%d", original.namespace, step.Version())
					}
				}
			}
		})
	}
}
