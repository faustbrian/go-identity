package reference

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferenceEnterpriseOIDCIsOptIn(t *testing.T) {
	config, dependencies, features := serverFixture(t)
	server, err := NewServer(config, dependencies, features)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ operation, method, path string }{
		{"identity.sso.signin-start", http.MethodPost, "/v1/sso/signin-start"},
		{"identity.sso.oidc-callback", http.MethodGet, "/sso/oidc/callback"},
	} {
		for _, operation := range server.OpenAPI().Operations() {
			if operation.Record.OperationID == route.operation {
				t.Fatalf("unselected %s advertised", route.operation)
			}
		}
		request := httptest.NewRequest(route.method, "https://login.example"+route.path, nil)
		request.RequestURI = request.URL.RequestURI()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
			t.Fatalf("unselected %s exposed: %d", route.operation, response.Code)
		}
	}
	for name, config := range map[string]StoreConfiguration{
		"HTTP without native selection":   {HTTPEnterpriseOIDC: &HTTPEnterpriseOIDCConfiguration{}},
		"native without the common graph": {EnterpriseOIDC: &EnterpriseOIDCConfiguration{}},
	} {
		t.Run(name, func(t *testing.T) {
			state := &storeState{}
			if err := state.composeFeatureStores(config, ReferenceDependencies{}); err == nil || state.features != nil {
				t.Fatal("enterprise selection silently dropped without its required owners")
			}
		})
	}
}

func TestReferenceEnterpriseRoleSyncRequiresOrganizationRoles(t *testing.T) {
	c := StoreConfiguration{
		EnterpriseOIDC: &EnterpriseOIDCConfiguration{RoleSync: &ssopg.StaticOIDCRoleMapping{}},
		Session:        &SessionConfiguration{}, Organization: &OrganizationConfiguration{}, OTP: &OTPSendConfiguration{},
	}
	if err := validateEnterpriseOIDCSelection(c); err == nil {
		t.Fatal("selected role sync accepted a graph without organization permission ownership")
	}
	c.EnterpriseOIDC.RoleSync = nil
	if err := validateEnterpriseOIDCSelection(c); err != nil {
		t.Fatal("unselected role sync made dynamic roles required", err)
	}
}

func TestReferenceEnterpriseRoleSyncAppendsOnlyNativeMigrationHistories(t *testing.T) {
	enterprise := &enterpriseOIDCState{sessionSchema: "session_store"}
	stores := StoreSet{state: &storeState{features: &featureState{enterpriseOIDC: enterprise}}}
	before, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	enterprise.roleSync = true
	after, err := stores.enterpriseOIDCMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == "identity_organization_provider_roles" })
	providers := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == "identity_enterprise_oidc" })
	if policy < 0 || providers <= policy || len(after[policy].history) != 2 {
		t.Fatal("role sync did not install its organization grants and projector before the provider trigger")
	}
	for _, old := range before {
		idx := slices.IndexFunc(after, func(h migrationHistory) bool { return h.namespace == old.namespace })
		if idx < 0 || len(after[idx].history) < len(old.history) || !slices.Equal(old.history, after[idx].history[:len(old.history)]) {
			t.Fatalf("role sync rewrote the installed %s prefix", old.namespace)
		}
		if idx == providers && (len(after[idx].history) != len(old.history)+1 || after[idx].history[len(old.history)].Version() != 7) {
			t.Fatal("role sync did not append its native provider lifecycle trigger")
		}
	}
}
