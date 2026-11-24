package reference

import (
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestReferenceSAMLIDPSelectionRequiresManagedProvider(t *testing.T) {
	config := StoreConfiguration{HTTPEnterpriseSAML: &HTTPEnterpriseSAMLConfiguration{IDPInitiated: true}}
	if err := validateEnterpriseSAMLSelection(config); err == nil {
		t.Fatal("unsolicited HTTP selection without a managed SAML provider was admitted")
	}
}

func TestReferenceSAMLLogoutMatchKeysAreDedicated(t *testing.T) {
	stateKey := [32]byte{1}
	confirmationKey := [32]byte{2}
	config := EnterpriseSAMLConfiguration{
		IDPInitiated: &EnterpriseSAMLIDPConfiguration{ConfirmationKeys: map[uint32][32]byte{1: confirmationKey}},
		Logout: &EnterpriseSAMLLogoutConfiguration{
			CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {3}},
		},
	}
	config.Login.StateKeys = map[uint32][32]byte{1: stateKey}
	if _, err := newEnterpriseSAMLLogoutCustody(config, "test-envelope"); err != nil {
		t.Fatal("dedicated logout match keys rejected", err)
	}
	for _, reused := range [][32]byte{stateKey, confirmationKey} {
		config.Logout.MatchKeys[1] = reused
		if _, err := newEnterpriseSAMLLogoutCustody(config, "test-envelope"); err == nil {
			t.Fatal("existing browser key was accepted as a logout match key")
		}
	}
}

func TestReferenceSAMLSPLogoutRequiresSelectedNativeAndReturn(t *testing.T) {
	native := EnterpriseSAMLConfiguration{}
	http := HTTPEnterpriseSAMLConfiguration{LogoutStart: true}
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, &http); err == nil {
		t.Fatal("HTTP logout start was selected without its native owner")
	}
	native.LogoutStart = &EnterpriseSAMLLogoutStartConfiguration{RequestKeys: kernel.RequestKeyConfig{Namespace: "logout-start"}}
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, &http); err != nil {
		t.Fatal("local-only logout unexpectedly required an IdP return", err)
	}
	native.LogoutStart.RedirectEndpoint = "https://idp.example/slo"
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, nil); err == nil {
		t.Fatal("native Redirect selected without original signed subject custody")
	}
	native.Logout = &EnterpriseSAMLLogoutConfiguration{}
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, &http); err == nil {
		t.Fatal("remote start was selected without the browser return")
	}
	http.Logout = true
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, &http); err != nil {
		t.Fatal("paired remote start and return selection rejected", err)
	}
	http.LogoutStart = false
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, &http); err != nil {
		t.Fatal("turning off new starts should not strand previously reserved returns", err)
	}
}

func TestReferenceSAMLSPLogoutRelayRequiresIndependentRemoteRequestKey(t *testing.T) {
	native := EnterpriseSAMLConfiguration{
		Logout: &EnterpriseSAMLLogoutConfiguration{RequestKeys: &kernel.RequestKeyConfig{Namespace: "idp-logout"}},
		LogoutStart: &EnterpriseSAMLLogoutStartConfiguration{
			RequestKeys:           kernel.RequestKeyConfig{Namespace: "sp-local"},
			RelayStateRequestKeys: &kernel.RequestKeyConfig{Namespace: "sp-relay"},
		},
	}
	native.Login.RequestKeys.Namespace = "signin"
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, nil); err == nil {
		t.Fatal("local-only selection accepted a remote relay namespace")
	}
	native.LogoutStart.RedirectEndpoint = "https://idp.example/slo"
	for _, namespace := range []string{"", "signin", "sp-local", "idp-logout"} {
		native.LogoutStart.RelayStateRequestKeys.Namespace = namespace
		if err := validateEnterpriseSAMLLogoutStartSelection(&native, nil); err == nil {
			t.Fatal("remote relay selection accepted missing or shared namespace", namespace)
		}
	}
	native.LogoutStart.RelayStateRequestKeys.Namespace = "sp-relay"
	if err := validateEnterpriseSAMLLogoutStartSelection(&native, nil); err != nil {
		t.Fatal("native relay storage must be selectable without HTTP", err)
	}
}

func TestReferenceSAMLSPLogoutPreservesAppliedSharedMigrationHistory(t *testing.T) {
	const schema = "identity_sessions"
	fromBase, err := appendEnterpriseSAMLLogoutStartMigrations(t.Context(), nil, schema, false)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := appendEnterpriseOIDCLogoutSessionMigrations(t.Context(), nil, schema)
	if err != nil {
		t.Fatal(err)
	}
	fromOIDC, err := appendEnterpriseSAMLLogoutStartMigrations(t.Context(), predecessor, schema, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromBase) != 2 || len(fromOIDC) != 3 || len(fromOIDC[2].history) != 2 {
		t.Fatal("expected shared and local history, with two extra remote steps only in Redirect mode")
	}
	for i, original := range fromBase {
		added := fromOIDC[i]
		if original.namespace != added.namespace || len(original.history) != len(added.history) {
			t.Fatal("configuration changed an installed migration namespace")
		}
		for j, step := range original.history {
			if step.Checksum() != added.history[j].Checksum() {
				t.Fatal("configuration changed an installed migration checksum")
			}
		}
	}
	state := &storeState{features: &featureState{enterpriseSAML: &enterpriseSAMLState{
		sessionSchema: schema, logoutStart: &enterpriseSAMLLogoutStartState{},
	}}}
	guards := readinessCatalogGuards(state, fromBase[0])
	if guards[0].constraints[0] != "session_revocations."+enterpriseSAMLLogoutStartConstraint ||
		fromBase[0].guards[0].constraints[0] != "session_revocations."+enterpriseOIDCLogoutSessionConstraint {
		t.Fatal("SAML readiness must follow the actual successor without mutating the installed history")
	}
}
