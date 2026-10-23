package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	native "github.com/faustbrian/go-passkey/postgres"
)

func TestPasskeyDiscoveryRetainsGraphLifetime(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{
		"nil":           nil,
		"zero":          {},
		"unselected":    {state: &storeState{features: &featureState{composed: true, ready: true}}},
		"uninitialized": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant"}}}},
		"closed":        {state: &storeState{closed: true, features: &featureState{composed: true, ready: true, passkey: &passkeyState{tenant: "tenant"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := owner.DiscoverableAuthenticationOptions(t.Context(), native.DiscoverableSigninRequest{}); err == nil {
				t.Fatal("unadmitted discovery options")
			}
			if out, err := owner.DiscoverableSignin(t.Context(), native.DiscoverableSigninCompletion{}); err == nil || out.Session.Token != (session.Token{}) {
				t.Fatal("unadmitted discovery returned a session")
			}
			if owner != nil && owner.state != nil && owner.state.active != 0 {
				t.Fatal("denial leaked graph lifetime")
			}
		})
	}
}

func TestPasskeysRequireExplicitLiveSelection(t *testing.T) {
	for name, graph := range map[string]FeatureSet{
		"zero":       {},
		"unselected": {state: &storeState{features: &featureState{composed: true}}},
		"closed":     {state: &storeState{closed: true, features: &featureState{composed: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			if owner, err := graph.Passkeys(); err == nil || owner != nil {
				t.Fatal("unselected or closed graph exposed passkey operations")
			}
		})
	}
}

func TestPasskeyHandleRetainsStartupTenantAndClose(t *testing.T) {
	_, _, graph := serverFixture(t)
	graph.state.features.passkey = &passkeyState{tenant: "tenant"}
	owner, err := graph.Passkeys()
	if err != nil {
		t.Fatal(err)
	}
	deny := func(tenant identity.TenantID) {
		t.Helper()
		if _, err := owner.Get(t.Context(), session.GetRequest{TenantID: tenant}); err == nil {
			t.Fatal("unadmitted read")
		}
		if _, err := owner.PrepareFlow(t.Context(), session.PreAuthPrepareInput{TenantID: tenant}); err == nil {
			t.Fatal("unadmitted initiation")
		}
		if _, err := owner.SignOut(t.Context(), session.SignOutRequest{TenantID: tenant}, session.CSRFToken{}); err == nil {
			t.Fatal("unadmitted logout")
		}
		if graph.state.active != 0 {
			t.Fatal("denial leaked graph lifetime")
		}
	}
	deny("tenant")
	graph.state.features.ready = true
	deny("foreign")
	graph.state.closed = true
	deny("tenant")
	if got, err := graph.Passkeys(); err == nil || got != nil {
		t.Fatal("closed graph exposed new handle")
	}
	var zero *PasskeyService
	if _, err := zero.Get(context.Background(), session.GetRequest{}); err == nil {
		t.Fatal("nil service read")
	}
}

func TestPasskeyCompositionDoesNotInventOwnersOrDiscloseKeys(t *testing.T) {
	if owner, err := composePasskey(StoreConfiguration{}, ReferenceDependencies{}, nil, risk.Evaluator{}, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected owner invented")
	}
	c := StoreConfiguration{Passkey: &PasskeyConfiguration{IdentifierKey: []byte("private-fixture-material")}}
	if owner, err := composePasskey(c, ReferenceDependencies{}, nil, risk.Evaluator{}, nil, nil); err == nil || owner != nil {
		t.Fatal("missing actual owners accepted")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected passkey silently disappeared")
	}
	if _, err := json.Marshal(c.Passkey); err == nil {
		t.Fatal("startup keys serialized")
	}
	if got := fmt.Sprintf("%#v", *c.Passkey); !strings.Contains(got, "redacted") || strings.Contains(got, "private-fixture-material") {
		t.Fatal("startup keys disclosed")
	}
}

func TestPasskeyMigrationsPreserveInstalledPrefixes(t *testing.T) {
	f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignin: &passwordpg.SigninService{}, passwordVerification: &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.passkey = &passkeyState{schema: "session_store", predecessor: "session_issuances_purpose_v3"}
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		found := false
		for _, current := range after {
			if old.namespace != current.namespace {
				continue
			}
			found = true
			for i, step := range old.history {
				if i >= len(current.history) || step != current.history[i] || old.owners[step.Version()] != current.owners[step.Version()] {
					t.Fatal("passkey rewrote installed history", old.namespace)
				}
			}
		}
		if !found {
			t.Fatal("passkey removed installed owner", old.namespace)
		}
	}
	for _, expected := range []string{"identity_passkey", "identity_passkey_password", "identity_passkey_session", "identity_passkey_preauth", "webauthn"} {
		found := false
		for _, h := range after {
			found = found || h.namespace == expected && len(h.history) > 0
		}
		if !found {
			t.Fatal("selected passkey omitted actual owner history", expected)
		}
	}
}
