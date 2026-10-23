package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
)

func TestPasskeyPortableOperationsRetainGraphLifetime(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{
		"nil":           nil,
		"zero":          {},
		"unselected":    {state: &storeState{features: &featureState{composed: true, ready: true}}},
		"uninitialized": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant"}}}},
		"closed":        {state: &storeState{closed: true, features: &featureState{composed: true, ready: true, passkey: &passkeyState{tenant: "tenant"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := owner.KeyedRegistrationOptions(t.Context(), passkey.KeyedRegistrationOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("unadmitted keyed enrollment")
			}
			if out, err := owner.Delete(t.Context(), passkey.DeleteRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("unadmitted passkey removal")
			}
			if out, err := owner.KeyedAuthenticationOptions(t.Context(), passkey.KeyedSigninOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("unadmitted keyed identified signin")
			}
			if out, err := owner.KeyedDiscoverableAuthenticationOptions(t.Context(), passkey.KeyedDiscoverableOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("unadmitted keyed discovery")
			}
			if out, err := owner.RegistrationRateSource(t.Context(), passkey.RegistrationCeremonyRateRequest{}); err == nil || out != (passkey.CeremonyRateSource{}) {
				t.Fatal("unadmitted enrollment source")
			}
			if out, err := owner.SigninRateSource(t.Context(), passkey.SigninCeremonyRateRequest{}); err == nil || out != (passkey.CeremonyRateSource{}) {
				t.Fatal("unadmitted identified source")
			}
			if out, err := owner.DiscoverableSigninRateSource(t.Context(), passkey.DiscoverableCeremonyRateRequest{}); err == nil || out != (passkey.CeremonyRateSource{}) {
				t.Fatal("unadmitted discovery source")
			}
			if owner != nil && owner.state != nil && owner.state.active != 0 {
				t.Fatal("denial leaked graph admission")
			}
		})
	}
}

func TestPasskeyKeyedOptionsRetainOpaqueStartupKeys(t *testing.T) {
	token, err := session.NewDigestKey(1, bytes.Repeat([]byte{229}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{230}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewPasskeyKeyedOptionsConfiguration("private-passkey-deployment", [32]byte{231, 232, 233}, token, csrf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("startup correlation keys serialized")
	}
	if got := fmt.Sprintf("%#v", c); got != "reference.PasskeyKeyedOptionsConfiguration(redacted)" {
		t.Fatal("startup keys disclosed in ordinary diagnostics")
	}
	// fmt bypasses methods through an unexported caller field. Secret storage
	// must itself remain opaque rather than relying only on a formatter.
	if got := fmt.Sprintf("%#v", struct {
		config PasskeyKeyedOptionsConfiguration
	}{c}); strings.Contains(got, "LookupKey") || strings.Contains(got, "0xe7") {
		t.Fatal("private caller field disclosed inline startup key material")
	}
	for _, input := range []passkeyKeyedOptionsInput{
		{"", [32]byte{1}, token, csrf},
		{strings.Repeat("x", 129), [32]byte{1}, token, csrf},
		{"\xff", [32]byte{1}, token, csrf},
		{"deployment", [32]byte{}, token, csrf},
		{"deployment", [32]byte{1}, session.DigestKey{}, csrf},
		{"deployment", [32]byte{1}, token, session.CSRFKey{}},
	} {
		if out, err := NewPasskeyKeyedOptionsConfiguration(input.namespace, input.lookupKey, input.tokenKey, input.csrfKey); err == nil || out.state != nil {
			t.Fatal("invalid startup key configuration accepted")
		}
	}
}

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
	if owner, err := composePasskey(StoreConfiguration{}, ReferenceDependencies{}, nil, risk.Evaluator{}, nil, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected owner invented")
	}
	c := StoreConfiguration{Passkey: &PasskeyConfiguration{IdentifierKey: []byte("private-fixture-material")}}
	if owner, err := composePasskey(c, ReferenceDependencies{}, nil, risk.Evaluator{}, nil, nil, nil); err == nil || owner != nil {
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

func TestPasskeyDeletionMigrationsRetainAllInstalledProofHistories(t *testing.T) {
	f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignin: &passwordpg.SigninService{}, passwordVerification: &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}, passkey: &passkeyState{schema: "session_store", predecessor: "session_issuances_purpose_v3", management: &native.ManagementService{}}}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.passkey.deletion = &native.DeletionService{}
	// Runtime label management may be off after its proof history was installed.
	// Deletion must retain those bytes and old signed/consumed proof allowances.
	f.passkey.management = nil
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
					t.Fatal("deletion rewrote installed proof history", old.namespace)
				}
			}
		}
		if !found {
			t.Fatal("deletion discarded installed owner", old.namespace)
		}
	}
	for _, history := range after {
		if history.namespace == "identity_passkey_deletion_password" {
			if len(history.history) != 1 || history.history[0].Version() != 42 {
				t.Fatal("deletion proof suffix collided")
			}
			return
		}
	}
	t.Fatal("selected deletion omitted owned password proof suffix")
}
