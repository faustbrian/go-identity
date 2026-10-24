package reference

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
)

func TestPasskeySignupRequiresSelectedLiveGraph(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{
		"nil":           nil,
		"zero":          {},
		"unselected":    {state: &storeState{features: &featureState{composed: true, ready: true, passkey: &passkeyState{tenant: "tenant"}}}},
		"uninitialized": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", signup: &native.SignupService{}}}}},
		"closed":        {state: &storeState{closed: true, features: &featureState{composed: true, ready: true, passkey: &passkeyState{tenant: "tenant", signup: &native.SignupService{}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := owner.PrepareSignupFlow(t.Context(), session.PreAuthPrepareInput{}); err == nil {
				t.Fatal("unadmitted signup preparation")
			}
			if _, err := owner.IssueSignupFlow(t.Context(), session.PreparedPreAuthIssuance{}); err == nil {
				t.Fatal("unadmitted signup flow")
			}
			if _, err := owner.SignupOptions(t.Context(), passkey.SignupRequest{}); err == nil {
				t.Fatal("unadmitted signup options")
			}
			if out, err := owner.KeyedSignupOptions(t.Context(), passkey.KeyedSignupOptionsRequest{}); err == nil || out.CommandID != "" {
				t.Fatal("unadmitted keyed signup")
			}
			if out, err := owner.Signup(t.Context(), passkey.SignupCompletion{}); err == nil || out.Session.Token != (session.Token{}) {
				t.Fatal("unadmitted signup completion")
			}
			if out, err := owner.SignupRateSource(t.Context(), passkey.SignupCeremonyRateRequest{}); err == nil || out != (passkey.CeremonyRateSource{}) {
				t.Fatal("unadmitted signup rate source")
			}
			if _, err := owner.RecoverSignupOptions(t.Context(), passkey.SignupRequest{}, authorization.DecisionContext{}); err == nil {
				t.Fatal("unadmitted signup options recovery")
			}
			if _, err := owner.RecoverSignup(t.Context(), passkey.SignupRequest{}, "", authorization.DecisionContext{}); err == nil {
				t.Fatal("unadmitted signup recovery")
			}
			if owner != nil && owner.state != nil && owner.state.active != 0 {
				t.Fatal("denied signup leaked graph admission")
			}
		})
	}
}

func TestPasskeySignupMigrationsRetainInstalledHistories(t *testing.T) {
	f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignin: &passwordpg.SigninService{}, passwordSignup: &passwordpg.SignupService{}, passwordVerification: &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}, passkey: &passkeyState{schema: "session_store", predecessor: "session_issuances_purpose_v3"}}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.passkey.signup = &native.SignupService{}
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
				if i >= len(current.history) || current.history[i] != step || current.owners[step.Version()] != old.owners[step.Version()] {
					t.Fatal("signup rewrote installed history", old.namespace)
				}
			}
		}
		if !found {
			t.Fatal("signup removed installed history", old.namespace)
		}
	}
	for _, namespace := range []string{"identity_passkey_signup_kernel", "identity_passkey_signup_factors", "identity_passkey_signup_counters"} {
		found := false
		for _, current := range after {
			found = found || current.namespace == namespace && len(current.history) == 1
		}
		if !found {
			t.Fatal("signup missing owned forward history", namespace)
		}
	}
}

func TestStandalonePasskeyCatalogContainsOnlySelectedOwners(t *testing.T) {
	f := &featureState{migrations: featureMigrationConfig{standalonePasskey: true, sessionSchema: "session_store", signinSchema: "session_store", global: "deployment", preauthIssue: true, singleSessionRevocation: true}, passkey: &passkeyState{standalone: true, signup: &native.SignupService{}, schema: "session_store", predecessor: "session_issuances_purpose_v2"}}
	s := StoreSet{state: &storeState{durable: true, config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
	catalog, err := s.migrationCatalog(t.Context())
	if err != nil {
		var input identity.InvalidInputError
		if errors.As(err, &input) {
			t.Fatal("standalone migration catalog", input.Field)
		}
		t.Fatal("standalone migration catalog", err)
	}
	for _, h := range catalog {
		for _, owner := range h.owners {
			switch owner {
			case "identity/otp/postgres", "identity/password/postgres", "identity/delivery/postgres":
				t.Fatal("unselected workflow contributes migrations", h.namespace, owner)
			}
		}
	}
}
