package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func oauthSigninEffectFixture(t *testing.T) (IdentifierAdmissionConfig, session.Session, kernel.ProviderAccountAdmission) {
	t.Helper()
	_, record, _ := oauthSigninMappingFixture(t, true)
	spec, _ := record.Bindings()
	vector, _ := spec.Authority.Bindings()
	key, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	vector.Factor.Binding.ScopeKey = key
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	record, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-a", PolicyNamespace: "users", Audience: spec.Audience, AuthenticationMethod: "oauth", CredentialKind: identity.CredentialProvider, CredentialOwner: "identity/oauth"}
	account := kernel.ProviderAccountAdmission{
		Account:           identity.Account{ID: "provider-account", TenantID: spec.TenantID, UserID: spec.UserID, Provider: "oidc", Issuer: "https://issuer.example", Subject: "opaque-subject", Version: 1},
		SocialLinkVersion: 1,
		Credential:        kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: record.EffectiveCredentialVersion()}, UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version},
	}
	return profile, record, account
}

func TestOAuthSigninSessionAdmissionRetainsSelectedCredentialAndEpochs(t *testing.T) {
	profile, record, account := oauthSigninEffectFixture(t)
	directory, policy, err := oauthSigninSessionAdmission(profile, record, account)
	if err != nil || directory.Query.TenantID != account.Account.TenantID || string(policy.Scope.SubjectID) != string(account.Account.UserID) {
		t.Fatal("original provider session admission", err)
	}
	for name, change := range map[string]func(*kernel.ProviderAccountAdmission){
		"user":               func(a *kernel.ProviderAccountAdmission) { a.Account.UserID = "other" },
		"credential":         func(a *kernel.ProviderAccountAdmission) { a.Credential.Credential.ID = "other" },
		"credential-version": func(a *kernel.ProviderAccountAdmission) { a.Credential.Credential.Version++ },
		"user-epoch":         func(a *kernel.ProviderAccountAdmission) { a.Credential.UserAuthorityVersion++ },
		"identifier-epoch":   func(a *kernel.ProviderAccountAdmission) { a.Credential.IdentifierAuthorityVersion++ },
		"credential-epoch":   func(a *kernel.ProviderAccountAdmission) { a.Credential.CredentialAuthorityVersion++ },
		"absent-link":        func(a *kernel.ProviderAccountAdmission) { a.SocialLinkVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := account
			change(&changed)
			if _, _, err := oauthSigninSessionAdmission(profile, record, changed); err == nil {
				t.Fatal("different account/credential snapshot admitted")
			}
		})
	}
	spec, _ := record.Bindings()
	v, _ := spec.Authority.Bindings()
	v.Factor.Binding.ScopeKey = "foreign-factor"
	spec.Authority, _ = session.NewAuthoritySnapshot(v)
	foreign, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := oauthSigninSessionAdmission(profile, foreign, account); err == nil {
		t.Fatal("foreign factor authority admitted")
	}
}

func TestOAuthSigninEffectRequiresOriginalNativeWork(t *testing.T) {
	profile, _, _ := oauthSigninEffectFixture(t)
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	for _, invalid := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if effect, err := NewOAuthSigninEffect(invalid, profile); effect != nil || err == nil {
			t.Fatal("invalid session configuration admitted")
		}
	}
	wrong := profile
	wrong.AuthenticationMethod = "password"
	wrong.CredentialKind = identity.CredentialPassword
	wrong.CredentialOwner = "identity/password"
	if effect, err := NewOAuthSigninEffect(config, wrong); effect != nil || err == nil {
		t.Fatal("password profile borrowed OAuth issuance")
	}
	effect, err := NewOAuthSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*OAuthSigninEffect{nil, {}, effect} {
		if _, err := candidate.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("unowned callback issued a session")
		}
		if err := candidate.CheckCurrent(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned final check admitted")
		}
		if _, err := candidate.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery manufactured issuance")
		}
	}
	if fmt.Sprintf("%#v", effect) != "postgres.OAuthSigninEffect(redacted)" {
		t.Fatal("deployment profile disclosed")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("deployment profile serialized")
	}
}
