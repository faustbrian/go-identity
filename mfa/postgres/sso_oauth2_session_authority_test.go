package mfapostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func ssoOAuth2FactorSession(t testing.TB) session.Session {
	t.Helper()
	spec, err := passkeyFactorSession(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector.Passkey = session.OptionalAuthorityBinding{}
	vector.ActiveOrganizationID = "organization-a"
	vector.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:organization-a", Version: 1}}
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.Method = "sso-oauth2"
	spec.Authentication.Proof.Assurance = auth.AssuranceSingleFactor
	spec.Authentication.CredentialID = "sso-provider-account"
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestSSOOAuth2SessionFactorProfile(t *testing.T) {
	original := ssoOAuth2FactorSession(t)
	if spec, version, err := ssoOAuth2SessionFactors(original); err != nil || version != 1 || spec.TenantID != "tenant-a" || spec.UserID != "user-a" {
		t.Fatal("enterprise factor profile lost original identity", err)
	}
	for _, mode := range []string{"oidc", "oauth2-alias", "wrong-purpose", "social", "password", "passkey", "unverified", "multi-factor", "missing-organization", "missing-factor", "foreign-factor", "foreign-tenant-factor", "passkey-authority"} {
		t.Run(mode, func(t *testing.T) {
			spec, _ := original.Bindings()
			vector, _ := spec.Authority.Bindings()
			switch mode {
			case "oidc":
				spec.Authentication.Proof.Method = "sso-oidc"
			case "oauth2-alias":
				spec.Authentication.Proof.Method = "sso-oauth"
			case "wrong-purpose":
				spec.Authentication.Proof.Purpose = "other-purpose"
			case "social":
				spec.Authentication.Proof.Method = "oauth"
			case "password":
				spec.Authentication.Proof.Method = "password"
			case "passkey":
				spec.Authentication.Proof.Method = "passkey"
			case "unverified":
				spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
				vector.Factor = session.OptionalAuthorityBinding{}
			case "multi-factor":
				spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
			case "missing-organization":
				vector.ActiveOrganizationID, vector.Organization = "", session.OptionalAuthorityBinding{}
			case "missing-factor":
				vector.Factor = session.OptionalAuthorityBinding{}
			case "foreign-factor":
				vector.Factor.Binding.ScopeKey, _ = FactorAuthorityKey("tenant-a", "other-user")
			case "foreign-tenant-factor":
				vector.Factor.Binding.ScopeKey, _ = FactorAuthorityKey("other-tenant", "user-a")
			case "passkey-authority":
				vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 1}}
			}
			var err error
			spec.Authority, err = session.NewAuthoritySnapshot(vector)
			if err != nil {
				t.Fatal("profile fixture", err)
			}
			record, err := session.NewSession(spec)
			if err != nil {
				t.Fatal("profile fixture", err)
			}
			if _, _, err := ssoOAuth2SessionFactors(record); err == nil {
				t.Fatal("foreign enterprise factor profile admitted")
			}
		})
	}
	if _, _, err := ssoOIDCSessionFactors(original); err == nil {
		t.Fatal("OAuth profile widened OIDC acceptance")
	}
	if _, _, err := ssoOAuth2SessionFactors(ssoOIDCFactorSession(t)); err == nil {
		t.Fatal("OIDC profile widened OAuth acceptance")
	}
	if _, _, err := oauthSessionFactors(original); err == nil {
		t.Fatal("enterprise profile widened social acceptance")
	}
}

func TestSSOOAuth2FactorsRejectUnownedInvocation(t *testing.T) {
	record := ssoOAuth2FactorSession(t)
	for _, ctx := range []context.Context{nil, t.Context()} {
		if state, err := ReadSSOOAuth2SigninFactors(ctx, nil, "tenant-a", "user-a", time.Second); err == nil || state.Version() != 0 {
			t.Fatal("missing primary supplied factor metadata")
		}
		if state, err := RequireSSOOAuth2SigninFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned enterprise callback supplied factor authority")
		}
		if err := ReadSSOOAuth2SessionFactors(ctx, nil, record, time.Second); err == nil {
			t.Fatal("missing primary supplied session factor authority")
		}
		if err := RequireSSOOAuth2SessionFactors(ctx, kernel.Work{}, nil, record); err == nil {
			t.Fatal("unowned revoke-one supplied session factor authority")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RequireSSOOAuth2SigninFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil {
		t.Fatal("cancelled unowned callback admitted")
	}
	if err := RequireSSOOAuth2SessionFactors(ctx, kernel.Work{}, nil, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled revoke-one lost cancellation", err)
	}
}
