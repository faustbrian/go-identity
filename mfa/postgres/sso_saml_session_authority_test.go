package mfapostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func ssoSAMLFactorSession(t testing.TB) session.Session {
	t.Helper()
	spec, err := ssoOIDCFactorSession(t).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.Method = "sso-saml"
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestSSOSAMLSessionFactorProfile(t *testing.T) {
	original := ssoSAMLFactorSession(t)
	if spec, version, err := ssoSAMLSessionFactors(original); err != nil || version != 1 || spec.TenantID != "tenant-a" || spec.UserID != "user-a" {
		t.Fatal("SAML factor profile lost original identity", err)
	}
	for _, mode := range []string{"oidc", "oauth2", "saml-alias", "wrong-purpose", "social", "password", "passkey", "unverified", "multi-factor", "missing-organization", "missing-factor", "foreign-factor", "foreign-tenant-factor", "passkey-authority"} {
		t.Run(mode, func(t *testing.T) {
			spec, _ := original.Bindings()
			vector, _ := spec.Authority.Bindings()
			switch mode {
			case "oidc":
				spec.Authentication.Proof.Method = "sso-oidc"
			case "oauth2":
				spec.Authentication.Proof.Method = "sso-oauth2"
			case "saml-alias":
				spec.Authentication.Proof.Method = "saml"
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
			if _, _, err := ssoSAMLSessionFactors(record); err == nil {
				t.Fatal("foreign SAML factor profile admitted")
			}
		})
	}
	if _, _, err := ssoOIDCSessionFactors(original); err == nil {
		t.Fatal("SAML profile widened OIDC acceptance")
	}
	if _, _, err := ssoOAuth2SessionFactors(original); err == nil {
		t.Fatal("SAML profile widened OAuth2 acceptance")
	}
	if _, _, err := oauthSessionFactors(original); err == nil {
		t.Fatal("SAML profile widened social acceptance")
	}
}

func TestSSOSAMLSessionFactorsRejectUnownedInvocation(t *testing.T) {
	record := ssoSAMLFactorSession(t)
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := ReadSSOSAMLSessionFactors(ctx, nil, record, time.Second); err == nil {
			t.Fatal("missing primary supplied SAML session factor authority")
		}
		if err := RequireSSOSAMLSessionFactors(ctx, kernel.Work{}, nil, record); err == nil {
			t.Fatal("unowned revoke-one supplied SAML session factor authority")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequireSSOSAMLSessionFactors(ctx, kernel.Work{}, nil, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled revoke-one lost cancellation", err)
	}
	for _, invalid := range []session.Session{{}, ssoOIDCFactorSession(t), ssoOAuth2FactorSession(t)} {
		if err := RequireSSOSAMLSessionFactors(t.Context(), kernel.Work{}, nil, invalid); err == nil {
			t.Fatal("foreign session supplied SAML factor authority")
		}
	}
}
