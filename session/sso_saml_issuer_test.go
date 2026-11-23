package session_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOSAMLSessionIssuerPreservesMethodAndWithholdsRecoveryCredentials(t *testing.T) {
	for _, mode := range []string{"commit", "replay", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			_, original, oidc, executor, clock := ssoOIDCIssuerFixture(t, true)
			record, _ := original.Session()
			spec, _ := record.Bindings()
			spec.Lookup = session.TokenDigest{}
			spec.Authentication.Proof.Method = "sso-saml"
			oldFeature, _ := oidc.Feature()
			binding := oldFeature.Binding
			binding.OperationID, binding.SchemaID = "identity.sso.saml-acs", "sso-enterprise-saml-acs-v1"
			operation := identity.FeatureOperation{Owner: "sso/saml", OperationID: binding.OperationID, SchemaID: binding.SchemaID, SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
			credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
			key, _ := session.NewDigestKey(1, make([]byte, 32))
			csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
			issuer, err := session.NewSSOSAMLSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
			if err != nil {
				t.Fatal("select SAML session issuer", err)
			}
			bad := spec
			bad.Authentication.Proof.Method = "sso-oidc"
			if _, err := issuer.PrepareSSOSAML(binding, session.SSOSAMLIssuanceSpec{Session: bad, Credential: credential}); !errors.Is(err, session.ErrInvalidIssuance) {
				t.Fatal("SAML issuer allowed OIDC provenance", err)
			}
			prepared, err := issuer.PrepareSSOSAML(binding, session.SSOSAMLIssuanceSpec{Session: spec, Credential: credential})
			if err != nil {
				t.Fatal("prepare prospective linked SAML session", err)
			}
			if _, err := issuer.BindSSOSAML(prepared, oidc); !errors.Is(err, session.ErrInvalidIssuance) {
				t.Fatal("foreign callback supplied browser custody for SAML", err)
			}
			borrowed, _ := oidc.PreAuthCookie()
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation}, borrowed)
			if err != nil {
				t.Fatal("construct original SAML browser command", err)
			}
			bound, err := issuer.BindSSOSAML(prepared, command)
			if err != nil {
				t.Fatal("bind native SAML command", err)
			}
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				actual, prospective, ok := request.SSOSAMLCommand()
				if !ok || actual != command {
					t.Fatal("native executor did not get only the original SAML custody")
				}
				if _, _, ok := request.SSOOIDCCommand(); ok {
					t.Fatal("SAML request acquired an OIDC identity")
				}
				if _, _, ok := request.SSOOAuth2Command(); ok {
					t.Fatal("SAML request acquired an OAuth2 identity")
				}
				out := session.IssueExecution{Receipt: identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: operation, BeforeVersion: 1, AfterVersion: 2}}, Session: prospective, Replayed: mode == "replay"}
				if mode == "unknown" {
					out.Receipt.Outcome, out.Receipt.AuditEventID, out.Session = identity.CommitOutcomeUnknown, "", session.Session{}
					out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 0
				}
				return out, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			_, tokenErr := got.Token.Reveal()
			_, csrfErr := bound.CSRFToken()
			if mode == "commit" {
				actual, bindErr := got.Session.Bindings()
				if err != nil || bindErr != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || tokenErr != nil || csrfErr != nil || got.Cookie.SameSite != http.SameSiteLaxMode || actual.Authentication.Proof.Method != "sso-saml" || actual.Remember != spec.Remember {
					t.Fatal("committed SAML session lost its exact method, lifetime or normal cookie policy", err)
				}
				return
			}
			if tokenErr == nil || csrfErr == nil || mode == "unknown" && got.CommitOutcome != identity.CommitOutcomeUnknown || mode == "replay" && (err != nil || !got.Replayed || got.CommitOutcome != identity.CommitOutcomeCommitted) {
				t.Fatal("SAML replay or uncertainty disclosed a session or changed the original outcome", mode, err)
			}
		})
	}
}
