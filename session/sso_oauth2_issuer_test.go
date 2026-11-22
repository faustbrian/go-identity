package session_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOOAuth2SessionIssuerKeepsOriginalProfileAndRevealsOnlyOnNewCommit(t *testing.T) {
	for _, mode := range []string{"commit", "replay", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, _ := ssoIssuerFixture(t, true, true)
			if _, err := issuer.BindSSOOIDC(prepared, command); !errors.Is(err, session.ErrInvalidIssuance) {
				t.Fatal("OIDC binding accepted prepared OAuth2 custody", err)
			}
			bound, err := issuer.BindSSOOAuth2(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := bound.Request(); ok {
				t.Fatal("enterprise OAuth2 exposed generic recovery custody")
			}
			executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				out := committedSSOIssue(t, r, true)
				if mode == "unknown" {
					out.Receipt.Outcome, out.Receipt.AuditEventID, out.Session = identity.CommitOutcomeUnknown, "", session.Session{}
					out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 0
					if err := out.Receipt.Validate(); err != nil {
						t.Fatalf("invalid unknown-commit fixture: %v", err)
					}
				}
				out.Replayed = mode == "replay"
				return out, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			if mode == "commit" {
				wanted, _ := prepared.Session()
				before, _ := wanted.Bindings()
				after, _ := got.Session.Bindings()
				if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed || before != after || got.Cookie.MaxAge <= 0 || after.Authentication.Proof.Method != "sso-oauth2" {
					t.Fatal("new OAuth2 receipt lost its original method, session or remember policy", err)
				}
				if _, err := got.Token.Reveal(); err != nil {
					t.Fatal("new committed session withheld its exact credential", err)
				}
				if _, err := bound.CSRFToken(); err != nil {
					t.Fatal("new committed session withheld its synchronizer", err)
				}
			} else {
				if mode == "replay" && (err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || !got.Replayed) || mode == "unknown" && got.CommitOutcome != identity.CommitOutcomeUnknown {
					t.Fatal("OAuth2 did not retain the exact outcome", mode, err)
				}
				if _, err := got.Token.Reveal(); err == nil {
					t.Fatal("OAuth2 replay or uncertainty delivered credentials")
				}
				if _, err := bound.CSRFToken(); err == nil {
					t.Fatal("OAuth2 replay or uncertainty delivered a synchronizer")
				}
			}
		})
	}
}

func TestSSOOAuth2SessionIssuerRejectsOIDCMethodAndOrdinaryIssueRoute(t *testing.T) {
	issuer, prepared, command, _, _ := ssoIssuerFixture(t, false, true)
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	ordinary, _, proof, _ := issueRequestFixture(t)
	issue, _ := ordinary.Issue()
	ordinarySpec, _ := issue.Session.Bindings()
	ordinarySpec.Lookup = session.TokenDigest{}
	if _, err := issuer.Prepare(issue.Binding, ordinarySpec, proof); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("enterprise OAuth bypassed its selected callback preparation", err)
	}
	feature, _ := command.Feature()
	credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
	if _, err := issuer.PrepareSSOOAuth2(feature.Binding, session.SSOOAuth2IssuanceSpec{Session: spec, Credential: credential}); err != nil {
		t.Fatal("unmodified exact profile rejected", err)
	}
	spec.Authentication.Proof.Method = "sso-oidc"
	if _, err := issuer.PrepareSSOOAuth2(feature.Binding, session.SSOOAuth2IssuanceSpec{Session: spec, Credential: credential}); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("enterprise OAuth accepted OIDC authentication provenance", err)
	}
}
