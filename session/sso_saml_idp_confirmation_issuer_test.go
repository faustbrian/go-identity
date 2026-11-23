package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func samlIDPConfirmationIssuerFixture(t *testing.T, persistent bool) (*session.SessionIssuer, identity.FeatureCommandSpec, session.SSOSAMLIssuanceSpec, *issueExecutor) {
	t.Helper()
	_, original, spCommand, executor, clock := ssoIssuerFixtureForMethod(t, persistent, "sso-saml")
	record, _ := original.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	feature, _ := spCommand.Feature()
	feature.Operation = identity.FeatureOperation{
		Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", SchemaID: "sso-enterprise-saml-idp-init-v1",
		SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectUser, RecordRequirement: identity.FeatureRecordRequired,
	}
	feature.Binding.OperationID, feature.Binding.SchemaID = feature.Operation.OperationID, feature.Operation.SchemaID
	feature.Binding.UserID, feature.Binding.AnonymousFlowID = spec.UserID, ""
	feature.Binding.ActorID = "native-saml-confirmation"
	credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	issuer, err := session.NewSSOSAMLIDPConfirmationSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal("select native IdP confirmation issuer", err)
	}
	return issuer, feature, session.SSOSAMLIssuanceSpec{Session: spec, Credential: credential}, executor
}

func samlIDPConfirmationIssuerCommand(t *testing.T, feature identity.FeatureCommandSpec) identity.Command {
	t.Helper()
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	form := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	command, err := identity.NewFeatureSAMLIDPConfirmationCommand(feature, auth.NewBearerCredential(cookie), auth.NewBearerCredential(form))
	if err != nil {
		t.Fatal("construct paired native confirmation custody", err)
	}
	return command
}

func TestSSOSAMLIDPConfirmationIssuerRetainsExactIntentAndNormalSessionDelivery(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		issuer, feature, input, executor := samlIDPConfirmationIssuerFixture(t, persistent)
		arrival, err := identity.ParseCommandID(feature.Binding.RecordID)
		if err != nil || arrival == feature.Binding.CommandID || feature.Binding.UserID != input.Session.UserID || feature.Binding.ActorID == identity.ActorID(input.Session.UserID) || feature.Binding.ActorKind != authorization.SubjectServiceAccount || feature.Binding.AnonymousFlowID != "" {
			t.Fatal("fixture lost native user, actor or distinct retained arrival")
		}
		prepared, err := issuer.PrepareSSOSAMLIDPConfirmation(feature.Binding, input)
		if err != nil {
			t.Fatal("prepare user-targeted confirmation session", err)
		}
		original, ok := prepared.Session()
		if !ok {
			t.Fatal("prospective confirmation session unavailable")
		}
		command := samlIDPConfirmationIssuerCommand(t, feature)
		bound, err := issuer.BindSSOSAMLIDPConfirmation(prepared, command)
		if err != nil {
			t.Fatal("bind both submitted confirmation credentials", err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("confirmation custody exposed as historical recovery input")
		}
		if _, err := bound.CSRFToken(); err == nil {
			t.Fatal("prospective confirmation disclosed synchronizer before commit")
		}
		calls := 0
		executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
			calls++
			actual, prospective, ok := request.SSOSAMLIDPConfirmationCommand()
			if !ok || actual != command {
				t.Fatal("native executor did not receive original paired custody")
			}
			projection, ok := actual.SAMLIDPConfirmationFeature()
			cookie, form, custody := actual.SAMLIDPConfirmationCustody()
			wantCookie, wantForm, _ := command.SAMLIDPConfirmationCustody()
			if !ok || !custody || projection.Binding != feature.Binding || projection.Operation != feature.Operation || cookie.Token() != wantCookie.Token() || form.Token() != wantForm.Token() || cookie.Token() == form.Token() {
				t.Fatal("native confirmation lost exact target, pending record or independent credentials")
			}
			if _, _, ok := request.SSOSAMLCommand(); ok {
				t.Fatal("IdP confirmation acquired SP callback custody")
			}
			if _, _, ok := request.SSOOIDCCommand(); ok {
				t.Fatal("IdP confirmation acquired OIDC custody")
			}
			if _, _, ok := request.SSOOAuth2Command(); ok {
				t.Fatal("IdP confirmation acquired OAuth custody")
			}
			if _, ok := request.Command(); ok {
				t.Fatal("confirmation metadata fabricated a proof-route command")
			}
			if _, ok := request.AuthenticatedProof(); ok {
				t.Fatal("confirmation custody fabricated authenticated proof")
			}
			if request.Validate(nil, input.Session.IssuedAt) == nil {
				t.Fatal("confirmation metadata admitted as verified authority")
			}
			return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 1, AfterVersion: 2}}, Session: prospective}, nil
		}
		got, err := issuer.Issue(t.Context(), bound)
		if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.CommandID != feature.Binding.CommandID || got.Replayed {
			t.Fatal("exact acknowledged confirmation did not deliver", err)
		}
		before, _ := original.Bindings()
		after, _ := got.Session.Bindings()
		if before != after || after.UserID != feature.Binding.UserID || after.Authentication.Proof.ID != auth.ProofID(feature.Binding.CommandID) || after.Authentication.Proof.Method != "sso-saml" || after.Authentication != input.Session.Authentication || after.Remember != input.Session.Remember {
			t.Fatal("confirmation replaced selected user, original signed intent or compatible SAML method")
		}
		if got.Cookie.Value != "" || !got.Cookie.Secure || !got.Cookie.HttpOnly || got.Cookie.Name != "__Host-session" || got.Cookie.SameSite != http.SameSiteLaxMode || persistent != (got.Cookie.MaxAge > 0 && !got.Cookie.Expires.IsZero()) {
			t.Fatal("confirmation changed normal session cookie or original remember choice")
		}
		if _, err := got.Token.Reveal(); err != nil {
			t.Fatal("new exact confirmation withheld session token", err)
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("new exact confirmation withheld synchronizer", err)
		}
		if _, err := issuer.Issue(t.Context(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) || calls != 1 {
			t.Fatal("confirmation preparation executed more than once", err)
		}
	}
}

func TestSSOSAMLIDPConfirmationIssuerRejectsForeignPreparation(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *session.SSOSAMLIssuanceSpec){
		"anonymous flow": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) {
			b.UserID, b.AnonymousFlowID = "", "sp-flow"
		},
		"mixed anonymous flow": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) { b.AnonymousFlowID = "sp-flow" },
		"wrong bound user":     func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) { b.UserID = "other-user" },
		"human actor": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) {
			b.ActorKind = authorization.SubjectUser
		},
		"SP operation": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) {
			b.OperationID = "identity.sso.saml-acs"
		},
		"SP schema": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) {
			b.SchemaID = "sso-enterprise-saml-acs-v1"
		},
		"missing pending arrival":      func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) { b.RecordID = "" },
		"malformed pending arrival":    func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) { b.RecordID = "pending-record" },
		"arrival reused as completion": func(b *identity.CommandBinding, _ *session.SSOSAMLIssuanceSpec) { b.RecordID = string(b.CommandID) },
		"wrong intent command": func(_ *identity.CommandBinding, s *session.SSOSAMLIssuanceSpec) {
			s.Session.Authentication.Proof.ID = "AwMDAwMDAwMDAwMDAwMDAw"
		},
		"wrong signed method": func(_ *identity.CommandBinding, s *session.SSOSAMLIssuanceSpec) {
			s.Session.Authentication.Proof.Method = "sso-oidc"
		},
		"wrong provider user": func(_ *identity.CommandBinding, s *session.SSOSAMLIssuanceSpec) { s.Credential.UserID = "other-user" },
		"wrong provider owner": func(_ *identity.CommandBinding, s *session.SSOSAMLIssuanceSpec) {
			s.Credential.Owner = "identity/oauth"
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, feature, input, _ := samlIDPConfirmationIssuerFixture(t, false)
			change(&feature.Binding, &input)
			got, err := issuer.PrepareSSOSAMLIDPConfirmation(feature.Binding, input)
			if err == nil {
				t.Fatal("foreign confirmation preparation admitted")
			}
			if _, ok := got.Session(); ok {
				t.Fatal("denied confirmation retained prospective session")
			}
		})
	}
}

func TestSSOSAMLIDPConfirmationIssuerRequiresExactPairedVariant(t *testing.T) {
	issuer, feature, input, _ := samlIDPConfirmationIssuerFixture(t, false)
	prepared, err := issuer.PrepareSSOSAMLIDPConfirmation(feature.Binding, input)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := identity.NewFeatureCommand(feature)
	if err != nil {
		t.Fatal(err)
	}
	spIssuer, spPrepared, spCommand, _, _ := ssoIssuerFixtureForMethod(t, false, "sso-saml")
	wrongUser := feature
	wrongUser.Binding.UserID = "other-user"
	wrongArrival := feature
	wrongArrival.Binding.RecordID = "AwMDAwMDAwMDAwMDAwMDAw"
	wrongCommand := feature
	wrongCommand.Binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	for _, command := range []identity.Command{identity.Command{}, metadata, spCommand, samlIDPConfirmationIssuerCommand(t, wrongUser), samlIDPConfirmationIssuerCommand(t, wrongArrival), samlIDPConfirmationIssuerCommand(t, wrongCommand)} {
		if _, err := issuer.BindSSOSAMLIDPConfirmation(prepared, command); !errors.Is(err, session.ErrInvalidIssuance) {
			t.Fatal("missing pair or foreign original scope bound confirmation", err)
		}
	}
	confirmation := samlIDPConfirmationIssuerCommand(t, feature)
	if _, err := spIssuer.BindSSOSAML(spPrepared, confirmation); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("SP issuer accepted IdP confirmation custody", err)
	}
	if _, err := issuer.BindSSOSAMLIDPConfirmation(spPrepared, confirmation); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("confirmation issuer accepted SP preparation", err)
	}
	if _, err := issuer.BindSSOSAMLIDPConfirmation(prepared, confirmation); err != nil {
		t.Fatal("rejected commands consumed exact confirmation binding claim", err)
	}
	if _, err := issuer.BindSSOSAMLIDPConfirmation(prepared, confirmation); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
		t.Fatal("copied preparation bound a second confirmation", err)
	}
	if _, _, ok := (session.IssueRequest{}).SSOSAMLIDPConfirmationCommand(); ok {
		t.Fatal("zero request exposed native confirmation")
	}
}

func TestSSOSAMLIDPConfirmationIssuerWithholdsReplayUnknownAndSubstitutedSession(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "commit-error", "wrong-user", "wrong-pending", "wrong-transition"} {
		t.Run(mode, func(t *testing.T) {
			issuer, feature, input, executor := samlIDPConfirmationIssuerFixture(t, false)
			prepared, err := issuer.PrepareSSOSAMLIDPConfirmation(feature.Binding, input)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := issuer.BindSSOSAMLIDPConfirmation(prepared, samlIDPConfirmationIssuerCommand(t, feature))
			if err != nil {
				t.Fatal(err)
			}
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				_, prospective, ok := request.SSOSAMLIDPConfirmationCommand()
				if !ok {
					t.Fatal("native confirmation unavailable")
				}
				out := session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 1, AfterVersion: 2}}, Session: prospective}
				switch mode {
				case "replay":
					out.Replayed = true
				case "unknown":
					out.Receipt.Outcome, out.Receipt.AuditEventID, out.Session = identity.CommitOutcomeUnknown, "", session.Session{}
					out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 0
				case "commit-error":
					return out, errors.New("private native detail")
				case "wrong-user":
					spec, _ := prospective.Bindings()
					spec.UserID, spec.Authentication.Proof.Subject = "other-user", "other-user"
					out.Session, err = session.NewSession(spec)
					if err != nil {
						t.Fatal("invalid substituted session fixture", err)
					}
				case "wrong-pending":
					out.Receipt.Binding.RecordID = "AwMDAwMDAwMDAwMDAwMDAw"
				case "wrong-transition":
					out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 1
				}
				return out, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			if mode == "replay" {
				if err != nil || !got.Replayed || got.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("historical confirmation lost committed replay outcome", err)
				}
			} else if err == nil {
				t.Fatal("uncertain or substituted confirmation accepted")
			}
			if mode == "unknown" && got.CommitOutcome != identity.CommitOutcomeUnknown {
				t.Fatal("uncertainty inferred a definite confirmation outcome")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("replay or uncertain confirmation disclosed synchronizer")
			}
		})
	}
}
