package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func ssoOIDCIssuerFixture(t *testing.T, persistent bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	return ssoIssuerFixture(t, persistent, false)
}

func ssoIssuerFixture(t *testing.T, persistent, oauth2 bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	spec := sessionSpec(t)
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
	vector.ActiveOrganizationID = "organization-a"
	vector.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:organization-a", Version: 3}}
	vector.Authorization = session.AuthorityBinding{ScopeKey: "membership:tenant-a:organization-a:user-a", Version: 4}
	vector.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 1}}
	spec.Version, spec.FamilyVersion = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	spec.Lookup = session.TokenDigest{}
	choice := session.BrowserSession
	if persistent {
		choice = session.PersistentSession
	}
	spec.Remember, _ = session.ResolveRememberPolicy(choice, config())
	b := issueBinding(spec)
	b.UserID, b.ActorID, b.ActorKind = "", "sso-login", authorization.SubjectServiceAccount
	b.AnonymousFlowID, b.RecordID = "original-flow", "AgICAgICAgICAgICAgICAg"
	b.OperationID, b.SchemaID = "identity.sso.oidc-callback", "sso-enterprise-oidc-callback-v1"
	spec.Authentication.Proof.ID = auth.ProofID(b.CommandID)
	spec.Authentication.Proof.Method = "sso-oidc"
	opOwner := "sso/oidc"
	if oauth2 {
		b.OperationID, b.SchemaID = "identity.sso.oauth-callback", "sso-enterprise-oauth2-callback-v1"
		spec.Authentication.Proof.Method, opOwner = "sso-oauth2", "sso/oauth2"
	}
	spec.Authentication.CredentialID = "enterprise-provider-account"
	executor := &issueExecutor{}
	executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		return committedSSOIssue(t, request, oauth2), nil
	}
	executor.recover = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("secret-bearing enterprise recovery was invoked")
		return session.IssueExecution{}, nil
	}
	clock := &mutableIssueClock{now: spec.IssuedAt}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	newIssuer := session.NewSSOOIDCSessionIssuerWithCSRF
	if oauth2 {
		newIssuer = session.NewSSOOAuth2SessionIssuerWithCSRF
	}
	issuer, err := newIssuer(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal("construct enterprise issuer", err)
	}
	credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
	var prepared session.PreparedIssuance
	if oauth2 {
		prepared, err = issuer.PrepareSSOOAuth2(b, session.SSOOAuth2IssuanceSpec{Session: spec, Credential: credential})
	} else {
		prepared, err = issuer.PrepareSSOOIDC(b, session.SSOOIDCIssuanceSpec{Session: spec, Credential: credential})
	}
	if err != nil {
		t.Fatal("prepare original enterprise session", err)
	}
	op := identity.FeatureOperation{Owner: opOwner, OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal("map native enterprise preauth command", err)
	}
	return issuer, prepared, command, executor, clock
}

func committedSSOOIDCIssue(t testing.TB, request session.IssueRequest) session.IssueExecution {
	t.Helper()
	return committedSSOIssue(t, request, false)
}

func committedSSOIssue(t testing.TB, request session.IssueRequest, oauth2 bool) session.IssueExecution {
	t.Helper()
	command, record, ok := request.SSOOIDCCommand()
	if oauth2 {
		if ok {
			t.Fatal("OAuth2 issuance acquired an OIDC command")
		}
		command, record, ok = request.SSOOAuth2Command()
	} else if _, _, ok := request.SSOOAuth2Command(); ok {
		t.Fatal("OIDC issuance acquired an OAuth2 command")
	}
	if !ok {
		t.Fatal("enterprise original command unavailable")
	}
	feature, _ := command.Feature()
	if _, ok := command.PreAuthCookie(); !ok {
		t.Fatal("original preauth custody lost")
	}
	if _, ok := request.Command(); ok {
		t.Fatal("enterprise metadata became a proof-route command")
	}
	if _, ok := request.AuthenticatedProof(); ok {
		t.Fatal("enterprise metadata fabricated opaque proof")
	}
	if _, _, ok := request.OAuthCommand(); ok {
		t.Fatal("enterprise custody became social OAuth")
	}
	if request.Validate(nil, time.Now()) == nil {
		t.Fatal("prospective enterprise metadata admitted as authenticated proof")
	}
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 1, AfterVersion: 2}}, Session: record}
}

func TestSSOOIDCSessionIssuerRetainsOriginalSessionAndRemember(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		issuer, prepared, command, _, _ := ssoOIDCIssuerFixture(t, persistent)
		original, ok := prepared.Session()
		if !ok {
			t.Fatal("original enterprise session unavailable")
		}
		if _, ok := prepared.Request(); ok {
			t.Fatal("unbound enterprise preparation exposed recovery custody")
		}
		bound, err := issuer.BindSSOOIDC(prepared, command)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("bound enterprise preparation exposed recovery custody")
		}
		got, err := issuer.Issue(t.Context(), bound)
		if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed {
			t.Fatal("exact new enterprise commit did not deliver", err)
		}
		before, _ := original.Bindings()
		after, _ := got.Session.Bindings()
		if before != after || got.Cookie.Value != "" || !got.Cookie.Secure || !got.Cookie.HttpOnly || got.Cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("enterprise issuance replaced original metadata or cookie policy")
		}
		if persistent != (got.Cookie.MaxAge > 0 && !got.Cookie.Expires.IsZero()) {
			t.Fatal("enterprise issuance changed original Remember policy")
		}
		if _, err := got.Token.Reveal(); err != nil {
			t.Fatal("new committed token unavailable", err)
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("new committed synchronizer unavailable", err)
		}
		if _, err := issuer.Issue(t.Context(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
			t.Fatal("enterprise preparation executed twice", err)
		}
	}
}

func TestSSOOIDCSessionIssuerWithholdsUnsafeDelivery(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "commit-error", "late-commit", "wrong-start-transition", "changed-user", "changed-organization", "changed-member-version", "changed-credential", "changed-remember", "changed-command"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := ssoOIDCIssuerFixture(t, false)
			bound, err := issuer.BindSSOOIDC(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				result := committedSSOOIDCIssue(t, request)
				spec, _ := result.Session.Bindings()
				vector, _ := spec.Authority.Bindings()
				switch mode {
				case "replay":
					result.Replayed = true
				case "unknown":
					result.Receipt.Outcome, result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 0, 0
					result.Session = session.Session{}
				case "commit-error":
					return result, errors.New("private native detail")
				case "late-commit":
					clock.now = spec.Authentication.Proof.ExpiresAt
				case "wrong-start-transition":
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 0, 1
				case "changed-user":
					spec.UserID, spec.Authentication.Proof.Subject = "other-user", "other-user"
				case "changed-organization":
					vector.ActiveOrganizationID = "other-organization"
					vector.Organization.Binding.ScopeKey = "organization:tenant-a:other-organization"
				case "changed-member-version":
					vector.Authorization.Version++
				case "changed-credential":
					spec.Authentication.CredentialID = "other-provider-account"
				case "changed-remember":
					spec.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, config())
				case "changed-command":
					result.Receipt.Binding.RecordID = "AwMDAwMDAwMDAwMDAwMDAw"
				}
				if mode == "changed-user" || mode == "changed-organization" || mode == "changed-member-version" || mode == "changed-credential" || mode == "changed-remember" {
					spec.Authority, _ = session.NewAuthoritySnapshot(vector)
					result.Session, err = session.NewSession(spec)
					if err != nil {
						t.Fatal("invalid substituted-session fixture", err)
					}
				}
				return result, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("unsafe enterprise delivery accepted")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("nondeliverable result disclosed synchronizer")
			}
		})
	}
}

func TestSSOOIDCSessionIssuerRejectsForeignScopeAndProvenance(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *session.SessionSpec){
		"foreign tenant":          func(b *identity.CommandBinding, _ *session.SessionSpec) { b.TenantID = "foreign" },
		"selected caller user":    func(b *identity.CommandBinding, s *session.SessionSpec) { b.UserID = s.UserID },
		"missing original flow":   func(b *identity.CommandBinding, _ *session.SessionSpec) { b.AnonymousFlowID = "" },
		"human caller":            func(b *identity.CommandBinding, _ *session.SessionSpec) { b.ActorKind = authorization.SubjectUser },
		"social operation":        func(b *identity.CommandBinding, _ *session.SessionSpec) { b.OperationID = "identity.oauth.callback" },
		"social schema":           func(b *identity.CommandBinding, _ *session.SessionSpec) { b.SchemaID = "oauth-signin-callback-v1" },
		"missing start command":   func(b *identity.CommandBinding, _ *session.SessionSpec) { b.RecordID = "" },
		"malformed start command": func(b *identity.CommandBinding, _ *session.SessionSpec) { b.RecordID = "not-a-command" },
		"reused start command":    func(b *identity.CommandBinding, _ *session.SessionSpec) { b.RecordID = string(b.CommandID) },
		"different proof command": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.Authentication.Proof.ID = "AwMDAwMDAwMDAwMDAwMDAw"
		},
		"social provenance": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.Authentication.Proof.Method = "oauth" },
		"non-session purpose": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.Authentication.Proof.Purpose = "reauthenticate"
		},
		"advanced family": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.FamilyVersion++ },
		"changed original activity": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.LastActivityAt = s.IssuedAt.Add(time.Second)
		},
		"unresolved remember": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.Remember = session.RememberPolicy{} },
		"missing organization": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.ActiveOrganizationID, v.Organization = "", session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
		"missing factor fence": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Factor = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
		"passkey profile": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant-a:other", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, prepared, command, _, _ := ssoOIDCIssuerFixture(t, false)
			record, _ := prepared.Session()
			spec, _ := record.Bindings()
			spec.Lookup = session.TokenDigest{}
			feature, _ := command.Feature()
			change(&feature.Binding, &spec)
			credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
			if _, err := issuer.PrepareSSOOIDC(feature.Binding, session.SSOOIDCIssuanceSpec{Session: spec, Credential: credential}); err == nil {
				t.Fatal("changed enterprise profile admitted")
			}
		})
	}
}

func TestSSOOIDCSessionIssuerBindsExactSSOCredentialOwner(t *testing.T) {
	for name, change := range map[string]func(*identity.CredentialRef){
		"social owner":       func(c *identity.CredentialRef) { c.Owner = "identity/oauth" },
		"password kind":      func(c *identity.CredentialRef) { c.Kind, c.Owner = identity.CredentialPassword, "identity/password" },
		"foreign tenant":     func(c *identity.CredentialRef) { c.TenantID = "foreign" },
		"foreign user":       func(c *identity.CredentialRef) { c.UserID = "foreign" },
		"foreign credential": func(c *identity.CredentialRef) { c.ID = "foreign" },
		"different version":  func(c *identity.CredentialRef) { c.Version++ },
		"zero version":       func(c *identity.CredentialRef) { c.Version = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			issuer, prepared, command, _, _ := ssoOIDCIssuerFixture(t, false)
			record, _ := prepared.Session()
			spec, _ := record.Bindings()
			spec.Lookup = session.TokenDigest{}
			feature, _ := command.Feature()
			credential := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion}
			change(&credential)
			got, err := issuer.PrepareSSOOIDC(feature.Binding, session.SSOOIDCIssuanceSpec{Session: spec, Credential: credential})
			if err == nil {
				t.Fatal("mislabeled enterprise credential admitted")
			}
			if _, ok := got.Session(); ok {
				t.Fatal("invalid enterprise input retained a session")
			}
		})
	}
}

func TestSSOOIDCSessionIssuerBindIsSharedAndProfileDisjoint(t *testing.T) {
	issuer, prepared, command, _, _ := ssoOIDCIssuerFixture(t, false)
	feature, _ := command.Feature()
	plain, _ := identity.NewFeatureCommand(feature)
	if _, err := issuer.BindSSOOIDC(prepared, plain); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("missing original preauth accepted", err)
	}
	_, _, social, _, _ := oauthIssuerFixture(t, false)
	if _, err := issuer.BindSSOOIDC(prepared, social); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("social OAuth admitted to enterprise session", err)
	}
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := issuer.BindSSOOIDC(prepared, command); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Error("unexpected enterprise bind result", err)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatal("copied enterprise preparation bound more than once")
	}
	if _, _, ok := (session.IssueRequest{}).SSOOIDCCommand(); ok {
		t.Fatal("zero enterprise request exposed custody")
	}
}

func TestSSOOIDCSessionIssuerSpecRedactsAuthenticationAndOrganization(t *testing.T) {
	spec := session.SSOOIDCIssuanceSpec{Session: sessionSpec(t), Credential: identity.CredentialRef{ID: "private-provider-account", Owner: "sso"}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, spec); got != "session.SSOOIDCIssuanceSpec(redacted)" {
			t.Fatal("enterprise spec exposed authentication metadata")
		}
	}
	if _, err := json.Marshal(spec); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("enterprise spec permitted implicit JSON export", err)
	}
	if _, err := spec.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("enterprise spec permitted implicit text export", err)
	}
}
