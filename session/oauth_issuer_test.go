package session_test

import (
	"context"
	"encoding/base64"
	"errors"
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

func oauthIssuerFixture(t *testing.T, persistent bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	spec := sessionSpec(t)
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
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
	b.UserID, b.ActorID, b.ActorKind = "", "oauth-login", authorization.SubjectServiceAccount
	b.AnonymousFlowID, b.RecordID = "original-flow", ""
	b.OperationID, b.SchemaID = "identity.oauth.callback", "oauth-signin-callback-v1"
	spec.Authentication.Proof.ID = auth.ProofID(b.CommandID)
	spec.Authentication.Proof.Method = "oauth"
	spec.Authentication.CredentialID = "provider-account"
	executor := &issueExecutor{}
	executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		return committedOAuthIssue(t, request), nil
	}
	executor.recover = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("secret-bearing OAuth recovery was invoked")
		return session.IssueExecution{}, nil
	}
	clock := &mutableIssueClock{now: spec.IssuedAt}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	issuer, err := session.NewOAuthSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal("construct prospective OAuth issuer", err)
	}
	prepared, err := issuer.PrepareOAuth(b, spec)
	if err != nil {
		t.Fatal("prepare original OAuth session", err)
	}
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal("map native OAuth preauth command", err)
	}
	return issuer, prepared, command, executor, clock
}

func committedOAuthIssue(t testing.TB, request session.IssueRequest) session.IssueExecution {
	t.Helper()
	command, record, ok := request.OAuthCommand()
	if !ok {
		t.Fatal("OAuth original command unavailable")
	}
	feature, _ := command.Feature()
	if _, ok := command.PreAuthCookie(); !ok {
		t.Fatal("original preauth possession lost")
	}
	if _, ok := request.Command(); ok {
		t.Fatal("prospective OAuth issuance became a proof-route command")
	}
	if _, ok := request.AuthenticatedProof(); ok {
		t.Fatal("prospective OAuth issuance fabricated opaque proof")
	}
	if _, _, ok := request.PasswordCommand(); ok {
		t.Fatal("OAuth reused password authentication")
	}
	if request.Validate(nil, time.Now()) == nil {
		t.Fatal("prospective OAuth metadata admitted as authenticated proof")
	}
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation}}, Session: record}
}

func TestOAuthSessionIssuerDeliversOnlyExactFreshCommit(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		issuer, prepared, command, executor, _ := oauthIssuerFixture(t, persistent)
		var calls atomic.Int32
		execute := executor.execute
		executor.execute = func(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
			calls.Add(1)
			return execute(ctx, request)
		}
		original, ok := prepared.Session()
		if !ok {
			t.Fatal("original prepared session unavailable")
		}
		if _, ok := prepared.Request(); ok {
			t.Fatal("unbound OAuth preparation advertised recovery custody")
		}
		bound, err := issuer.BindOAuth(prepared, command)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("bound OAuth preparation advertised secret-bearing recovery")
		}
		got, err := issuer.Issue(t.Context(), bound)
		if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed || calls.Load() != 1 {
			t.Fatal("exact new native commit did not deliver", err)
		}
		before, _ := original.Bindings()
		after, _ := got.Session.Bindings()
		if before != after || got.Cookie.Value != "" || !got.Cookie.Secure || !got.Cookie.HttpOnly || got.Cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("OAuth issuance replaced original metadata or cookie policy")
		}
		if persistent != (got.Cookie.MaxAge > 0 && !got.Cookie.Expires.IsZero()) {
			t.Fatal("OAuth changed the original Remember policy")
		}
		if _, err := got.Token.Reveal(); err != nil {
			t.Fatal("new committed token unavailable", err)
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("new committed synchronizer unavailable", err)
		}
		if _, err := issuer.Issue(t.Context(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
			t.Fatal("OAuth preparation executed twice", err)
		}
	}
}

func TestOAuthSessionIssuerWithholdsReplayUnknownAndExpiredDelivery(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "commit-error", "late-commit", "changed-session"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := oauthIssuerFixture(t, false)
			bound, err := issuer.BindOAuth(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				result := committedOAuthIssue(t, request)
				switch mode {
				case "replay":
					result.Replayed = true
				case "unknown":
					result.Receipt.Outcome, result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
					result.Session = session.Session{}
				case "commit-error":
					return result, errors.New("private native detail")
				case "late-commit":
					spec, _ := result.Session.Bindings()
					clock.now = spec.Authentication.Proof.ExpiresAt
				case "changed-session":
					spec, _ := result.Session.Bindings()
					spec.Authentication.CredentialID = "another-provider-account"
					result.Session, _ = session.NewSession(spec)
				}
				return result, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("unsafe delivery accepted")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("nondeliverable OAuth result disclosed synchronizer")
			}
		})
	}
}

func TestOAuthSessionIssuerBindIsSharedAndRejectsOtherMethods(t *testing.T) {
	issuer, prepared, command, _, _ := oauthIssuerFixture(t, false)
	feature, _ := command.Feature()
	plain, _ := identity.NewFeatureCommand(feature)
	if _, err := issuer.BindOAuth(prepared, plain); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("missing original preauth accepted", err)
	}
	var bound atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := issuer.BindOAuth(prepared, command); err == nil {
				bound.Add(1)
			} else if !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Error("unexpected bind result", err)
			}
		}()
	}
	group.Wait()
	if bound.Load() != 1 {
		t.Fatal("copied OAuth preparation bound more than once")
	}
	if _, _, ok := (session.IssueRequest{}).OAuthCommand(); ok {
		t.Fatal("zero OAuth request exposed custody")
	}
}

func TestOAuthSessionIssuerRejectsChangedScopeAndAuthentication(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *session.SessionSpec){
		"foreign tenant":        func(b *identity.CommandBinding, _ *session.SessionSpec) { b.TenantID = "foreign" },
		"selected caller user":  func(b *identity.CommandBinding, s *session.SessionSpec) { b.UserID = s.UserID },
		"missing original flow": func(b *identity.CommandBinding, _ *session.SessionSpec) { b.AnonymousFlowID = "" },
		"human caller":          func(b *identity.CommandBinding, _ *session.SessionSpec) { b.ActorKind = authorization.SubjectUser },
		"link callback schema":  func(b *identity.CommandBinding, _ *session.SessionSpec) { b.SchemaID = "oauth-link-callback-v1" },
		"different proof command": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.Authentication.Proof.ID = "AgICAgICAgICAgICAgICAg"
		},
		"password provenance": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.Authentication.Proof.Method = "password" },
		"non-session purpose": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.Authentication.Proof.Purpose = "reauthenticate"
		},
		"advanced family": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.FamilyVersion++ },
		"changed original activity": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.LastActivityAt = s.IssuedAt.Add(time.Second)
		},
		"missing factor fence": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Factor = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
		"organization profile": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, prepared, command, _, _ := oauthIssuerFixture(t, false)
			record, _ := prepared.Session()
			projection, _ := record.Bindings()
			projection.Lookup = session.TokenDigest{}
			feature, _ := command.Feature()
			change(&feature.Binding, &projection)
			if _, err := issuer.PrepareOAuth(feature.Binding, projection); err == nil {
				t.Fatal("changed OAuth issuance profile admitted")
			}
		})
	}
	issuer, prepared, command, _, clock := oauthIssuerFixture(t, false)
	bound, err := issuer.BindOAuth(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := prepared.Session()
	projection, _ := record.Bindings()
	clock.now = projection.Authentication.Proof.ExpiresAt
	got, err := issuer.Issue(t.Context(), bound)
	if err == nil {
		t.Fatal("exclusive original proof expiry admitted before execution")
	}
	requireNoIssuedToken(t, got)
}
