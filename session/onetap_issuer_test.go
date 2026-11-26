package session_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// The executor supplies bounded durable outcomes, not Google authentication,
// browser verification, PostgreSQL effects or production OAuth authority.
func oneTapIssuerFixture(t *testing.T, persistent bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	_, ordinary, command, executor, clock := oauthIssuerFixture(t, persistent)
	record, _ := ordinary.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	feature, _ := command.Feature()
	feature.Operation = identity.FeatureOperation{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", SchemaID: "oauth-onetap-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	feature.Binding.OperationID, feature.Binding.SchemaID = feature.Operation.OperationID, feature.Operation.SchemaID
	feature.Binding.RecordID = feature.Binding.AnonymousFlowID
	cookieCredential, _ := command.PreAuthCookie()
	command, err := identity.NewFeaturePreAuthCommand(feature, cookieCredential)
	if err != nil {
		t.Fatal("freeze original One Tap callback", err)
	}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	issuer, err := session.NewOneTapSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal("construct One Tap issuer", err)
	}
	prepared, err := issuer.PrepareOneTap(feature.Binding, spec)
	if err != nil {
		t.Fatal("prepare prospective One Tap session", err)
	}
	executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		return committedOneTapIssue(t, request), nil
	}
	return issuer, prepared, command, executor, clock
}

func committedOneTapIssue(t testing.TB, request session.IssueRequest) session.IssueExecution {
	t.Helper()
	command, record, ok := request.OneTapCommand()
	if !ok {
		t.Fatal("original One Tap custody unavailable")
	}
	feature, _ := command.Feature()
	if _, ok := command.PreAuthCookie(); !ok {
		t.Fatal("One Tap lost original browser custody")
	}
	if _, _, ok := request.OAuthCommand(); ok {
		t.Fatal("One Tap exposed ordinary OAuth custody")
	}
	if _, ok := request.Command(); ok {
		t.Fatal("One Tap exposed proof-route custody")
	}
	if _, ok := request.AuthenticatedProof(); ok {
		t.Fatal("One Tap fabricated authenticated proof")
	}
	if _, _, ok := request.PasswordCommand(); ok {
		t.Fatal("One Tap exposed password custody")
	}
	if request.Validate(nil, time.Now()) == nil {
		t.Fatal("prospective One Tap metadata authenticated itself")
	}
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: 1, AfterVersion: 2}}, Session: record}
}

func TestOneTapSessionIssuerDeliversExactFreshCommitOnce(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		issuer, prepared, command, executor, _ := oneTapIssuerFixture(t, persistent)
		original, _ := prepared.Session()
		if _, err := prepared.CSRFToken(); err == nil {
			t.Fatal("uncommitted One Tap preparation disclosed synchronizer")
		}
		if _, ok := prepared.Request(); ok {
			t.Fatal("unbound One Tap preparation advertised recovery custody")
		}
		bound, err := issuer.BindOneTap(prepared, command)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("bound One Tap preparation advertised browser-bearing recovery")
		}
		if _, err := issuer.BindOneTap(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
			t.Fatal("copied original preparation bound twice", err)
		}
		calls := 0
		var captured session.IssueRequest
		executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
			calls++
			captured = request
			gotCommand, _, ok := request.OneTapCommand()
			if !ok || gotCommand != command {
				t.Fatal("executor borrowed a reconstructed callback")
			}
			return committedOneTapIssue(t, request), nil
		}
		got, err := issuer.Issue(t.Context(), bound)
		if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed || calls != 1 {
			t.Fatal("exact new One Tap commitment did not deliver", err)
		}
		before, _ := original.Bindings()
		after, _ := got.Session.Bindings()
		if before != after || got.Cookie.Name != "__Host-session" || got.Cookie.Value != "" || !got.Cookie.Secure || !got.Cookie.HttpOnly || got.Cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("One Tap changed original session or cookie policy")
		}
		if !got.DeliveryValidUntil.Equal(before.Authentication.Proof.ExpiresAt) {
			t.Fatal("One Tap delivery did not retain the original proof cutoff")
		}
		if persistent != (got.Cookie.MaxAge > 0 && !got.Cookie.Expires.IsZero()) {
			t.Fatal("One Tap changed original remember choice")
		}
		if _, err := got.Token.Reveal(); err != nil {
			t.Fatal("new committed One Tap token unavailable", err)
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("new committed One Tap synchronizer unavailable", err)
		}
		if repeated, err := issuer.Issue(t.Context(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) || calls != 1 {
			t.Fatal("original One Tap preparation executed again", err)
		} else {
			requireNoIssuedToken(t, repeated)
		}
		if recovered, err := issuer.Recover(t.Context(), captured); err == nil {
			t.Fatal("original credential was accepted for One Tap recovery")
		} else {
			requireNoIssuedToken(t, recovered)
		}
	}
}

func TestOneTapSessionIssuerWithholdsUnsafeExecution(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "commit-error", "missing-receipt", "ordinary-oauth-operation", "old-record-free-lifecycle", "old-creation-lifecycle", "other-lifecycle", "foreign-record", "foreign-binding", "missing-session", "changed-session", "late-commit"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := oneTapIssuerFixture(t, false)
			bound, err := issuer.BindOneTap(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				result := committedOneTapIssue(t, request)
				switch mode {
				case "replay":
					result.Replayed = true
				case "unknown":
					result.Receipt.Outcome, result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 0, 0
					result.Session = session.Session{}
				case "commit-error":
					return result, errors.New("private native detail")
				case "missing-receipt":
					result.Receipt.Feature = nil
				case "ordinary-oauth-operation":
					result.Receipt.Feature.Operation.Owner = "identity/oauth"
					result.Receipt.Feature.Operation.OperationID = "identity.oauth.callback"
					result.Receipt.Feature.Operation.SchemaID = "oauth-signin-callback-v1"
					result.Receipt.Feature.Operation.RecordRequirement = identity.FeatureRecordOmitted
				case "old-record-free-lifecycle":
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 0, 0
				case "old-creation-lifecycle":
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 0, 1
				case "other-lifecycle":
					result.Receipt.Feature.BeforeVersion, result.Receipt.Feature.AfterVersion = 2, 3
				case "foreign-record":
					result.Receipt.Binding.RecordID = "other-flow"
				case "foreign-binding":
					result.Receipt.Binding.CorrelationID = "different"
				case "missing-session":
					result.Session = session.Session{}
				case "changed-session":
					spec, _ := result.Session.Bindings()
					spec.Authentication.CredentialID = "another-google-account"
					result.Session, _ = session.NewSession(spec)
				case "late-commit":
					spec, _ := result.Session.Bindings()
					clock.now = spec.Authentication.Proof.ExpiresAt
				}
				return result, nil
			}
			got, err := issuer.Issue(t.Context(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("unsafe One Tap execution accepted")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("non-deliverable One Tap execution disclosed synchronizer")
			}
		})
	}
}

func TestOneTapSessionIssuerRejectsOrdinaryOAuthCustody(t *testing.T) {
	issuer, prepared, command, _, _ := oneTapIssuerFixture(t, false)
	ordinaryIssuer, ordinaryPrepared, ordinaryCommand, ordinaryExecutor, _ := oauthIssuerFixture(t, false)
	f, _ := command.Feature()
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	if _, err := issuer.PrepareOAuth(f.Binding, spec); err == nil {
		t.Fatal("ordinary OAuth preparation accepted One Tap")
	}
	if _, err := issuer.BindOAuth(prepared, command); err == nil {
		t.Fatal("ordinary OAuth binding accepted One Tap")
	}
	if _, err := ordinaryIssuer.PrepareOneTap(f.Binding, spec); err == nil {
		t.Fatal("ordinary OAuth issuer prepared One Tap")
	}
	if _, err := issuer.BindOneTap(ordinaryPrepared, ordinaryCommand); err == nil {
		t.Fatal("One Tap issuer borrowed ordinary OAuth preparation")
	}
	if _, err := ordinaryIssuer.BindOneTap(prepared, command); err == nil {
		t.Fatal("ordinary OAuth issuer borrowed One Tap preparation")
	}
	plain, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindOneTap(prepared, plain); err == nil {
		t.Fatal("One Tap bound metadata without original browser credential")
	}
	if _, err := issuer.BindOneTap(prepared, ordinaryCommand); err == nil {
		t.Fatal("One Tap bound ordinary OAuth command")
	}
	ordinaryExecutor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		if _, _, ok := request.OneTapCommand(); ok {
			t.Fatal("One Tap accessor exposed ordinary OAuth custody")
		}
		return committedOAuthIssue(t, request), nil
	}
	bound, err := ordinaryIssuer.BindOAuth(ordinaryPrepared, ordinaryCommand)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinaryIssuer.Issue(t.Context(), bound); err != nil {
		t.Fatal("ordinary OAuth control failed", err)
	}
	if _, _, ok := (session.IssueRequest{}).OneTapCommand(); ok {
		t.Fatal("zero request exposed One Tap custody")
	}
}

func TestOneTapSessionIssuerRejectsChangedOriginalContract(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *session.SessionSpec){
		"foreign tenant":     func(b *identity.CommandBinding, _ *session.SessionSpec) { b.TenantID = "other" },
		"selected user":      func(b *identity.CommandBinding, s *session.SessionSpec) { b.UserID = s.UserID },
		"human actor":        func(b *identity.CommandBinding, _ *session.SessionSpec) { b.ActorKind = authorization.SubjectUser },
		"missing flow":       func(b *identity.CommandBinding, _ *session.SessionSpec) { b.AnonymousFlowID = "" },
		"foreign record":     func(b *identity.CommandBinding, _ *session.SessionSpec) { b.RecordID = "other-flow" },
		"ordinary operation": func(b *identity.CommandBinding, _ *session.SessionSpec) { b.OperationID = "identity.oauth.callback" },
		"ordinary schema":    func(b *identity.CommandBinding, _ *session.SessionSpec) { b.SchemaID = "oauth-signin-callback-v1" },
		"different proof command": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.Authentication.Proof.ID = "AgICAgICAgICAgICAgICAg"
		},
		"password provenance": func(_ *identity.CommandBinding, s *session.SessionSpec) { s.Authentication.Proof.Method = "password" },
		"advanced family":     func(_ *identity.CommandBinding, s *session.SessionSpec) { s.FamilyVersion++ },
		"changed activity": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			s.LastActivityAt = s.IssuedAt.Add(time.Second)
		},
		"missing factor authority": func(_ *identity.CommandBinding, s *session.SessionSpec) {
			vector, _ := s.Authority.Bindings()
			vector.Factor = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(vector)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, prepared, command, _, _ := oneTapIssuerFixture(t, false)
			record, _ := prepared.Session()
			spec, _ := record.Bindings()
			spec.Lookup = session.TokenDigest{}
			feature, _ := command.Feature()
			change(&feature.Binding, &spec)
			if _, err := issuer.PrepareOneTap(feature.Binding, spec); err == nil {
				t.Fatal("changed original One Tap contract admitted")
			}
		})
	}
	issuer, prepared, command, executor, clock := oneTapIssuerFixture(t, false)
	bound, err := issuer.BindOneTap(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	clock.now = spec.Authentication.Proof.ExpiresAt
	executor.execute = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("expired One Tap proof entered executor")
		return session.IssueExecution{}, nil
	}
	got, err := issuer.Issue(t.Context(), bound)
	if err == nil {
		t.Fatal("exclusive original proof expiry admitted")
	}
	requireNoIssuedToken(t, got)
	if _, err := bound.CSRFToken(); err == nil {
		t.Fatal("expired One Tap preparation disclosed synchronizer")
	}
}
