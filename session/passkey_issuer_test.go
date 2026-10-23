package session_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This executor is the explicit durable-owner seam, not a WebAuthn verifier.
// These tests establish delivery custody; native tests must prove authentication.
func passkeyIssuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	spec := sessionSpec(t)
	spec.Version, spec.FamilyVersion, spec.Lookup = 1, 1, session.TokenDigest{}
	spec.Authentication.CredentialID = "passkey-a"
	spec.Authentication.Proof.Method = "passkey"
	spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
	vector.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 2}}
	vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant-a:user-a", Version: 3}}
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	b := issueBinding(spec)
	b.OperationID, b.SchemaID, b.RecordID = "identity.passkey.signin-verify", "identity.passkey.signin-verify.native-v1", spec.SessionID
	op := identity.FeatureOperation{Owner: "passkey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	clock := &mutableIssueClock{now: spec.IssuedAt}
	executor := &issueExecutor{}
	executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		actual, record, ok := request.PasskeyCommand()
		if !ok || actual != command {
			t.Fatal("original passkey command lost")
		}
		if _, ok := request.Command(); ok {
			t.Fatal("prospective assertion became authenticated-proof command")
		}
		if _, ok := request.AuthenticatedProof(); ok {
			t.Fatal("prospective assertion fabricated authenticated proof")
		}
		if err := request.Validate(nil, clock.now); !errors.Is(err, session.ErrInvalidIssueRequest) {
			t.Fatal("prospective assertion passed proof admission", err)
		}
		return session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: op, AfterVersion: 1}}, Session: record}, nil
	}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-passkey", SameSite: http.SameSiteStrictMode})
	issuer, err := session.NewPasskeySessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.PreparePasskey(b, spec)
	if err != nil {
		t.Fatal("passkey preparation", err)
	}
	return issuer, prepared, command, executor, clock
}

func TestPasskeyIssuerPreservesOriginalCommitGate(t *testing.T) {
	issuer, prepared, command, _, _ := passkeyIssuerFixture(t)
	if _, err := issuer.Issue(context.Background(), prepared); err == nil {
		t.Fatal("unbound assertion issued")
	}
	if _, err := prepared.CSRFToken(); err == nil {
		t.Fatal("uncommitted CSRF revealed")
	}
	original, ok := prepared.Session()
	if !ok {
		t.Fatal("prospective record absent")
	}
	if _, ok := prepared.Request(); ok {
		t.Fatal("prospective command advertised as proof-route recovery")
	}
	bound, err := issuer.BindPasskey(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindPasskey(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
		t.Fatal("copied preparation bound twice", err)
	}
	result, err := issuer.Issue(context.Background(), bound)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
		t.Fatal("exact new commit rejected", err)
	}
	got, _ := result.Session.Bindings()
	want, _ := original.Bindings()
	if got != want || got.Authentication.Proof.Method != "passkey" || got.Authentication.Proof.Assurance != auth.AssurancePhishingResistant {
		t.Fatal("original authentication, authority, remember or digest changed")
	}
	if token, err := result.Token.Reveal(); err != nil || token == "" {
		t.Fatal("new committed bearer withheld", err)
	}
	if _, err := bound.CSRFToken(); err != nil {
		t.Fatal("new committed synchronizer withheld", err)
	}
	if _, err := issuer.Recover(context.Background(), session.IssueRequest{}); err == nil {
		t.Fatal("passkey issuer enabled proof-profile recovery")
	}
}

func TestPasskeyIssuerDoesNotDeliverAmbiguousReplayedOrLateResults(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "failure", "different-record", "late"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := passkeyIssuerFixture(t)
			native := executor.execute
			executor.execute = func(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				result, err := native(ctx, request)
				switch mode {
				case "replay":
					result.Replayed = true
				case "unknown":
					result.Receipt.Outcome, result.Receipt.AuditEventID, result.Session = identity.CommitOutcomeUnknown, "", session.Session{}
				case "failure":
					err = errors.New("private-error")
				case "different-record":
					spec, _ := result.Session.Bindings()
					spec.Authentication.CredentialID = "foreign-passkey"
					result.Session, _ = session.NewSession(spec)
				case "late":
					spec, _ := result.Session.Bindings()
					clock.now = spec.Authentication.Proof.ExpiresAt
				}
				return result, err
			}
			bound, err := issuer.BindPasskey(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			result, err := issuer.Issue(context.Background(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("invalid result accepted")
			}
			requireNoIssuedToken(t, result)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("non-deliverable result revealed CSRF")
			}
		})
	}
}

func TestPasskeyIssuerRejectsOtherMethodsAndAuthorityDimensions(t *testing.T) {
	issuer, prepared, command, _, _ := passkeyIssuerFixture(t)
	record, _ := prepared.Session()
	base, _ := record.Bindings()
	base.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Proof.Method = "password" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = auth.AssuranceSingleFactor },
		func(s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Passkey = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
		func(s *session.SessionSpec) {
			v, _ := s.Authority.Bindings()
			v.Factor = session.OptionalAuthorityBinding{}
			s.Authority, _ = session.NewAuthoritySnapshot(v)
		},
	} {
		spec := base
		mutate(&spec)
		if _, err := issuer.PreparePasskey(f.Binding, spec); err == nil {
			t.Fatal("unsupported authentication admitted")
		}
	}
	legacy, _, _, _ := issuerFixture(t)
	if _, err := legacy.PreparePasskey(f.Binding, base); err == nil {
		t.Fatal("proof issuer selected prospective assertion")
	}
	f.Operation.OperationID, f.Operation.SchemaID = "identity.passkey.register-verify", "identity.passkey.register-verify.native-v1"
	f.Binding.OperationID, f.Binding.SchemaID = f.Operation.OperationID, f.Operation.SchemaID
	wrong, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindPasskey(prepared, wrong); err == nil {
		t.Fatal("registration command substituted for signin")
	}
	if _, err := issuer.BindPasskey(prepared, command); err != nil {
		t.Fatal("invalid bind consumed original claim", err)
	}
}

func TestPasskeyIssuerCopiedPreparationDeliversOnce(t *testing.T) {
	issuer, prepared, command, _, _ := passkeyIssuerFixture(t)
	bound, err := issuer.BindPasskey(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	var delivered atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, err := issuer.Issue(context.Background(), bound)
			if err == nil && result.CommitOutcome == identity.CommitOutcomeCommitted {
				if _, err := result.Token.Reveal(); err == nil {
					delivered.Add(1)
				}
			} else if !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Error("unexpected concurrent outcome", err)
			}
		})
	}
	wg.Wait()
	if delivered.Load() != 1 {
		t.Fatal("copied original did not deliver exactly once", delivered.Load())
	}
}

func TestPasskeyIssuerBindsSessionLifecycleSubject(t *testing.T) {
	issuer, prepared, command, _, _ := passkeyIssuerFixture(t)
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	f.Binding.RecordID = "foreign-session"
	if _, err := issuer.PreparePasskey(f.Binding, spec); err == nil {
		t.Fatal("session creation attributed to another record")
	}
}
