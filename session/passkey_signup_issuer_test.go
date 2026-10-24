package session_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// The durable executor is a controlled delivery seam, not WebAuthn or signup
// policy. Actual native cryptographic/transactional acceptance remains separate.
func passkeySignupIssuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	spec := sessionSpec(t)
	spec.Lookup = session.TokenDigest{}
	spec.Version, spec.FamilyVersion = 1, 1
	spec.LastActivityAt = spec.IssuedAt
	spec.Authentication.CredentialID, spec.Authentication.CredentialVersion = "new-passkey", 1
	spec.Authentication.Proof.Method, spec.Authentication.Proof.Assurance = "passkey", auth.AssurancePhishingResistant
	v, _ := spec.Authority.Bindings()
	v.User.Version, v.Identifier.Version, v.Credential.Version, v.Authorization.Version, v.Session.Version, v.SessionFamily.Version = 1, 1, 1, 1, 1, 1
	v.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:new-user", Version: 1}}
	v.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:new-user", Version: 1}}
	spec.Authority, _ = session.NewAuthoritySnapshot(v)
	b := issueBinding(spec)
	b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = "", "signup-flow", "signup-service", authorization.SubjectServiceAccount
	b.OperationID, b.SchemaID, b.RecordID = "identity.passkey.register-verify", "identity.passkey.register-verify.signup-v1", spec.Authentication.CredentialID
	op := identity.FeatureOperation{Owner: "passkey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	clock := &mutableIssueClock{now: spec.IssuedAt}
	executor := &issueExecutor{}
	executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		original, record, ok := r.PasskeySignupCommand()
		if !ok || original != command {
			t.Fatal("original signup arm lost")
		}
		if _, _, ok := r.PasskeyCommand(); ok {
			t.Fatal("signup reinterpreted as an assertion")
		}
		if _, ok := r.AuthenticatedProof(); ok {
			t.Fatal("signup invented authenticated-proof custody")
		}
		return session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-signup", Feature: &identity.FeatureReceipt{Operation: op, AfterVersion: 1}}, Session: record}, nil
	}
	cfg := signupIssuerConfig(t, spec.IssuedAt)
	cfg.Clock = clock
	issuer, err := session.NewPasskeySignupSessionIssuerWithCSRF(executor, cfg, signupCSRFKey(t))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.PreparePasskeySignup(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, prepared, command, executor, clock
}

func TestPasskeySignupIssuerPreservesOriginalDeliveryCustody(t *testing.T) {
	issuer, prepared, command, _, _ := passkeySignupIssuerFixture(t)
	if _, err := issuer.Issue(t.Context(), prepared); err == nil {
		t.Fatal("unbound signup issued")
	}
	if _, err := prepared.CSRFToken(); err == nil {
		t.Fatal("uncommitted synchronizer revealed")
	}
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	if _, err := issuer.PreparePasskey(f.Binding, spec); err == nil {
		t.Fatal("signup enabled legacy assertion profile")
	}
	if _, err := issuer.BindPasskey(prepared, command); err == nil {
		t.Fatal("signup bound through assertion arm")
	}
	bound, err := issuer.BindPasskeySignup(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindPasskeySignup(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
		t.Fatal("signup bound twice", err)
	}
	result, err := issuer.Issue(t.Context(), bound)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
		t.Fatal("new signup not delivered", err)
	}
	want, _ := record.Bindings()
	got, _ := result.Session.Bindings()
	if got != want {
		t.Fatal("original prospective session changed")
	}
	if token, err := result.Token.Reveal(); err != nil || token == "" {
		t.Fatal("new committed bearer withheld", err)
	}
	if _, err := bound.CSRFToken(); err != nil {
		t.Fatal("new committed CSRF withheld", err)
	}
	if _, ok := bound.Request(); ok {
		t.Fatal("signup exposed proof-route recovery")
	}
}

func TestPasskeySignupIssuerWithholdsAmbiguousReplayedOrLateCredentials(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "error", "wrong-record", "late"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := passkeySignupIssuerFixture(t)
			native := executor.execute
			executor.execute = func(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				result, err := native(ctx, r)
				switch mode {
				case "replay":
					result.Replayed = true
				case "unknown":
					result.Receipt.Outcome, result.Receipt.AuditEventID, result.Session = identity.CommitOutcomeUnknown, "", session.Session{}
				case "error":
					err = errors.New("private execution detail")
				case "wrong-record":
					s, _ := result.Session.Bindings()
					s.Authentication.CredentialID = "foreign-credential"
					result.Session, _ = session.NewSession(s)
				case "late":
					s, _ := result.Session.Bindings()
					clock.now = s.Authentication.Proof.ExpiresAt
				}
				return result, err
			}
			bound, err := issuer.BindPasskeySignup(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			result, err := issuer.Issue(t.Context(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("invalid signup delivery admitted")
			}
			requireNoIssuedToken(t, result)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("undeliverable signup disclosed CSRF")
			}
		})
	}
}

func TestPasskeySignupCopiedPreparationExecutesOnce(t *testing.T) {
	issuer, prepared, command, executor, _ := passkeySignupIssuerFixture(t)
	bound, err := issuer.BindPasskeySignup(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	native := executor.execute
	var calls, delivered atomic.Int32
	executor.execute = func(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		calls.Add(1)
		return native(ctx, r)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := issuer.Issue(t.Context(), bound)
			if err == nil {
				if _, err := r.Token.Reveal(); err == nil {
					delivered.Add(1)
				}
			} else if !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || delivered.Load() != 1 {
		t.Fatal("copied signup executed/delivered more than once", calls.Load(), delivered.Load())
	}
}

func TestPasskeySignupIssuerRejectsForeignProfilesAndGenerations(t *testing.T) {
	issuer, prepared, command, _, _ := passkeySignupIssuerFixture(t)
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	legacy, err := session.NewPasskeySessionIssuer(&issueExecutor{}, signupIssuerConfig(t, spec.IssuedAt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.PreparePasskeySignup(f.Binding, spec); err == nil {
		t.Fatal("legacy assertion issuer enabled signup")
	}
	for name, change := range map[string]func(*session.AuthoritySnapshotSpec){
		"user":          func(v *session.AuthoritySnapshotSpec) { v.User.Version++ },
		"identifier":    func(v *session.AuthoritySnapshotSpec) { v.Identifier.Version++ },
		"credential":    func(v *session.AuthoritySnapshotSpec) { v.Credential.Version++ },
		"authorization": func(v *session.AuthoritySnapshotSpec) { v.Authorization.Version++ },
		"factor":        func(v *session.AuthoritySnapshotSpec) { v.Factor.Binding.Version++ },
		"passkey":       func(v *session.AuthoritySnapshotSpec) { v.Passkey.Binding.Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := spec
			v, _ := spec.Authority.Bindings()
			change(&v)
			candidate.Authority, err = session.NewAuthoritySnapshot(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.PreparePasskeySignup(f.Binding, candidate); err == nil {
				t.Fatal("noninitial signup authority adopted")
			}
		})
	}
	foreign := f.Binding
	foreign.RecordID = "other-credential"
	if _, err := issuer.PreparePasskeySignup(foreign, spec); err == nil {
		t.Fatal("foreign credential lifecycle subject admitted")
	}
	foreign = f.Binding
	foreign.ActorKind = authorization.SubjectUser
	if _, err := issuer.PreparePasskeySignup(foreign, spec); err == nil {
		t.Fatal("human-selected signup actor admitted")
	}
}
