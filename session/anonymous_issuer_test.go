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

func anonymousIssuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	_, _, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	spec.Lookup, spec.Version, spec.FamilyVersion = session.TokenDigest{}, 1, 1
	spec.LastActivityAt = spec.IssuedAt
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-guest", SameSite: http.SameSiteStrictMode})
	clock := &mutableIssueClock{now: spec.IssuedAt}
	executor := &issueExecutor{}
	issuer, err := session.NewAnonymousSessionIssuer(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(spec)
	b.OperationID, b.SchemaID, b.RecordID, b.UserID, b.AnonymousFlowID = "identity.anonymous.signin", "identity.anonymous.signin.native-v1", "", "", "original-anonymous-flow"
	prepared, err := issuer.PrepareAnonymous(b, spec)
	if err != nil {
		t.Fatal("anonymous original preparation", err)
	}
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	executor.execute = func(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
		original, record, ok := request.AnonymousCommand()
		if !ok || original != command {
			t.Fatal("original anonymous command lost")
		}
		if _, ok := request.Command(); ok {
			t.Fatal("anonymous request became a verified command")
		}
		if _, ok := request.AuthenticatedProof(); ok {
			t.Fatal("anonymous request fabricated proof")
		}
		if err := request.Validate(nil, clock.now); err == nil {
			t.Fatal("anonymous request passed verified admission")
		}
		return session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "committed-audit", Feature: &identity.FeatureReceipt{Operation: op}}, Session: record}, nil
	}
	return issuer, prepared, command, executor, clock
}

func TestAnonymousIssuerCommitGateAndOriginalCustody(t *testing.T) {
	issuer, prepared, command, _, _ := anonymousIssuerFixture(t)
	if _, err := issuer.Issue(context.Background(), prepared); err == nil {
		t.Fatal("unbound guest issued")
	}
	if _, ok := prepared.Request(); ok {
		t.Fatal("unbound anonymous request advertised proof-route recovery")
	}
	bound, err := issuer.BindAnonymous(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindAnonymous(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
		t.Fatal("anonymous preparation bound twice", err)
	}
	if _, ok := bound.Request(); ok {
		t.Fatal("anonymous request advertised proof-route recovery")
	}
	result, err := issuer.Issue(context.Background(), bound)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
		t.Fatal("anonymous commit withheld", err)
	}
	actual, _ := result.Session.Bindings()
	original, _ := prepared.Session()
	expected, _ := original.Bindings()
	if actual.Authentication.Kind != session.AuthenticationAnonymous || actual.Lookup != expected.Lookup || actual.Remember != expected.Remember {
		t.Fatal("anonymous authority/remember/original-token custody changed")
	}
	if token, err := result.Token.Reveal(); err != nil || token == "" {
		t.Fatal("committed anonymous token unavailable", err)
	}
	if repeated, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
		t.Fatal("anonymous issuance repeated", err)
	} else {
		requireNoIssuedToken(t, repeated)
	}
}

func TestAnonymousIssuerDeniesReplayFailureAndSubstitution(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "dependency-failure", "different-record", "late-expiry"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := anonymousIssuerFixture(t)
			native := executor.execute
			executor.execute = func(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				execution, err := native(ctx, request)
				switch mode {
				case "replay":
					execution.Replayed = true
				case "unknown":
					execution.Receipt.Outcome, execution.Receipt.AuditEventID, execution.Session = identity.CommitOutcomeUnknown, "", session.Session{}
				case "dependency-failure":
					err = errors.New("private-dependency-error")
				case "different-record":
					spec, _ := execution.Session.Bindings()
					spec.UserID = "different-guest"
					execution.Session, _ = session.NewSession(spec)
				case "late-expiry":
					life, _ := execution.Session.Lifetime(clock.now)
					clock.now = life.AbsoluteExpiresAt
				}
				return execution, err
			}
			bound, err := issuer.BindAnonymous(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			result, err := issuer.Issue(context.Background(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("invalid anonymous result was delivered")
			}
			requireNoIssuedToken(t, result)
		})
	}
}

func TestAnonymousIssuerCannotUseVerifiedPreparationOrOtherPurpose(t *testing.T) {
	issuer, prepared, command, _, _ := anonymousIssuerFixture(t)
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	legacy, _, _, _ := issuerFixture(t)
	if _, err := legacy.PrepareAnonymous(f.Binding, spec); err == nil {
		t.Fatal("verified issuer admitted anonymous preparation")
	}
	if _, err := issuer.PrepareOTP(f.Binding, spec, session.OTPAuthentication{}); err == nil {
		t.Fatal("anonymous issuer admitted OTP")
	}
	f.Operation.SchemaVersion, f.Binding.SchemaVersion = 2, 2
	changed, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindAnonymous(prepared, changed); err == nil {
		t.Fatal("anonymous preparation changed profile")
	}
	f.Operation.SchemaVersion, f.Binding.SchemaVersion = 1, 1
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt.Add(-time.Second)}
	if _, err := issuer.PrepareAnonymous(f.Binding, spec); err == nil {
		t.Fatal("anonymous issuance substituted original creation time")
	}
}
