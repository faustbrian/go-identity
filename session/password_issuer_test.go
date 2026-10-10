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

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

type passwordIssuancePreparer interface {
	PreparePassword(identity.CommandBinding, session.SessionSpec) (session.PreparedIssuance, error)
	BindPassword(session.PreparedIssuance, identity.Command) (session.PreparedIssuance, error)
}

func passwordIssuerFixture(t *testing.T, anonymous bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock, primitive.Secret) {
	t.Helper()
	spec := sessionSpec(t)
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, spec.Version = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	spec.Lookup = session.TokenDigest{}
	b := issueBinding(spec)
	b.OperationID, b.SchemaID, b.RecordID = "identity.password.signin", "password-signin", ""
	b.ActorID, b.ActorKind = "login-service", authorization.SubjectServiceAccount
	d := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", "original-flow"
		d.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	clock := &mutableIssueClock{now: spec.IssuedAt}
	ex := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedPasswordIssue(t, r), nil
	}, recover: func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("secret-bearing recovery")
		return session.IssueExecution{}, nil
	}}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	issuer, err := session.NewPasswordSessionIssuerWithCSRF(ex, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, csrf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := issuer.PreparePassword(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := primitive.NewSecret([]byte("raw candidate password"))
	t.Cleanup(password.Destroy)
	c, err := identity.NewFeaturePasswordSigninCommand(identity.FeatureCommandSpec{Binding: b, Operation: d, Fields: []identity.FeatureField{{Name: "native.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "native-mapping-fixture"}}}}, password, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	return issuer, p, c, ex, clock, password
}

func committedPasswordIssue(t testing.TB, r session.IssueRequest) session.IssueExecution {
	t.Helper()
	c, record, ok := r.PasswordCommand()
	if !ok {
		t.Fatal("original password command unavailable")
	}
	f, _ := c.PasswordSigninFeature()
	p, b, ok := c.PasswordSigninCustody()
	if !ok || p.Len() == 0 || b.Token() == "" {
		t.Fatal("original password/preauth custody lost")
	}
	if _, ok := r.Command(); ok {
		t.Fatal("password request downgraded to proof command")
	}
	if _, ok := r.AuthenticatedProof(); ok {
		t.Fatal("prospective request fabricated opaque proof")
	}
	if _, _, ok := r.OTPCommand(); ok {
		t.Fatal("password request entered OTP profile")
	}
	if err := r.Validate(nil, time.Now()); !errors.Is(err, session.ErrInvalidIssueRequest) {
		t.Fatal("prospective data admitted as proof", err)
	}
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: f.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: f.Operation}}, Session: record}
}

func TestPasswordIssuerBindsOnceAndDeliversOnlyExactOriginalCommit(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		issuer, p, c, _, _, password := passwordIssuerFixture(t, anonymous)
		original, _ := p.Session()
		if _, ok := p.Request(); ok {
			t.Fatal("unbound input exposed for recovery")
		}
		if got, err := issuer.Issue(context.Background(), p); !errors.Is(err, session.ErrInvalidIssuance) || got.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("unbound preparation executed", err)
		}
		if _, err := p.CSRFToken(); err == nil {
			t.Fatal("uncommitted synchronizer delivered")
		}
		bound, err := issuer.BindPassword(p, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("password request exposed as safe recovery")
		}
		if _, err := issuer.BindPassword(bound, c); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
			t.Fatal("rebound original custody", err)
		}
		got, err := issuer.Issue(context.Background(), bound)
		if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed {
			t.Fatal("known commit withheld", err)
		}
		before, _ := original.Bindings()
		after, _ := got.Session.Bindings()
		if before.Authentication != after.Authentication || before.Lookup != after.Lookup || before.Remember != after.Remember || before.Authority.CompareCurrent(after.Authority) != nil {
			t.Fatal("original authentication/authority/remember changed")
		}
		key, _ := session.NewDigestKey(1, make([]byte, 32))
		digest, err := got.Token.Digest(key, string(before.TenantID))
		if err != nil || digest != before.Lookup || got.Cookie.Value != "" {
			t.Fatal("token delivery differs from prepared custody", err)
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("committed synchronizer withheld", err)
		}
		if password.Len() == 0 {
			t.Fatal("session issuer destroyed borrowed password")
		}
		if retry, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
			t.Fatal("second execution", err)
		} else {
			requireNoIssuedToken(t, retry)
		}
	}
}

func TestPasswordIssuerInvalidBindingDoesNotClaimAndCopiesShareOneBind(t *testing.T) {
	issuer, p, c, ex, _, password := passwordIssuerFixture(t, true)
	foreign, _, _, _, _, _ := passwordIssuerFixture(t, true)
	if _, err := foreign.BindPassword(p, c); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("foreign owner admitted", err)
	}
	f, _ := c.PasswordSigninFeature()
	plain, _ := identity.NewFeatureCommand(f)
	if _, err := issuer.BindPassword(p, plain); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("plain command fabricated password", err)
	}
	f.Binding.CorrelationID = "substituted"
	_, cookie, _ := c.PasswordSigninCustody()
	changed, _ := identity.NewFeaturePasswordSigninCommand(f, password, cookie)
	if _, err := issuer.BindPassword(p, changed); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("changed scope admitted", err)
	}
	var winners, calls atomic.Int32
	ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		calls.Add(1)
		return committedPasswordIssue(t, r), nil
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			bound, err := issuer.BindPassword(p, c)
			if errors.Is(err, session.ErrIssuanceAlreadyBound) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			winners.Add(1)
			if _, err := issuer.Issue(context.Background(), bound); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 || calls.Load() != 1 {
		t.Fatal("copies bound different commands")
	}
}

func TestPasswordIssuerWithholdsHistoricalFailedOrExpiredDelivery(t *testing.T) {
	for _, scenario := range []string{"replay", "error", "cancel", "expiry", "substitution"} {
		t.Run(scenario, func(t *testing.T) {
			issuer, p, c, ex, clock, _ := passwordIssuerFixture(t, false)
			bound, err := issuer.BindPassword(p, c)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e := committedPasswordIssue(t, r)
				switch scenario {
				case "replay":
					e.Replayed = true
				case "error":
					return e, errors.New("private dependency data")
				case "cancel":
					cancel()
				case "expiry":
					spec, _ := e.Session.Bindings()
					clock.now = spec.Authentication.Proof.ExpiresAt
				case "substitution":
					spec, _ := e.Session.Bindings()
					spec.Authentication.CredentialVersion++
					e.Session, _ = session.NewSessionWithCSRF(spec, e.Session.CSRFState())
				}
				return e, nil
			}
			got, err := issuer.Issue(ctx, bound)
			if scenario == "replay" && (err != nil || !got.Replayed) {
				t.Fatal("replay misclassified", err)
			}
			if scenario != "replay" && err == nil {
				t.Fatal("unsafe delivery admitted")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("unsafe synchronizer delivery")
			}
		})
	}
}

func TestPasswordIssuerRejectsIncompleteProspectiveMetadataBeforeExecution(t *testing.T) {
	for _, mutate := range []func(*identity.CommandBinding, *session.SessionSpec, *mutableIssueClock){
		func(b *identity.CommandBinding, _ *session.SessionSpec, _ *mutableIssueClock) { b.UserID = "foreign" },
		func(b *identity.CommandBinding, _ *session.SessionSpec, _ *mutableIssueClock) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding, _ *session.SessionSpec, _ *mutableIssueClock) {
			b.OperationID = "identity.password.signup"
		},
		func(b *identity.CommandBinding, _ *session.SessionSpec, _ *mutableIssueClock) {
			b.RecordID = "unexpected"
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Lookup.Sum = [32]byte{1}
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) { s.Version = 2 },
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.LastActivityAt = s.IssuedAt.Add(time.Second)
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Authentication.Proof.Method = "passkey"
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Authentication.Proof.Assurance = auth.AssuranceMultiFactor
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Authentication.Proof.Purpose = "other"
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Authentication.Proof.Subject = "foreign"
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, _ *mutableIssueClock) {
			s.Authentication.Proof.IssuedAt = s.IssuedAt.Add(time.Second)
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, c *mutableIssueClock) {
			c.now = s.Authentication.Proof.ExpiresAt
		},
		func(_ *identity.CommandBinding, s *session.SessionSpec, c *mutableIssueClock) {
			c.now = s.IssuedAt.Add(-time.Second)
		},
		func(_ *identity.CommandBinding, _ *session.SessionSpec, c *mutableIssueClock) { c.now = time.Time{} },
	} {
		issuer, p, command, ex, clock, _ := passwordIssuerFixture(t, false)
		record, _ := p.Session()
		spec, _ := record.Bindings()
		spec.Lookup = session.TokenDigest{}
		f, _ := command.PasswordSigninFeature()
		binding := f.Binding
		mutate(&binding, &spec, clock)
		ex.execute = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
			t.Fatal("invalid preparation executed")
			return session.IssueExecution{}, nil
		}
		if p, err := issuer.PreparePassword(binding, spec); err == nil || p != (session.PreparedIssuance{}) {
			t.Fatal("invalid prospective metadata accepted")
		}
	}
	issuer, p, c, _, clock, password := passwordIssuerFixture(t, false)
	password.Destroy()
	if _, err := issuer.BindPassword(p, c); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("destroyed password bound", err)
	}
	record, _ := p.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := c.PasswordSigninFeature()
	clock.panicNow = true
	if p, err := issuer.PreparePassword(f.Binding, spec); !errors.Is(err, session.ErrIssuerUnavailable) || p != (session.PreparedIssuance{}) {
		t.Fatal("clock panic escaped", err)
	}
	if _, err := session.NewPasswordSessionIssuer(nil, session.IssuerConfig{}); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("nil composition accepted", err)
	}
	if _, err := session.NewPasswordSessionIssuer(nil, session.IssuerConfig{Authority: &auth.AuthorityAuthenticator{}}); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("proof authority selected prospective profile", err)
	}
	if _, err := session.NewPasswordSessionIssuerWithCSRF(nil, session.IssuerConfig{}, session.CSRFKey{}); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("zero synchronizer selected", err)
	}
}

func TestPasswordIssuerExpiredOriginalNeverEntersExecutorOrProofRecovery(t *testing.T) {
	issuer, p, c, ex, clock, _ := passwordIssuerFixture(t, false)
	bound, err := issuer.BindPassword(p, c)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := p.Session()
	spec, _ := record.Bindings()
	clock.now = spec.Authentication.Proof.ExpiresAt
	ex.execute = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("expired original executed")
		return session.IssueExecution{}, nil
	}
	got, err := issuer.Issue(context.Background(), bound)
	if !errors.Is(err, session.ErrInvalidIssuance) || got.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("expired original admitted", err)
	}
	requireNoIssuedToken(t, got)
	if got, err := issuer.Recover(context.Background(), session.IssueRequest{}); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("password profile entered proof recovery", err)
	} else {
		requireNoIssuedToken(t, got)
	}
	proofIssuer, _, _, _ := issuerFixture(t)
	if _, err := proofIssuer.PreparePassword(specBinding(t, c), spec); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("proof issuer enabled native password", err)
	}
	otpIssuer, _, _, _, _ := otpIssuerFixture(t, true, true)
	if _, err := otpIssuer.BindPassword(bound, c); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("OTP issuer accepted password custody", err)
	}
}

func specBinding(t testing.TB, c identity.Command) identity.CommandBinding {
	t.Helper()
	f, ok := c.PasswordSigninFeature()
	if !ok {
		t.Fatal("password mapping missing")
	}
	return f.Binding
}

func TestPasswordIssuerKeepsNativeNoncommittedOutcomesCredentialFree(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeUnknown} {
		issuer, p, c, ex, _, _ := passwordIssuerFixture(t, true)
		bound, err := issuer.BindPassword(p, c)
		if err != nil {
			t.Fatal(err)
		}
		ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
			e := committedPasswordIssue(t, r)
			e.Receipt.Outcome, e.Receipt.AuditEventID, e.Session = outcome, "", session.Session{}
			if outcome == identity.CommitOutcomeInProgress {
				e.Receipt.RetryAfter = time.Second
			}
			return e, errors.New("private storage data")
		}
		got, err := issuer.Issue(context.Background(), bound)
		if err == nil || got.CommitOutcome != outcome || got.Session != (session.Session{}) {
			t.Fatal("native outcome lost or payload disclosed", err)
		}
		requireNoIssuedToken(t, got)
		if _, err := bound.CSRFToken(); err == nil {
			t.Fatal("noncommit disclosed synchronizer")
		}
	}
}

func TestPasswordSigninHasProspectiveSessionCustody(t *testing.T) {
	// Runtime API boundary: committed-original proof issuance cannot admit the
	// transaction that will create that original. Preparation needs a disjoint
	// native-password profile, never a fabricated opaque proof.
	if _, ok := any(&session.SessionIssuer{}).(passwordIssuancePreparer); !ok {
		t.Fatal("prospective password session custody unavailable")
	}
}
