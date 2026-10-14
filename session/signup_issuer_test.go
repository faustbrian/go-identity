package session_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func signupIssuerConfig(t *testing.T, now time.Time) session.IssuerConfig {
	t.Helper()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	return session.IssuerConfig{Clock: &mutableIssueClock{now: now}, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}
}

func signupFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor) {
	t.Helper()
	_, prepared, signin, ex, _, _ := passwordIssuerFixture(t, true)
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	feature, _ := signin.PasswordSigninFeature()
	feature.Binding.OperationID, feature.Binding.SchemaID = "identity.password.signup", "password-signup"
	feature.Operation.OperationID, feature.Operation.SchemaID = feature.Binding.OperationID, feature.Binding.SchemaID
	_, cookie, _ := signin.PasswordSigninCustody()
	command, err := identity.NewFeaturePasswordSignupCommand(feature, "$synthetic-only$prepared-signup-verifier", cookie)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPasswordSignupSessionIssuerWithCSRF(ex, signupIssuerConfig(t, spec.IssuedAt), signupCSRFKey(t))
	if err != nil {
		t.Fatal(err)
	}
	p, err := issuer.PrepareSignup(feature.Binding, spec)
	if err != nil {
		t.Fatal(err)
	}
	ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		_, original, ok := r.PasswordSignupCommand()
		if !ok {
			t.Fatal("signup arm unavailable")
		}
		return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation}}, Session: original}, nil
	}
	return issuer, p, command, ex
}

func TestSignupIssuerDeniesNonfreshAndAdverseDeliveries(t *testing.T) {
	for _, name := range []string{"rollback", "conflict", "in-progress", "unknown", "replayed", "error-after-commit", "wrong-operation", "expired", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			issuer, p, command, ex := signupFixture(t)
			bound, err := issuer.BindSignup(p, command)
			if err != nil {
				t.Fatal(err)
			}
			original := ex.execute
			ex.execute = func(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				result, err := original(ctx, r)
				switch name {
				case "rollback":
					result.Receipt.Outcome = identity.CommitOutcomeNotCommitted
					result.Session = session.Session{}
				case "conflict":
					result.Receipt.Outcome = identity.CommitOutcomeConflict
					result.Session = session.Session{}
				case "in-progress":
					result.Receipt.Outcome = identity.CommitOutcomeInProgress
					result.Receipt.RetryAfter = time.Second
					result.Session = session.Session{}
				case "unknown":
					result.Receipt.Outcome = identity.CommitOutcomeUnknown
					result.Session = session.Session{}
				case "replayed":
					result.Replayed = true
				case "error-after-commit":
					err = errors.New("synthetic bounded failure")
				case "wrong-operation":
					result.Receipt.Feature.Operation.OperationID = "identity.password.signin"
				}
				return result, err
			}
			ctx := context.Background()
			if name == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if name == "expired" {
				s, _ := p.Session()
				spec, _ := s.Bindings()
				// The configured clock belongs to this task's native fixture.
				// Build a fresh issuer whose preparation is valid, then advance only
				// its trusted clock to the original exclusive authentication expiry.
				clock := &mutableIssueClock{now: spec.Authentication.Proof.ExpiresAt}
				c := signupIssuerConfig(t, spec.IssuedAt)
				c.Clock = clock
				late, e := session.NewPasswordSignupSessionIssuerWithCSRF(ex, c, signupCSRFKey(t))
				if e != nil {
					t.Fatal(e)
				}
				f, _ := command.PasswordSignupFeature()
				spec.Lookup = session.TokenDigest{}
				if _, e := late.PrepareSignup(f.Binding, spec); !errors.Is(e, session.ErrInvalidIssuance) {
					t.Fatal("exclusive expiry accepted", e)
				}
				return
			}
			got, err := issuer.Issue(ctx, bound)
			if name != "replayed" && err == nil {
				t.Fatal("adverse outcome accepted")
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("adverse outcome revealed synchronizer")
			}
		})
	}
}

func TestSignupIssuerInvalidBindingAndConcurrentCopies(t *testing.T) {
	issuer, p, command, _ := signupFixture(t)
	foreign, _, _, _ := signupFixture(t)
	if _, err := foreign.BindSignup(p, command); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("foreign issuer admitted", err)
	}
	f, _ := command.PasswordSignupFeature()
	plain, _ := identity.NewFeatureCommand(f)
	if _, err := issuer.BindSignup(p, plain); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("plain signup fabricated custody", err)
	}
	f.Binding.CorrelationID = "substituted"
	hash, cookie, _ := command.PasswordSignupCustody()
	changed, _ := identity.NewFeaturePasswordSignupCommand(f, hash, cookie)
	if _, err := issuer.BindSignup(p, changed); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("changed scope admitted", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			bound, err := issuer.BindSignup(p, command)
			if err == nil {
				wins.Add(1)
				if got, err := issuer.Issue(context.Background(), bound); err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Errorf("winning signup denied: %v", err)
				}
			} else if !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Errorf("wrong bind loser: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("copied signup generated multiple claims")
	}
}

func TestSignupIssuerConstructorsAndProfileIsolation(t *testing.T) {
	_, p, signup, ex := signupFixture(t)
	record, _ := p.Session()
	spec, _ := record.Bindings()
	c := signupIssuerConfig(t, spec.IssuedAt)
	if _, err := session.NewPasswordSignupSessionIssuer(nil, c); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("nil executor admitted", err)
	}
	if _, err := session.NewPasswordSignupSessionIssuerWithCSRF(ex, c, session.CSRFKey{}); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("zero synchronizer key admitted", err)
	}
	issuer, err := session.NewPasswordSignupSessionIssuer(ex, c)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := signup.PasswordSignupFeature()
	spec.Lookup = session.TokenDigest{}
	if _, err := issuer.PreparePassword(f.Binding, spec); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("signup issuer selected signin", err)
	}
	signinIssuer, _, _, _, _, _ := passwordIssuerFixture(t, true)
	if _, err := signinIssuer.PrepareSignup(f.Binding, spec); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("signin issuer selected signup", err)
	}
	prepared, err := issuer.PrepareSignup(f.Binding, spec)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := issuer.BindSignup(prepared, signup)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := issuer.Issue(context.Background(), bound); err != nil || got.Token == (session.Token{}) {
		t.Fatal("token-only signup denied", err)
	}
	if _, err := bound.CSRFToken(); !errors.Is(err, session.ErrInvalidCSRF) {
		t.Fatal("token-only signup fabricated synchronizer", err)
	}
}

func signupCSRFKey(t *testing.T) session.CSRFKey {
	t.Helper()
	key, _ := session.NewCSRFKey(2, make([]byte, 32))
	return key
}

func TestSignupIssuerPreservesOriginalPairedCommandAndCommitDelivery(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		old, prepared, signin, ex, _, _ := passwordIssuerFixture(t, anonymous)
		_ = old
		record, _ := prepared.Session()
		spec, _ := record.Bindings()
		spec.Lookup = session.TokenDigest{}
		if anonymous {
			spec.Remember, _ = session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: 15 * time.Minute, IdleTTL: 5 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		}
		feature, _ := signin.PasswordSigninFeature()
		feature.Binding.OperationID, feature.Binding.SchemaID = "identity.password.signup", "password-signup"
		feature.Operation.OperationID, feature.Operation.SchemaID = feature.Binding.OperationID, feature.Binding.SchemaID
		_, cookie, _ := signin.PasswordSigninCustody()
		command, err := identity.NewFeaturePasswordSignupCommand(feature, "$synthetic-only$prepared-signup-verifier", cookie)
		if err != nil {
			t.Fatal(err)
		}
		issuer, err := session.NewPasswordSignupSessionIssuerWithCSRF(ex, signupIssuerConfig(t, spec.IssuedAt), signupCSRFKey(t))
		if err != nil {
			t.Fatal(err)
		}
		p, err := issuer.PrepareSignup(feature.Binding, spec)
		if err != nil {
			t.Fatal("valid signup preparation denied", err)
		}
		if _, err := issuer.BindPassword(p, signin); !errors.Is(err, session.ErrInvalidIssuance) {
			t.Fatal("signup relabelled signin", err)
		}
		ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
			got, original, ok := r.PasswordSignupCommand()
			if !ok || got != command {
				t.Fatal("original signup command lost")
			}
			hash, bearer, ok := got.PasswordSignupCustody()
			if !ok || hash != "$synthetic-only$prepared-signup-verifier" || bearer != cookie {
				t.Fatal("paired custody changed")
			}
			if _, _, ok := r.PasswordCommand(); ok {
				t.Fatal("signup exposed signin arm")
			}
			if _, ok := r.Command(); ok {
				t.Fatal("signup exposed proof arm")
			}
			if _, _, ok := r.OTPCommand(); ok {
				t.Fatal("signup exposed OTP arm")
			}
			if _, ok := r.AuthenticatedProof(); ok {
				t.Fatal("signup fabricated proof")
			}
			return session.IssueExecution{Receipt: identity.CommandResult{Binding: feature.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: feature.Operation}}, Session: original}, nil
		}
		bound, err := issuer.BindSignup(p, command)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := bound.Request(); ok {
			t.Fatal("signup exposed secret-bearing recovery")
		}
		if _, err := bound.CSRFToken(); err == nil {
			t.Fatal("uncommitted synchronizer revealed")
		}
		original, _ := p.Session()
		result, err := issuer.Issue(context.Background(), bound)
		if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("exact signup commit denied", err)
		}
		before, _ := original.Bindings()
		after, _ := result.Session.Bindings()
		if before != after || result.Token == (session.Token{}) || result.Cookie.Value != "" {
			t.Fatal("original signup delivery changed")
		}
		key, _ := session.NewDigestKey(1, make([]byte, 32))
		if digest, err := result.Token.Digest(key, string(before.TenantID)); err != nil || digest != before.Lookup {
			t.Fatal("signup bearer differs from prepared lookup", err)
		}
		if anonymous && (!result.Cookie.Expires.IsZero() || result.Cookie.MaxAge != 0) {
			t.Fatal("browser signup cookie upgraded to persistent")
		}
		if _, err := bound.CSRFToken(); err != nil {
			t.Fatal("committed synchronizer withheld", err)
		}
		if _, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
			t.Fatal("signup executed twice", err)
		}
	}
}
