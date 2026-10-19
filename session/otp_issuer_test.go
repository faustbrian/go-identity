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

func otpIssuerFixture(t testing.TB, anonymous, csrf bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	return otpIssuerPolicyFixture(t, anonymous, csrf, session.BrowserSession)
}

func otpIssuerPolicyFixture(t testing.TB, anonymous, csrf bool, choice session.RememberChoice, phone ...bool) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	spec, p := otpSession(t)
	var err error
	spec.Remember, err = session.ResolveRememberPolicy(choice, config())
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := spec.Authority.Bindings()
	spec.Version, vector.Session.Version = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	spec.Lookup = session.TokenDigest{}
	b := issueBinding(spec)
	b.CommandID, b.OperationID, b.SchemaID, b.RecordID = p.CommandID, "identity.otp.signin", "identity-otp-signin", ""
	b.ActorID, b.ActorKind = "login-service", authorization.SubjectServiceAccount
	d := identity.FeatureOperation{Owner: "identity/otp", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if len(phone) == 1 && phone[0] {
		b.OperationID, b.SchemaID = "identity.phone.signin", "identity.phone.signin.native-v1"
		d.Owner, d.OperationID, d.SchemaID = "identity/phone", b.OperationID, b.SchemaID
		p.IdentifierKind = identity.IdentifierPhone
	}
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", "original-preauth"
		d.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	metadata, err := session.NewOTPAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	clock := &mutableIssueClock{now: spec.IssuedAt}
	executor := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedOTPIssue(t, r), nil
	}, recover: func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		t.Fatal("code-bearing OTP request entered recovery")
		return session.IssueExecution{}, nil
	}}
	config := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}
	var issuer *session.SessionIssuer
	if csrf {
		csrfKey, _ := session.NewCSRFKey(2, make([]byte, 32))
		issuer, err = session.NewOTPSessionIssuerWithCSRF(executor, config, csrfKey)
	} else {
		issuer, err = session.NewOTPSessionIssuer(executor, config)
	}
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.PrepareOTP(b, spec, metadata)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	command, err := identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: d, Fields: []identity.FeatureField{{Name: "native.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "frozen-native-intent"}}}}, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	return issuer, prepared, command, executor, clock
}

func TestOTPIssuerPhoneSigninRetainsDistinctPurposeAndRemember(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		t.Run(map[session.RememberChoice]string{session.BrowserSession: "browser", session.PersistentSession: "persistent"}[choice], func(t *testing.T) {
			issuer, prepared, command, _, _ := otpIssuerPolicyFixture(t, true, true, choice, true)
			f, _ := command.Feature()
			original, _ := prepared.Session()
			originalSpec, _ := original.Bindings()
			originalOTP, _ := original.OTPAuthentication().Bindings()
			if f.Operation.Owner != "identity/phone" || f.Binding.OperationID != "identity.phone.signin" || originalOTP.IdentifierKind != identity.IdentifierPhone {
				t.Fatal("phone signin lost its owning operation or identifier kind")
			}
			changed := f
			changed.Binding.OperationID, changed.Operation.OperationID = "identity.otp.signin", "identity.otp.signin"
			changed.Binding.SchemaID, changed.Operation.SchemaID = "identity-otp-signin", "identity-otp-signin"
			changed.Operation.Owner = "identity/otp"
			code, _ := command.OneTimeCode()
			cookie, _ := command.PreAuthCookie()
			other, err := identity.NewFeatureOneTimeCodePreAuthCommand(changed, code, cookie)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.BindOTP(prepared, other); !errors.Is(err, session.ErrInvalidIssuance) {
				t.Fatal("phone preparation accepted another OTP workflow", err)
			}
			bound, err := issuer.BindOTP(prepared, command)
			if err != nil {
				t.Fatal("phone preparation rejected original consuming custody", err)
			}
			result, err := issuer.Issue(context.Background(), bound)
			if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
				t.Fatal("phone consuming commit failed", err)
			}
			resultSpec, _ := result.Session.Bindings()
			resultOTP, _ := result.Session.OTPAuthentication().Bindings()
			if resultOTP != originalOTP || resultSpec.Remember != originalSpec.Remember || resultSpec.Lookup != originalSpec.Lookup {
				t.Fatal("phone issuance replaced original authentication/remember/token custody")
			}
			if _, err := bound.CSRFToken(); err != nil {
				t.Fatal("fresh phone commit withheld its original CSRF token", err)
			}
		})
	}
}

func TestOTPIssuerPhoneSigninRejectsEmailAuthentication(t *testing.T) {
	issuer, prepared, command, _, _ := otpIssuerFixture(t, true, true)
	original, _ := prepared.Session()
	spec, _ := original.Bindings()
	spec.Lookup = session.TokenDigest{}
	f, _ := command.Feature()
	f.Binding.OperationID, f.Binding.SchemaID = "identity.phone.signin", "identity.phone.signin.native-v1"
	if _, err := issuer.PrepareOTP(f.Binding, spec, original.OTPAuthentication()); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("phone-owned signin accepted an email OTP authentication", err)
	}
}

func committedOTPIssue(t testing.TB, r session.IssueRequest) session.IssueExecution {
	t.Helper()
	c, record, ok := r.OTPCommand()
	if !ok {
		t.Fatal("original consuming OTP command missing")
	}
	f, _ := c.Feature()
	if _, ok := c.OneTimeCode(); !ok {
		t.Fatal("submitted code custody lost")
	}
	if _, ok := c.PreAuthCookie(); !ok {
		t.Fatal("original pre-auth custody lost")
	}
	if _, ok := r.Command(); ok {
		t.Fatal("OTP request downgraded to legacy session command")
	}
	if _, ok := r.AuthenticatedProof(); ok {
		t.Fatal("OTP request fabricated final proof")
	}
	if err := r.Validate(nil, time.Now()); !errors.Is(err, session.ErrInvalidIssueRequest) {
		t.Fatal("OTP request admitted by credential-proof validation", err)
	}
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: f.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: f.Operation}}, Session: record}
}

func TestOTPIssuerPreservesAnonymousAndUserCustodyThroughCommit(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, csrf := range []bool{false, true} {
			issuer, prepared, command, _, clock := otpIssuerFixture(t, anonymous, csrf)
			original, ok := prepared.Session()
			if !ok {
				t.Fatal("native adapter cannot bind prepared session intent")
			}
			if _, ok := prepared.Request(); ok {
				t.Fatal("unbound preparation escaped as executable request")
			}
			if got, err := issuer.Issue(context.Background(), prepared); !errors.Is(err, session.ErrInvalidIssuance) || got.CommitOutcome != identity.CommitOutcomeInvalid {
				t.Fatal("unbound OTP preparation executed", err)
			}
			bound, err := issuer.BindOTP(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.BindOTP(bound, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Fatal("bound preparation rebound", err)
			}
			if _, ok := bound.Request(); ok {
				t.Fatal("code-bearing request advertised as safe recovery input")
			}
			got, err := issuer.Issue(context.Background(), bound)
			if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Replayed {
				t.Fatal("exact consuming commit failed", err)
			}
			before, _ := original.OTPAuthentication().Bindings()
			after, _ := got.Session.OTPAuthentication().Bindings()
			beforeSpec, _ := original.Bindings()
			afterSpec, _ := got.Session.Bindings()
			if before != after || beforeSpec.Lookup != afterSpec.Lookup || beforeSpec.Remember != afterSpec.Remember || !afterSpec.IssuedAt.Equal(clock.now) {
				t.Fatal("binding regenerated custody or remember policy")
			}
			key, _ := session.NewDigestKey(1, make([]byte, 32))
			digest, err := got.Token.Digest(key, string(beforeSpec.TenantID))
			if err != nil || digest != beforeSpec.Lookup || got.Cookie.Value != "" {
				t.Fatal("delivered token does not match original prepared digest", err)
			}
			_, csrfErr := bound.CSRFToken()
			if (csrfErr == nil) != csrf {
				t.Fatal("wrong CSRF delivery profile", csrfErr)
			}
			if retry, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Fatal("preparation executed twice", err)
			} else {
				requireNoIssuedToken(t, retry)
			}
		}
	}
}

func TestOTPIssuerBindRejectsSubstitutionAndSharesOneClaim(t *testing.T) {
	issuer, prepared, command, executor, _ := otpIssuerFixture(t, true, true)
	other, _, _, _, _ := otpIssuerFixture(t, true, true)
	if _, err := other.BindOTP(prepared, command); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("foreign issuer bound original custody", err)
	}
	f, _ := command.Feature()
	plain, _ := identity.NewFeatureCommand(f)
	if _, err := issuer.BindOTP(prepared, plain); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("structural command fabricated code/preauth", err)
	}
	f.Binding.CorrelationID = "substituted"
	code, _ := command.OneTimeCode()
	cookie, _ := command.PreAuthCookie()
	changed, _ := identity.NewFeatureOneTimeCodePreAuthCommand(f, code, cookie)
	if _, err := issuer.BindOTP(prepared, changed); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("substituted command scope accepted", err)
	}
	var winners atomic.Int32
	var calls atomic.Int32
	executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		calls.Add(1)
		return committedOTPIssue(t, r), nil
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			bound, err := issuer.BindOTP(prepared, command)
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
		t.Fatal("copies bound or executed different consuming commands")
	}
}

func TestOTPIssuerWithholdsCommittedCredentialAfterOriginalDeadline(t *testing.T) {
	issuer, prepared, command, executor, clock := otpIssuerFixture(t, true, true)
	bound, err := issuer.BindOTP(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		result := committedOTPIssue(t, r)
		p, _ := result.Session.OTPAuthentication().Bindings()
		clock.now = p.ValidUntil
		return result, nil
	}
	got, err := issuer.Issue(context.Background(), bound)
	if err == nil || got.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("expired original continuation did not suppress delivery", err)
	}
	requireNoIssuedToken(t, got)
	if _, err := bound.CSRFToken(); !errors.Is(err, session.ErrInvalidCSRF) {
		t.Fatal("expired original continuation disclosed CSRF", err)
	}
}

func TestOTPIssuerPreservesAllOutcomesWithoutCredentialDelivery(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeUnknown, identity.CommitOutcomeCommitted} {
		issuer, prepared, command, executor, _ := otpIssuerFixture(t, true, true)
		bound, err := issuer.BindOTP(prepared, command)
		if err != nil {
			t.Fatal(err)
		}
		executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
			e := committedOTPIssue(t, r)
			e.Receipt.Outcome = outcome
			if outcome == identity.CommitOutcomeCommitted {
				e.Replayed = true
			} else {
				e.Session = session.Session{}
				e.Receipt.AuditEventID = ""
				if outcome == identity.CommitOutcomeInProgress {
					e.Receipt.RetryAfter = time.Second
				}
			}
			return e, nil
		}
		got, err := issuer.Issue(context.Background(), bound)
		if got.CommitOutcome != outcome || (err == nil) != (outcome == identity.CommitOutcomeCommitted) {
			t.Fatal("consuming outcome classification changed", err)
		}
		requireNoIssuedToken(t, got)
		if _, err := bound.CSRFToken(); !errors.Is(err, session.ErrInvalidCSRF) {
			t.Fatal("historical or noncommitted result disclosed CSRF", err)
		}
	}
}

func TestOTPIssuerRejectsMalformedCompletionAndCodeBearingRecovery(t *testing.T) {
	for _, kind := range []string{"operation", "scope", "provenance", "error", "cancel", "panic", "recovery"} {
		t.Run(kind, func(t *testing.T) {
			issuer, prepared, command, executor, _ := otpIssuerFixture(t, false, true)
			bound, err := issuer.BindOTP(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e := committedOTPIssue(t, r)
				switch kind {
				case "operation":
					e.Receipt.Feature.Operation = session.IssueOperation()
				case "scope":
					e.Receipt.Binding.CorrelationID = "substituted"
				case "provenance":
					base, _ := e.Session.Bindings()
					p, _ := e.Session.OTPAuthentication().Bindings()
					p.AttemptID = "BAQEBAQEBAQEBAQEBAQEBA"
					changed, err := session.NewOTPAuthentication(p)
					if err != nil {
						t.Fatal(err)
					}
					e.Session, err = session.NewSessionWithOTPAndCSRF(base, changed, e.Session.CSRFState())
					if err != nil {
						t.Fatal(err)
					}
				case "error":
					return e, errors.New("private dependency detail")
				case "cancel":
					cancel()
				case "panic":
					panic("private dependency detail")
				case "recovery":
					if got, err := issuer.Recover(ctx, r); !errors.Is(err, session.ErrInvalidIssuance) || got.CommitOutcome != identity.CommitOutcomeInvalid {
						t.Fatal("code-bearing input entered recovery", err)
					}
					return e, errors.New("recovery fixture suppresses original delivery")
				}
				return e, nil
			}
			got, err := issuer.Issue(ctx, bound)
			if err == nil {
				t.Fatal("non-deliverable execution succeeded")
			}
			want := identity.CommitOutcomeUnknown
			if kind == "error" || kind == "cancel" || kind == "recovery" {
				want = identity.CommitOutcomeCommitted
			}
			if got.CommitOutcome != want {
				t.Fatal("lost authoritative outcome", err)
			}
			requireNoIssuedToken(t, got)
			if _, err := bound.CSRFToken(); !errors.Is(err, session.ErrInvalidCSRF) {
				t.Fatal("non-deliverable execution disclosed CSRF", err)
			}
		})
	}
}

func TestOTPIssuerExpiryAndCanceledAdmissionDoNotEnterExecutor(t *testing.T) {
	for _, expired := range []bool{false, true} {
		issuer, prepared, command, executor, clock := otpIssuerFixture(t, true, false)
		bound, err := issuer.BindOTP(prepared, command)
		if err != nil {
			t.Fatal(err)
		}
		executor.execute = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
			t.Fatal("invalid admission entered durable executor")
			return session.IssueExecution{}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		if expired {
			record, _ := prepared.Session()
			p, _ := record.OTPAuthentication().Bindings()
			clock.now = p.ValidUntil
		} else {
			cancel()
		}
		got, err := issuer.Issue(ctx, bound)
		cancel()
		if err == nil || got.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("failed pre-execution admission acquired an outcome", err)
		}
		requireNoIssuedToken(t, got)
	}
}

func TestOTPIssuerKeepsPersistentChoiceAndClosedProfile(t *testing.T) {
	issuer, prepared, command, executor, _ := otpIssuerPolicyFixture(t, true, true, session.PersistentSession)
	bound, err := issuer.BindOTP(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.Issue(context.Background(), bound)
	if err != nil || got.Cookie.Expires.IsZero() || got.Cookie.MaxAge <= 0 {
		t.Fatal("persistent choice became a browser session", err)
	}
	base, _ := got.Session.Bindings()
	base.Lookup = session.TokenDigest{}
	metadata := got.Session.OTPAuthentication()
	f, _ := command.Feature()
	proofIssuer, _, _, _ := issuerFixture(t)
	if _, err := proofIssuer.PrepareOTP(f.Binding, base, metadata); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("legacy proof profile accepted OTP preparation", err)
	}
	if _, err := issuer.Prepare(f.Binding, base, auth.AuthenticatedProof{}); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("OTP profile accepted proof preparation", err)
	}
	if _, err := session.NewOTPSessionIssuer(executor, session.IssuerConfig{}); !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("zero OTP composition accepted", err)
	}
}
