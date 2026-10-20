//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestReferencePostgresPhonePasswordTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, mfaEnrollment: true}, true)
}

func TestReferencePostgresPhonePasswordTOTPIndependent(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, mfaEnrollment: true}, true)
}

func TestReferencePostgresPhonePasswordTOTPRollback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, phoneTOTPRollback: true, mfaEnrollment: true}, true)
}

func TestReferencePostgresPhonePasswordTOTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, completionCommitFault: true, mfaEnrollment: true}, true)
}

// Registration, verification, phone possession and independent TOTP enrollment
// are real preceding public workflows. This consumer supplies configuration and
// secrets, never a domain store, proof verdict, continuation or session engine.
func proveReferencePhoneTOTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, origin string, factor mfa.FactorID, secret []byte) {
	t.Helper()
	primary, err := features.PhoneSignin()
	if err != nil {
		t.Fatal(err)
	}
	completion, err := features.PhoneTOTP()
	if err != nil {
		t.Fatal("selected phone TOTP completion unavailable", err)
	}
	preauth, err := features.PhoneSigninPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	bound, err := preauth.BindPreAuthIdentifier(ctx, otpTenant, "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, f.config.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	prepared, err := preauth.Prepare(ctx, session.PreAuthPrepareInput{TenantID: otpTenant, CommandID: id, CorrelationID: string(id), Remember: remember, IdentifierBinding: bound})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := preauth.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("original phone browser issuance", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "phone-totp-consumer", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.phone.password-signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.phone.password-signin"}}}
	passwordValue := "synthetic-registration-password"
	if f.phonePasswordReset && !f.phoneResetRollback {
		passwordValue = referencePhoneResetPassword
	}
	candidate, err := primitive.NewSecret([]byte(passwordValue))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	var before int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	signed, err := primary.Signin(ctx, password.SigninRequest{TenantID: otpTenant, PreAuthID: flow.Binding.ID, Cookie: auth.NewBearerCredential(wire), Identifier: "+12025550123", Password: candidate, Remember: remember, Origin: origin, CallbackURL: flow.Binding.Intent.CallbackURL, Network: "127.0.0.1", Device: "phone-totp-consumer", Caller: caller})
	if err != nil || signed.State != auth.SignInStateChallengeRequired || signed.SessionID != "" || signed.Issuance.Token != (session.Token{}) {
		t.Fatal("phone comparison did not require real TOTP", err)
	}
	var after int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&after); err != nil || before != after {
		t.Fatal("phone comparison issued session before factor", err)
	}
	command, _ := identity.NewCommandID()
	code, err := auth.NewOneTimeCode(passwordMFAFixtureCode(secret, time.Now().UTC().Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = "identity.mfa.totp-verify"
	caller.Request.Resource = authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(signed.Challenge.ID)}
	request := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: command, ChallengeID: mfa.ChallengeID(signed.Challenge.ID), FactorID: factor, Proof: signed.Challenge.Proof, Code: code, PreAuthID: flow.Binding.ID, Cookie: auth.NewBearerCredential(wire), Caller: caller, Origin: origin, Callback: flow.Binding.Intent.CallbackURL, Network: "127.0.0.1", Device: "phone-totp-consumer"}
	readState := func() (sessions, attempts, uses int, step *int64) {
		t.Helper()
		err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),c.attempts_remaining,p.uses,t.last_step FROM identity_mfa.continuations c JOIN public.capability_identity_one_use p ON p.tenant_id=c.tenant_id AND p.capability_id=c.continuation_id JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id AND t.factor_id=$3 WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, string(request.ChallengeID), string(factor)).Scan(&sessions, &attempts, &uses, &step)
		if err != nil {
			t.Fatal("real phone TOTP state unavailable", err)
		}
		return
	}
	initialSessions, initialAttempts, initialUses, initialStep := readState()
	if initialAttempts != 3 || initialUses != 0 || initialStep == nil {
		t.Fatal("phone challenge lacks original unused budget and confirmed replay state")
	}
	assertUnchanged := func() {
		t.Helper()
		sessions, attempts, uses, step := readState()
		if sessions != initialSessions || attempts != initialAttempts || uses != initialUses || step == nil || *step != *initialStep {
			t.Fatal("rejected phone completion changed session, factor or original attempt budget")
		}
	}
	deny := func(owner mfa.TOTPCompletionService, submitted mfa.TotpVerifyRequest) {
		t.Helper()
		out, err := owner.TotpVerify(ctx, submitted)
		if err == nil || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("invalid phone completion delivered credentials")
		}
	}
	for _, variant := range []string{"origin", "callback", "cookie", "trust", "tenant"} {
		submitted := request
		submitted.CommandID, _ = identity.NewCommandID()
		switch variant {
		case "origin":
			submitted.Origin = "https://foreign.example"
		case "callback":
			submitted.Callback = "https://foreign.example/reset"
		case "cookie":
			submitted.Cookie = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		case "trust":
			submitted.TrustDevice = true
		case "tenant":
			submitted.TenantID = "foreign-tenant"
			submitted.Caller = submitted.Caller.Clone()
			submitted.Caller.Request.Tenant = "foreign-tenant"
		}
		deny(completion, submitted)
		assertUnchanged()
	}
	emailCompletion, err := features.PasswordTOTP()
	if f.phoneTOTPOnly {
		if err == nil || emailCompletion != nil {
			t.Fatal("phone selection exposed unselected email TOTP")
		}
	} else if err != nil {
		t.Fatal("independent email completion profile unavailable", err)
	} else {
		deny(emailCompletion, request)
		assertUnchanged()
	}

	// Exclude every admissible code, including the already-used enrollment step,
	// rather than assuming a fixed synthetic value cannot collide with TOTP.
	wrongWire := ""
	wrongAt := time.Now().UTC()
	for _, candidate := range []string{"000000", "000001", "000002", "000003", "000004"} {
		collision := false
		for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
			collision = collision || passwordMFAFixtureCode(secret, wrongAt.Add(offset)) == candidate
		}
		if !collision {
			wrongWire = candidate
			break
		}
	}
	if wrongWire == "" {
		t.Fatal("unable to select bounded nonmatching TOTP fixture")
	}
	wrong := request
	wrong.CommandID, _ = identity.NewCommandID()
	wrong.Code, err = auth.NewOneTimeCode(wrongWire)
	if err != nil {
		t.Fatal(err)
	}
	deny(completion, wrong)
	initialAttempts--
	assertUnchanged()
	deny(completion, wrong)
	assertUnchanged()
	changed := wrong
	changed.Code = request.Code
	deny(completion, changed)
	assertUnchanged()

	var clearRollback func()
	if f.phoneTOTPRollback {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.phone_totp_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic phone TOTP rollback'; END $$; CREATE TRIGGER phone_totp_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.phone_totp_fixture_fail()`); err != nil {
			t.Fatal("phone completion rollback fixture unavailable", err)
		}
		clearRollback = func() {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS phone_totp_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS public.phone_totp_fixture_fail()`); err != nil {
				t.Error("phone rollback fixture cleanup failed", err)
			}
		}
		t.Cleanup(clearRollback)
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	result, err := completion.TotpVerify(ctx, request)
	if f.completionFault != nil || f.phoneTOTPRollback {
		if f.completionFault != nil {
			f.completionFault.armed.Store(false)
		}
		want := identity.CommitOutcomeNotCommitted
		if f.completionFault != nil {
			want = identity.CommitOutcomeUnknown
			if !f.completionFault.hit.Load() {
				t.Fatal("phone completion did not reach actual lost-COMMIT boundary")
			}
		}
		if err == nil || result.Outcome != want || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("failed or ambiguous phone completion disclosed credentials or changed outcome", result.Outcome, err)
		}
		if f.phoneTOTPRollback {
			assertUnchanged()
		} else {
			sessions, _, uses, step := readState()
			if sessions != initialSessions+1 || uses != 1 || step == nil || *step <= *initialStep {
				t.Fatal("lost phone COMMIT acknowledgement did not conserve atomic session/child/factor effects")
			}
		}
		commandBytes, _ := base64.RawURLEncoding.DecodeString(string(command))
		var lifecycle int
		wantLifecycle := 0
		if f.completionFault != nil {
			wantLifecycle = 1
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1`, commandBytes).Scan(&lifecycle); err != nil || lifecycle != wantLifecycle {
			t.Fatal("phone failure/ambiguity violated lifecycle atomicity", err)
		}
		query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: command, AnonymousFlowID: string(flow.Binding.ID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.totp-verify"}
		caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.Binding.ID)}
		history, recoveryErr := completion.RecoverTotpVerify(ctx, query, caller)
		want = identity.CommitOutcomeNotCommitted
		if f.completionFault != nil {
			want = identity.CommitOutcomeCommitted
		}
		if history.Outcome != want || history.Session.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || f.completionFault != nil && recoveryErr != nil || f.phoneTOTPRollback && recoveryErr == nil {
			t.Fatal("phone failure recovery lost original result or disclosed credentials", history.Outcome, recoveryErr)
		}
		if clearRollback != nil {
			clearRollback()
		}
		*f.phoneTOTPCompleted = true
		return
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Session.Token == (session.Token{}) || result.CSRFToken == (session.CSRFToken{}) {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("genuine phone TOTP rejected field", invalid.Field)
		}
		t.Fatal("genuine phone TOTP did not deliver session", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, result.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !observed.Authenticated || observed.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("phone TOTP session is not authenticated", err)
	}
	stored, err := observed.Session.Bindings()
	if err != nil || stored.Remember.Choice() != session.BrowserSession {
		t.Fatal("phone TOTP completion changed original remember policy")
	}
	sessionsAfter, _, usesAfter, stepAfter := readState()
	if sessionsAfter != initialSessions+1 || usesAfter != 1 || stepAfter == nil || *stepAfter <= *initialStep {
		t.Fatal("phone completion did not atomically issue one session and consume original child/factor replay")
	}
	commandBytes, _ := base64.RawURLEncoding.DecodeString(string(command))
	var lifecycle int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1`, commandBytes).Scan(&lifecycle); err != nil || lifecycle != 1 {
		t.Fatal("phone completion lacks exactly one durable lifecycle event", err)
	}
	retry, err := completion.TotpVerify(ctx, request)
	if err != nil || retry.Outcome != identity.CommitOutcomeCommitted || retry.Session.Token != (session.Token{}) || retry.CSRFToken != (session.CSRFToken{}) || !retry.Session.Replayed {
		t.Fatal("phone completion retry changed outcome or redelivered credentials", err)
	}
	query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: command, AnonymousFlowID: string(flow.Binding.ID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.totp-verify"}
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.Binding.ID)}
	history, err := completion.RecoverTotpVerify(ctx, query, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || !history.Session.Replayed || history.Session.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("original phone TOTP recovery lost result or redelivered credentials", err)
	}
	foreign := caller.Clone()
	foreign.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAABA"
	if _, err := completion.RecoverTotpVerify(ctx, query, foreign); err == nil {
		t.Fatal("foreign actor recovered phone completion")
	}
	logoutID, _ := identity.NewCommandID()
	signout := session.SignOutRequest{TenantID: otpTenant, CommandID: logoutID, CorrelationID: string(logoutID), Transport: session.CredentialCookie, Credential: credential}
	if _, err := sessions.SignOut(ctx, signout, session.CSRFToken{}); err == nil {
		t.Fatal("phone MFA cookie signed out without synchronizer")
	}
	loggedOut, err := sessions.SignOut(ctx, signout, result.CSRFToken)
	if err != nil || !loggedOut.SignedOut || !loggedOut.ClearCookie || loggedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine phone MFA session did not sign out", err)
	}
	observed, err = sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || observed.Authenticated {
		t.Fatal("signed-out phone MFA credential remained authenticated", err)
	}
	*f.phoneTOTPCompleted = true
}
