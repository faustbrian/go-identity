//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceServerHTTPPasswordTOTPFromRealEnrollment(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, passwordMFA: true}, true)
}

func TestReferenceServerHTTPPasswordTOTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, passwordMFA: true, completionCommitFault: true}, true)
}

func TestReferencePostgresPasswordTOTPCompatibility(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		name := "committed"
		if ambiguous {
			name = "lost-acknowledgement"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, completionCommitFault: ambiguous}, true)
		})
	}
}

func configureReferencePasswordMFA(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	issuer := c.PasswordSignup.Issuer
	issuer.Audience = c.PasswordSignin.Native.Profile.Audience
	issuer.Crypto.Limits.MaxCaveats = 16
	c.PasswordSignin.MFA = &passwordpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: origin, Issuer: issuer, Custody: c.PasswordSignup.Preparation}
	counters := c.PasswordSignup.Counters
	policy := *counters.CommandCounters
	policy.Policy, policy.Keys = c.Velocity.Native.Policy, c.Velocity.Native.Keys
	counters.CommandCounters = &policy
	admitted, err := policy.Policy.Admit("identity.mfa.totp-verify")
	if err != nil {
		t.Fatal(err)
	}
	counters.PolicyVersion = admitted.PolicyVersion
	c.PasswordSignin.TOTP = &reference.PasswordTOTPConfiguration{MaximumDuration: c.OTP.Timeout, ConfigurationID: "reference-password-totp-v1", PolicyID: "password-totp", Counters: counters, RiskKeys: c.OTP.RiskKeys, ComparisonKey: [32]byte{188}, ComparisonKeyVersion: 1, ActiveEnvelopeKeyID: "issue-envelope"}
	c.HTTPMFA = &reference.HTTPMFAConfiguration{PasswordTOTPVerify: true, ActorID: c.HTTPPasswordSignin.ActorID, PolicyRevision: c.HTTPPasswordSignin.PolicyRevision, VerificationNamespace: "reference-password-totp-http", VerificationKey: [32]byte{189}}
}

func passwordMFAFixtureCode(secret []byte, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	defer clear(sum)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

// Every account, factor, primary challenge and completed session is produced
// through public native/HTTP owners. No identity/factor/session row is seeded.
func proveReferencePasswordMFAHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, factor mfa.FactorID, secret []byte, profile ...string) {
	t.Helper()
	method, path, identifierKey, identifierValue := "password", "/v1/password/signin", "identifier", "registered@example.invalid"
	if len(profile) == 1 && profile[0] == "username" {
		method, path, identifierKey, identifierValue = "username", "/v1/username/signin", "username", "STRASSE"
	}
	invoke := func(path string, body any, cookies []*http.Cookie, variant string) (*http.Response, []byte) {
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if variant != "" {
			request.Header.Set("X-MFA-Variant", variant)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("password MFA transport unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(data) > 16384 {
			t.Fatal("bounded password MFA response")
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("authentication response cacheable")
		}
		return response, data
	}
	flowInput := map[string]any{"method": method}
	if method == "username" {
		flowInput["remember"] = f.usernameTOTPPersistent
	}
	response, data := invoke("/v1/session/preauth-issue", flowInput, nil, "")
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		t.Fatal("MFA original flow unavailable", response.StatusCode)
	}
	cookies := response.Cookies()
	signinInput := map[string]any{"flowID": flow.FlowID, identifierKey: identifierValue, "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}
	if method == "username" {
		signinInput["remember"] = f.usernameTOTPPersistent
	}
	response, data = invoke(path, signinInput, cookies, "")
	var challenge passwordhttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(data, &challenge) != nil || !challenge.ChallengeRequired || challenge.SignedIn || challenge.SessionID != "" || response.Header.Get("X-MFA-Token") == "" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("password primary did not deliver challenge-only result", response.StatusCode, challenge.Error)
	}
	proof := response.Header.Get("X-MFA-Token")
	if method == "username" {
		if f.usernamePrimaryRecovery == nil {
			t.Fatal("username primary restart recovery was not selected")
		}
		f.usernamePrimaryRecovery(challenge, cookies)
	}
	command, _ := identity.NewCommandID()
	code := passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second))
	body := map[string]any{"commandID": command, "preAuthID": flow.FlowID, "challengeID": challenge.ChallengeID, "factorID": factor, "token": proof, "code": code, "callbackURL": origin + "/reset", "trustDevice": false}
	if method == "username" {
		response, _ = invoke("/v1/mfa/totp-verify", body, cookies, "password")
		want := http.StatusForbidden
		if f.usernameTOTPOnly {
			want = http.StatusBadRequest // No email-password completion arm is selected.
		}
		if response.StatusCode != want || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("username challenge entered email-password completion", response.StatusCode)
		}
	}
	foreign, _ := invoke("/v1/session/preauth-issue", map[string]string{"method": method}, nil, "")
	if foreign.StatusCode != http.StatusOK {
		t.Fatal("foreign browser setup unavailable")
	}
	response, _ = invoke("/v1/mfa/totp-verify", body, foreign.Cookies(), method)
	if response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("foreign browser completed password challenge", response.StatusCode)
	}
	if f.usernameTOTPWithdrawal != "" {
		// These are deliberate authoritative invalidations of a genuinely issued
		// challenge, not seeded accounts, factors or replacement authentication.
		query := map[string]string{
			"user":       `UPDATE identity.users SET status='suspended',authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2)`,
			"identifier": `UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2)`,
			"factor":     `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2)`,
		}[f.usernameTOTPWithdrawal]
		var before int
		if query == "" || method != "username" {
			t.Fatal("unknown username authority withdrawal")
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&before); err != nil {
			t.Fatal("withdrawal session baseline unavailable")
		}
		changed, err := f.pool.Raw().Exec(ctx, query, otpTenant, string(factor))
		if err != nil || changed.RowsAffected() != 1 {
			t.Fatal("authoritative withdrawal fixture failed")
		}
		response, _ = invoke("/v1/mfa/totp-verify", body, cookies, method)
		if response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("withdrawn original authority completed username challenge", response.StatusCode)
		}
		var after, attempts, uses int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),c.attempts_remaining,p.uses FROM identity_mfa.continuations c JOIN public.capability_identity_one_use p ON p.tenant_id=c.tenant_id AND p.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, string(challenge.ChallengeID)).Scan(&after, &attempts, &uses); err != nil || after != before || attempts != 3 || uses != 0 {
			t.Fatal("withdrawn challenge changed session, attempt or one-use state")
		}
		return
	}
	wrongCommand, _ := identity.NewCommandID()
	wrongCode := "000000"
	if code == wrongCode {
		wrongCode = "000001"
	}
	wrong := map[string]any{"commandID": wrongCommand, "preAuthID": flow.FlowID, "challengeID": challenge.ChallengeID, "factorID": factor, "token": proof, "code": wrongCode, "callbackURL": origin + "/reset", "trustDevice": false}
	response, _ = invoke("/v1/mfa/totp-verify", wrong, cookies, method)
	if response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("wrong password TOTP code did not deny without delivery", response.StatusCode)
	}
	// Fail after protected session/factor work has begun. No successful session,
	// factor replay advancement or lifecycle effect may escape the transaction.
	var sessionsBefore int
	var stepBefore *int64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),last_step FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, otpTenant, string(factor)).Scan(&sessionsBefore, &stepBefore); err != nil {
		t.Fatal("completion rollback baseline unavailable")
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.password_totp_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic password TOTP rollback'; END $$; CREATE TRIGGER password_totp_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.password_totp_fixture_fail()`); err != nil {
		t.Fatal("completion rollback fixture unavailable")
	}
	cleanup := func() {
		bounded, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS password_totp_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS public.password_totp_fixture_fail()`); err != nil {
			t.Error("completion rollback fixture cleanup failed")
		}
	}
	t.Cleanup(cleanup)
	response, data = invoke("/v1/mfa/totp-verify", body, cookies, method)
	var aborted struct {
		CommitOutcome string
		SignedIn      bool
	}
	if json.Unmarshal(data, &aborted) != nil || response.StatusCode != http.StatusServiceUnavailable || aborted.CommitOutcome != "not_committed" || aborted.SignedIn || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("failed lifecycle delivered password MFA credentials", response.StatusCode, aborted.CommitOutcome)
	}
	cleanup()
	var sessionsAfter, lifecycle int
	var stepAfter *int64
	commandBytes, _ := base64.RawURLEncoding.DecodeString(string(command))
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3),last_step FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, otpTenant, string(factor), commandBytes).Scan(&sessionsAfter, &lifecycle, &stepAfter); err != nil || sessionsAfter != sessionsBefore || lifecycle != 0 || stepBefore == nil != (stepAfter == nil) || stepBefore != nil && stepAfter != nil && *stepBefore != *stepAfter {
		t.Fatal("rollback leaked session, lifecycle or factor replay advancement")
	}
	owner, err := features.PasswordTOTP()
	if method == "username" {
		owner, err = features.UsernameTOTP()
	}
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(otpTenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.FlowID)}}}
	query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: command, AnonymousFlowID: string(flow.FlowID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.totp-verify"}
	recovered, err := owner.RecoverTotpVerify(ctx, query, caller)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("failed completion recovery lost outcome or exposed custody", recovered.Outcome, fmt.Sprintf("%T", err))
	}
	command, _ = identity.NewCommandID()
	// A proven abort retires its reserved one-use child; it cannot be revived by
	// changing the completion command. Obtain a genuinely new password primary.
	response, data = invoke("/v1/session/preauth-issue", flowInput, nil, "")
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		t.Fatal("replacement password flow unavailable")
	}
	cookies = response.Cookies()
	signinInput["flowID"] = flow.FlowID
	response, data = invoke(path, signinInput, cookies, "")
	challenge = passwordhttp.SigninResponse{}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &challenge) != nil || !challenge.ChallengeRequired || challenge.SignedIn || response.Header.Get("X-MFA-Token") == "" || len(response.Cookies()) != 0 {
		t.Fatal("replacement password challenge unavailable", response.StatusCode)
	}
	body["commandID"], body["preAuthID"], body["challengeID"], body["token"] = command, flow.FlowID, challenge.ChallengeID, response.Header.Get("X-MFA-Token")
	query.AnonymousFlowID = string(flow.FlowID)
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	response, data = invoke("/v1/mfa/totp-verify", body, cookies, method)
	var result struct {
		SignedIn      bool
		CommitOutcome string
		CommandID     string
		SessionID     string
		Error         string
	}
	decodeErr := json.Unmarshal(data, &result)
	if f.completionFault != nil {
		if !f.completionFault.hit.Load() || response.StatusCode != http.StatusServiceUnavailable || decodeErr != nil || result.SignedIn || result.CommitOutcome != "unknown" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("lost commit acknowledgement did not withhold credentials", response.StatusCode, result.CommitOutcome, "fault hit", f.completionFault.hit.Load())
		}
		query.CommandID = command
		recovered, err := owner.RecoverTotpVerify(ctx, query, caller)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Session.Replayed || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("ambiguous completion cannot reconcile without credentials", fmt.Sprintf("%T", err), recovered.Outcome)
		}
		var newSessions, uses, lifecycle int
		commandBytes, _ := base64.RawURLEncoding.DecodeString(string(command))
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT uses FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3)`, otpTenant, string(challenge.ChallengeID), commandBytes).Scan(&newSessions, &uses, &lifecycle); err != nil || newSessions != sessionsBefore+1 || uses != 1 || lifecycle != 1 {
			t.Fatal("ambiguous commit did not conserve one session, use and lifecycle")
		}
		response, _ = invoke("/v1/mfa/totp-verify", body, cookies, method)
		if response.StatusCode == http.StatusOK || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("ambiguous retry redelivered credentials")
		}
		return
	}
	if response.StatusCode != 200 || decodeErr != nil || !result.SignedIn || result.CommitOutcome != "committed" || result.SessionID == "" || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("password TOTP did not create usable session", response.StatusCode, result.Error, "outcome", result.CommitOutcome, "command present", result.CommandID != "")
	}
	completedCookies, csrf := response.Cookies(), response.Header.Get("X-CSRF-Token")
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(completedCookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !observed.Authenticated || observed.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("completed password MFA session unreadable", err)
	}
	if method == "username" {
		stored, err := observed.Session.Bindings()
		if err != nil || (stored.Remember.Choice() == session.PersistentSession) != f.usernameTOTPPersistent || (completedCookies[0].MaxAge > 0) != f.usernameTOTPPersistent {
			t.Fatal("username TOTP completion changed original remember policy")
		}
	}
	response, data = invoke("/v1/mfa/totp-verify", body, cookies, method)
	if response.StatusCode == 200 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("completion replay redelivered credentials")
	}
	query.CommandID = command
	recovered, err = owner.RecoverTotpVerify(ctx, query, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Session.Replayed || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("completed password MFA recovery redelivered or lost outcome")
	}
	foreignCaller := caller.Clone()
	foreignCaller.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAABA"
	if _, err := owner.RecoverTotpVerify(ctx, query, foreignCaller); err == nil {
		t.Fatal("foreign actor recovered password MFA command")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, completedCookies, csrf, result.SessionID, f, features)
}
