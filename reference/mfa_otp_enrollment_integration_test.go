//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestReferencePostgresOTPEnrollmentAndSignin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true}, true)
}

func TestReferencePostgresOTPEnrollmentWithoutLogin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPEnrollmentOnly: true}, true)
}

func configureReferenceMFAOTPEnrollment(t *testing.T, c *reference.StoreConfiguration, origin string, standalone bool) {
	t.Helper()
	configureReferencePasswordMFA(t, c, origin)
	configureReferenceMFAEnrollment(t, c, origin)
	shared := c.MFAEnrollment
	requestKeys, err := kernel.NewRequestKeyConfig("reference-mfa-otp-enable", [32]byte{211}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	n, err := mfapg.NewOTPEnrollmentConfig(requestKeys, [32]byte{212}, [32]byte{213}, 1, "issue-envelope")
	if err != nil {
		t.Fatal(err)
	}
	n.ConfigurationID, n.PolicyID = "reference-mfa-otp-enable-v1", "mfa-otp-enable"
	n.MaximumDuration, n.TTL = shared.Native.MaximumDuration, shared.Native.TTL
	n.Coordinator, n.Risk, n.Counters = shared.Native.Coordinator, shared.Native.Risk, shared.Native.Counters
	n.Risk.ConfigurationID = n.ConfigurationID
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.MFAOTPEnrollment = &reference.MFAOTPEnrollmentConfiguration{Native: n, Primary: shared.Primary, CSRFKeys: shared.CSRFKeys, AllowedOrigins: shared.AllowedOrigins, SessionKeys: map[uint32][]byte{11: bytes.Repeat([]byte{0x79}, 32)}, FreshnessLimit: 5 * time.Minute, Policy: policy, AttemptKeyVersion: 7, TemplateID: c.OTP.TemplateID, TemplateVersion: c.OTP.TemplateVersion, LocaleChain: c.OTP.LocaleChain}
	loginKeys, err := kernel.NewRequestKeyConfig("reference-secondary-otp", [32]byte{214}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordSignin.OTP = &reference.PasswordOTPConfiguration{MaximumDuration: n.MaximumDuration, ConfigurationID: "reference-secondary-otp-v1", CompletionConfigurationID: "reference-secondary-otp-completion-v1", PolicyID: "password-otp", RequestKeys: loginKeys, IntentKey: [32]byte{215}, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID, Counters: n.Counters, RiskKeys: n.Risk.Keys, Policy: policy, AttemptKeyVersion: 7, TemplateID: c.OTP.TemplateID, TemplateVersion: c.OTP.TemplateVersion, LocaleChain: c.OTP.LocaleChain}
	c.PasswordSignin.MFA.AllowedMethods = []string{"otp"}
	c.PasswordSignin.TOTP = nil
	c.MFAEnrollment, c.HTTPMFAEnrollment = nil, nil
	c.HTTPMFA.PasswordTOTPVerify = false
	c.HTTPMFA.PasswordOTPVerify, c.HTTPMFA.PasswordOTPSend = true, true
	if standalone {
		c.PasswordSignin.OTP, c.PasswordSignin.MFA, c.HTTPMFA = nil, nil, nil
	}
}

// All identity, session, primary proof and factor state comes from public
// workflows. Only delivery provider IO is captured, at the supported sender seam.
func proveReferenceMFAOTPEnrollment(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, cookies []*http.Cookie, csrfWire string, messages <-chan string, recipient identity.IdentifierID) {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("original primary cookie missing")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("original registered session unavailable", err)
	}
	bindings, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(bindings.UserID)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(bindings.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	verifier, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	proof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: auth.NewBearerCredential(cookies[0].Value), Password: candidate, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"}, Caller: caller, Network: "127.0.0.1", Device: "reference-enrollment-device"}, CSRFToken: csrf})
	if err != nil {
		t.Fatal("fresh OTP-enrollment proof", err)
	}
	enroller, err := features.MFAOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := features.MFAOTPEnrollmentConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("reference-otp-enable"))
	caller.Request.Action = "identity.mfa.enable"
	enable := mfa.EnableRequest{TenantID: otpTenant, PrimaryProof: bindings.Authentication.Proof, Reauthentication: proof.Proof, Session: auth.NewBearerCredential(cookies[0].Value), Caller: caller, IdempotencyKey: key, Network: "127.0.0.1", FactorPolicy: mfa.FactorPolicy{Method: "otp", RecoveryCodes: 10}, CSRFToken: csrf}
	enable.OTP = &mfa.OTPEnrollmentSelection{Channel: delivery.ChannelEmail, IdentifierID: recipient}
	pending, err := enroller.Enable(ctx, enable)
	defer func() {
		for _, code := range pending.RecoveryMaterial.Codes {
			code.Destroy()
		}
	}()
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted || pending.Enrollment.ID == "" || pending.Enrollment.FactorMethod != "otp" || len(pending.RecoveryMaterial.Codes) != 10 {
		t.Fatal("public graph pending OTP enrollment", err)
	}
	var active int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2`, otpTenant, string(bindings.UserID)).Scan(&active); err != nil || active != 0 {
		t.Fatal("enrollment activated without confirmation", err)
	}
	if f.config.MFAOTPEnrollment.Listing {
		proveOTPFactorInventory(t, ctx, f, features, client, base, cookies, string(pending.Enrollment.ID), mfa.FactorPending, 0)
	}
	repeat, err := enroller.Enable(ctx, enable)
	if err != nil || repeat.Outcome != identity.CommitOutcomeCommitted || len(repeat.RecoveryMaterial.Codes) != 0 {
		t.Fatal("enrollment replay disclosed new recovery material", err)
	}
	caller.Request.Action = "identity.mfa.otp-send"
	key, _ = identity.NewIdempotencyKey([]byte("reference-otp-enrollment-send"))
	send := mfa.OtpSendRequest{TenantID: otpTenant, FactorID: mfa.FactorID(pending.Enrollment.ID), Channel: delivery.ChannelEmail, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key, Enrollment: &mfa.OTPEnrollmentContext{Session: enable.Session, CSRFToken: csrf}}
	sent, err := confirmation.OtpSend(ctx, send)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted || sent.DeliveryState != delivery.StateQueued {
		t.Fatal("public graph enrollment delivery", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("OTP enrollment delivery worker", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("captured OTP enrollment code unavailable")
	}
	caller.Request.Action = "identity.mfa.otp-verify"
	id, _ := identity.NewCommandID()
	secret, err := auth.NewOneTimeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	check := mfa.OtpVerifyRequest{TenantID: otpTenant, CommandID: id, FactorID: send.FactorID, Code: secret, Caller: caller, Origin: origin, Network: send.Network, Enrollment: &mfa.OTPEnrollmentContext{Session: enable.Session, CSRFToken: csrf}}
	out, err := confirmation.OtpVerify(ctx, check)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Enrollment.ID != pending.Enrollment.ID {
		t.Fatal("OTP confirmation failed or issued login authority", err)
	}
	if _, err := out.Session.Session.Bindings(); err == nil {
		t.Fatal("enrollment confirmation issued a login session")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2`, otpTenant, string(bindings.UserID)).Scan(&active); err != nil || active != 1 {
		t.Fatal("OTP factor did not activate", err)
	}
	if f.config.MFAOTPEnrollment.Listing {
		proveOTPFactorInventory(t, ctx, f, features, client, base, cookies, string(pending.Enrollment.ID), mfa.FactorActive, 10)
	}
	if f.mfaOTPEnrollmentOnly {
		if owner, err := features.PasswordOTP(); err == nil || owner != nil {
			t.Fatal("enrollment selected an unrequested login method")
		}
		if f.config.MFAOTPEnrollment.Listing {
			proveRegistrationSessionLogout(t, ctx, client, base, origin, cookies, csrfWire, bindings.SessionID, f, features)
			proveOTPInventoryLoggedOut(t, ctx, features, cookies)
		}
		return
	}
	// OTP's send family intentionally spans enrollment and login. Honor the
	// configured resend interval from its actual persisted send observation;
	// do not reset that family, change native clocks or lower its policy bounds.
	profile, _, err := f.config.MFAOTPEnrollment.Policy.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	var lastSent time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT sent_at[cardinality(sent_at)] FROM otp_store.send_families WHERE tenant_id=$1`, otpTenant).Scan(&lastSent); err != nil {
		t.Fatal("original OTP send observation", err)
	}
	timer := time.NewTimer(max(0, time.Until(lastSent.Add(profile.ResendInterval))))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("original resend window exceeded journey budget")
	}
	previous := mfa.OTPAuthenticatedStepUp{Session: enable.Session, CSRFToken: csrf, Purpose: "identity.mfa.factor-update"}
	proveReferencePasswordOTPHTTP(t, ctx, f, features, workers, client, base, origin, send.FactorID, messages, previous)
}

func proveReferencePasswordOTPHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, factor mfa.FactorID, messages <-chan string, previous mfa.OTPAuthenticatedStepUp, expectedLabel ...string) {
	t.Helper()
	invoke := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("OTP browser transport", err)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("OTP response bounds/cache/cleanup")
		}
		return response, data
	}
	response, data := invoke("/v1/session/preauth-issue", map[string]any{"method": "password"}, "", nil)
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		t.Fatal("OTP password flow unavailable", response.StatusCode)
	}
	cookies := response.Cookies()
	response, data = invoke("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, "", cookies)
	var primary passwordhttp.SigninResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &primary) != nil || !primary.ChallengeRequired || primary.SignedIn || primary.SessionID != "" || response.Header.Get("X-MFA-Token") == "" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("OTP primary was not challenge-only", response.StatusCode, primary.Error)
	}
	proof := response.Header.Get("X-MFA-Token")
	sending := map[string]any{"preAuthID": flow.FlowID, "continuationID": primary.ChallengeID, "factorID": factor, "channel": "email", "token": proof, "callbackURL": origin + "/reset"}
	sendKey := "reference-mfa-otp-login-send"
	if len(expectedLabel) > 0 {
		sendKey += "-after-rename"
	}
	response, data = invoke("/v1/mfa/otp-send", sending, sendKey, cookies)
	var sent mfahttp.OTPSendResponse
	decode := json.Unmarshal(data, &sent)
	if response.StatusCode != http.StatusAccepted || decode != nil || !sent.Accepted || sent.DeliveryState != "queued" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("OTP original login send", response.StatusCode, sent.Error)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("OTP login delivery worker", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("OTP login code unavailable")
	}
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	command, _ := identity.NewCommandID()
	completion := map[string]any{"commandID": command, "preAuthID": flow.FlowID, "continuationID": primary.ChallengeID, "token": proof, "code": wrong, "callbackURL": origin + "/reset", "trustDevice": false}
	// The independent login/active-proof journeys retain the wrong-login debit
	// partition. Rename proves two successful logins plus action-proof denial;
	// adding the same wrong-login probes twice would exhaust the unchanged
	// five-attempt velocity policy before its final successful login.
	activeProfile := f.config.MFAOTPEnrollment.ActiveStepUp
	if f.mfaOTPActiveCase == "" && len(expectedLabel) == 0 && (activeProfile == nil || activeProfile.FactorManagement == nil) {
		var sessionsBefore int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&sessionsBefore); err != nil {
			t.Fatal(err)
		}
		response, data = invoke("/v1/mfa/otp-verify", completion, "", cookies)
		var rejected mfahttp.OTPVerifyResponse
		decode = json.Unmarshal(data, &rejected)
		// The existing coordinator reports a counted first-attachment denial as
		// ConflictError (executePreparedFeature/preparationAttachmentDenied). Its
		// immutable not-committed outcome and exactly one debit distinguish this
		// denial from an unrelated conflict, retry or uncharged comparison failure.
		if (response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusConflict) || decode != nil || rejected.SignedIn || rejected.CommitOutcome != "not_committed" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("wrong secondary code did not return a closed denial", response.StatusCode, rejected.Error, rejected.CommitOutcome)
		}
		var remaining, uses, sessionsAfter int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,u.uses,(SELECT count(*) FROM session_store.sessions) FROM identity_mfa.continuations c JOIN public.capability_identity_one_use u ON u.tenant_id=c.tenant_id AND u.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, string(primary.ChallengeID)).Scan(&remaining, &uses, &sessionsAfter); err != nil || remaining != 2 || uses != 0 || sessionsAfter != sessionsBefore {
			t.Fatal("wrong secondary code lost shared budget or one-use isolation", err, remaining, uses)
		}
	}
	command, _ = identity.NewCommandID()
	completion["commandID"], completion["code"] = command, code
	response, data = invoke("/v1/mfa/otp-verify", completion, "", cookies)
	var completed mfahttp.OTPVerifyResponse
	decode = json.Unmarshal(data, &completed)
	if response.StatusCode != http.StatusOK || decode != nil || !completed.SignedIn || completed.CommitOutcome != "committed" || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("OTP completion did not deliver session", response.StatusCode, completed.Error, completed.CommitOutcome)
	}
	issued, csrf := response.Cookies(), response.Header.Get("X-CSRF-Token")
	token, err := session.ParseToken(issued[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("actual OTP-issued session not usable", err)
	}
	binding, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	response, _ = invoke("/v1/mfa/otp-verify", completion, "", cookies)
	if response.StatusCode == http.StatusOK || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("OTP replay redelivered session")
	}
	proveOTPLogoutCurrentAuthority(t, ctx, f, credential, csrf)
	if f.config.MFAOTPEnrollment.Listing {
		proveOTPFactorInventory(t, ctx, f, features, client, base, issued, string(factor), mfa.FactorActive, 10)
		proveOTPMixedFactorInventory(t, ctx, f, features, issued, binding.UserID, string(factor))
		proveOTPInventoryCorruption(t, ctx, f, features, issued, binding.UserID)
	}
	if f.config.MFAOTPEnrollment.ActiveStepUp != nil {
		label := proveReferenceMFAOTPActive(t, ctx, f, features, workers, issued[0].Value, csrf, origin, factor, binding.UserID, messages, previous)
		if f.mfaOTPRemoval {
			proveOTPInventoryLoggedOut(t, ctx, features, issued)
			passwordSession := proveOTPRemovalPasswordSignin(t, ctx, f, features, client, base, origin, issued, factor)
			proveReferenceEmailResetAfterRemoval(t, ctx, f, features, workers, client, base, origin, issued, messages, binding.UserID, "registered@example.invalid")
			if got, e := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: passwordSession}); e == nil && got.Authenticated {
				t.Fatal("post-removal reset retained its earlier password-only session")
			}
			return
		}
		if label != "" {
			proveOTPInventoryLoggedOut(t, ctx, features, issued)
			var lastSent time.Time
			if err := f.pool.Raw().QueryRow(ctx, `SELECT max(sent_at[cardinality(sent_at)]) FROM otp_store.send_families WHERE tenant_id=$1`, otpTenant).Scan(&lastSent); err != nil {
				t.Fatal("original login resend observation", err)
			}
			profile, _, _ := f.config.MFAOTPEnrollment.Policy.Bindings()
			timer := time.NewTimer(max(0, time.Until(lastSent.Add(profile.ResendInterval))))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal("post-rename login resend window exceeded journey budget")
			}
			// The second genuine login proves the updated factor/session epoch.
			// Skip only repeating the already completed mutation in this test helper.
			selection := *f.config.MFAOTPEnrollment
			selection.ActiveStepUp = nil
			f.config.MFAOTPEnrollment = &selection
			proveReferencePasswordOTPHTTP(t, ctx, f, features, workers, client, base, origin, factor, messages, previous, label)
			return
		}
	}
	if len(expectedLabel) > 0 {
		owner, err := features.MFAListing()
		if err != nil {
			t.Fatal(err)
		}
		inventory, err := owner.List(ctx, otpInventoryRequest(t, issued))
		if err != nil {
			t.Fatal("post-rename authenticated inventory", err)
		}
		found := false
		for _, item := range inventory.Factors {
			if item.ID == factor {
				found = item.Method == "otp" && item.Label == expectedLabel[0]
			}
		}
		if !found {
			t.Fatal("new OTP session did not read renamed factor")
		}
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, issued, csrf, binding.SessionID, f, features)
	if f.config.MFAOTPEnrollment.Listing {
		proveOTPInventoryLoggedOut(t, ctx, features, issued)
	}
}

// Prepare real caller custody before changing authority, then execute it while
// that custody is still fresh. A new read could reject earlier and would not
// prove the final native transaction fences the original OTP enrollment.
func proveOTPLogoutCurrentAuthority(t *testing.T, ctx context.Context, f liveStores, credential session.Credential, csrfWire string) {
	t.Helper()
	c := f.config.Session.Native
	validation := c.Validation
	validation.Clock = c.Execution.Clock
	profile := f.config.PasswordSignin.Native.Profile
	selection := sessionpg.SingleFactorSessionAdmissionConfig{Verified: &profile}
	reader, err := sessionpg.NewSelectedSessionService(f.pool, sessionpg.SelectedSessionServiceConfig{Repository: c.Execution.Repository, Validation: validation, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: selection, MFAPassword: &profile}})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := sessionpg.NewCookieRevokeOneExecutor(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: c.Execution, Sessions: reader, Admission: &selection, MFAPassword: &profile}, f.config.Session.CSRFKeys)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"enrollment epoch", `UPDATE identity_mfa.otp_factors SET enrollment_version=enrollment_version+1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity_mfa.otp_factors SET enrollment_version=enrollment_version-1 WHERE tenant_id=$1 AND user_id=$2`},
		{"recipient verification", `UPDATE identity.identifiers SET verification_version=verification_version+1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.identifiers SET verification_version=verification_version-1 WHERE tenant_id=$1 AND user_id=$2`},
		{"factor generation", `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity_mfa.factor_authorities SET version=version-1 WHERE tenant_id=$1 AND user_id=$2`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
			if err != nil || !current.Authenticated {
				t.Fatal("original native caller unavailable", err)
			}
			spec, _ := current.Session.Bindings()
			op := session.RevokeOneOperation()
			id, _ := identity.NewCommandID()
			binding := identity.CommandBinding{CommandID: id, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: spec.SessionID, PolicyID: c.Execution.PolicyID, PolicyVersion: c.Execution.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: "otp-current-authority"}
			command, err := session.NewRevokeOneCommand(binding, current.Session)
			if err != nil {
				t.Fatal(err)
			}
			request, err := reader.PrepareRevokeOneWithCSRF(current, command, csrf, f.config.Session.CSRFKeys[0])
			if err != nil {
				t.Fatal(err)
			}
			changed, err := f.pool.Raw().Exec(ctx, tc.change, otpTenant, string(spec.UserID))
			if err != nil || changed.RowsAffected() != 1 {
				t.Fatal("authority mutation fixture", err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(ctx, tc.restore, otpTenant, string(spec.UserID)); err != nil {
					t.Error("authority fixture restoration", err)
				}
			}()
			result, err := executor.ExecuteRevokeOneWithCSRF(ctx, request)
			if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("stale OTP authority revoked a session", err, result.Outcome)
			}
			binaryID, err := base64.RawURLEncoding.DecodeString(string(id))
			if err != nil {
				t.Fatal(err)
			}
			var revocations, events int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, binaryID).Scan(&revocations, &events); err != nil || revocations != 0 || events != 0 {
				t.Fatal("denied authority leaked protected effects", err)
			}
		})
	}
}
