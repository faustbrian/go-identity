//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

const referencePhoneResetPassword = "synthetic-phone-reset-password"

type referencePhonePasswordResetPolicy struct{}

func (referencePhonePasswordResetPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && c.Request.Resource.Type == "identity.user" {
		switch c.Request.Action {
		case "identity.phone.password-reset-request", "identity.phone.password-reset-complete", "identity.risk.evaluate":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && c.Request.Action == "identity.phone.password-reset-request" && c.Request.Resource.Type == "identity.request-admission" && c.Request.Resource.ID == "identity.phone.password-reset-request" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referencePhoneSigninPolicy{}).Decide(ctx, c)
}

func TestReferencePostgresPhonePasswordResetHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, phonePasswordReset: true, mfaEnrollment: true}, true)
}

func TestReferencePostgresPhonePasswordResetCommitRecoveryHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, phonePasswordReset: true, mfaEnrollment: true, completionCommitFault: true}, true)
}

func TestReferencePostgresPhonePasswordResetRollbackHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneTOTP: true, phoneTOTPOnly: true, phonePasswordReset: true, phoneResetRollback: true, mfaEnrollment: true}, true)
}

// All domain owners, counters, grant issuance and delivery are real. Only the
// declared external carrier/HIBP/sender boundaries are controlled observations.
func configureReferencePhonePasswordReset(t *testing.T, c *reference.StoreConfiguration, origin string) *atomic.Int32 {
	t.Helper()
	if c.Phone == nil || c.DurableAdmission == nil || c.PasswordSignin == nil || c.PasswordSignup == nil {
		t.Fatal("phone reset requires preceding actual configured owners")
	}
	// Signup screening follows the already selected version-9 shared evaluator.
	// Retain that actual policy instance for enrollment and signin counters.
	c.PasswordSignup.Native.Screening.Policy = registrationRiskPolicy(t, 9, true)
	collect, calls := registrationScreening(t, c.PasswordSignup.Native.Screening.Policy)
	c.PasswordSignup.Native.Screening.Collect = collect
	var profiles []risk.Profile
	for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.session.get"} {
		admitted, err := c.PasswordSignup.Native.Screening.Policy.Admit(action)
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, admitted.Profile)
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 9, Profiles: profiles, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.phone.password-reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	screening := c.PasswordSignup.Native.Screening
	screening.Policy, screening.Now = policy, nil
	screening.Collect, _ = registrationScreening(t, policy, "identity.phone.password-reset-complete")
	carrierConfig := risk.CarrierEvaluatorConfig{Enabled: true, PolicyVersion: 9, Lifetime: 20 * time.Second, Clock: func() time.Time { return time.Now().UTC() }, Timeout: time.Second}
	for _, kind := range []risk.CarrierKind{risk.SIMSwap, risk.NumberRecycling, risk.Carrier} {
		carrierConfig.Sources = append(carrierConfig.Sources, risk.CarrierSource{Kind: kind, Version: "reference-external-v1", Timeout: time.Second, Read: func(_ context.Context, r risk.CarrierRequest) (risk.CarrierObservation, error) {
			at := time.Now().UTC()
			return risk.CarrierObservation{Binding: r.Binding, Phase: r.Phase, Kind: kind, State: risk.CarrierNegative, ProviderVersion: "reference-external-v1", ObservedAt: at, ExpiresAt: at.Add(20 * time.Second)}, nil
		}})
	}
	carrier, err := risk.NewCarrierEvaluator(carrierConfig)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.NewRequestKeyConfig("reference-phone-password-reset", [32]byte{225}, *c.PasswordSignin.Native.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	code, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePasswordReset, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	checks, err := otp.NewAttemptPolicy(code, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	issuer := c.PasswordSignup.Issuer
	issuer.Audience = "phone-reset"
	pre := *c.PasswordSignin.PreAuth
	callback := pre.CallbackURL
	c.PhonePasswordReset = &reference.PhonePasswordResetConfiguration{Policy: c.Phone.Policy,
		Request: passwordpg.PhonePasswordResetRequestConfig{Enabled: true, AcceptCarrierRisk: true, ConfigurationID: "reference-phone-password-reset-v1", RequestKeys: keys, IntentKey: [32]byte{226}, ActiveEnvelopeKeyID: c.PasswordSignup.Native.ActiveEnvelopeKeyID, NumberBindingKeyVersion: 1,
			Risk:    passwordpg.PhonePasswordResetRiskConfig{Store: riskpg.Config{Schema: c.DurableAdmission.Schema, PolicyVersion: 9, EnvelopeKeys: map[string][]byte{"phone-reset": bytes.Repeat([]byte{227}, 32)}, CurrentEnvelopeKey: "phone-reset"}, Issuer: risk.PhoneEvidenceIssuerConfig{Carrier: carrier, Clock: func() time.Time { return time.Now().UTC() }, Timeout: 5 * time.Second}, Coordinator: c.PasswordSignin.Native.Coordinator, PolicyID: "phone-password-reset-risk", RetentionPolicyVersion: 1},
			Profile: password.ResetProfileConfig{Issuer: origin, Audience: "phone-reset", MaximumLifetime: time.Minute, Callbacks: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {228}}}, Issuer: issuer, IssuanceCustody: c.PasswordSignup.Preparation,
			Delivery: passwordpg.SignupDeliveryConfig{Resolver: c.PasswordSignup.Native.Delivery.Resolver, Endpoint: callback, TemplateID: "phone-reset-link", TemplateVersion: 1, ProviderVersion: 2, Locales: []string{"en"}, ScopeKey: [32]byte{229}, Timeout: time.Second}},
		Completion: passwordpg.PhonePasswordResetCompletionConfig{ConfigurationID: "reference-phone-password-reset-complete-v1", Screening: screening, AttemptKeyVersion: c.OTP.Signin.CurrentAttemptKeyVersion},
		Issuance:   reference.PhoneIssuanceConfiguration{Policy: checks, TemplateID: "phone-reset-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}}, PreAuth: pre, ComparisonKey: [32]byte{230}, ComparisonKeyVersion: 1,
	}
	c.Delivery.Templates = append(c.Delivery.Templates,
		delivery.Template{ID: "phone-reset-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Phone reset code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128},
		delivery.Template{ID: "phone-reset-link", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Phone reset link: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	c.HTTPPhonePasswordReset = &reference.HTTPPhonePasswordResetConfiguration{ActorID: pre.ActorID, PolicyRevision: 9}
	return calls
}

func proveReferencePhoneResetMixedSchemaRejected(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies, retained *reference.PasswordResetConfiguration) {
	t.Helper()
	const otherSchema = "email_reset_sessions"
	alternate, otpConfig, emailConfig := c, *c.OTP, *retained
	selectedRequest := *emailConfig.Native.Request
	selectedRequest.RequestKeys.Policy = c.OTP.RequestKeys.Policy
	emailConfig.Native.Request = &selectedRequest
	emailConfig.Native.Coordinator = c.PasswordSignin.Native.Coordinator
	emailConfig.Native.Session.Schema = otherSchema
	emailConfig.Native.Screening.Collect, _ = registrationScreening(t, emailConfig.Native.Screening.Policy, "identity.password.reset-complete")
	store := c.PasswordSignin.Native.Session
	store.Schema = otherSchema
	otpConfig.Session = &otppg.SessionAdmissionConfig{Store: store, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: c.Phone.Issuance.SessionKeys, FreshnessLimit: time.Minute}
	alternate.OTP, alternate.PasswordReset = &otpConfig, &emailConfig
	closeGraph := func(graph reference.StoreSet) {
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := graph.Close(bounded); err != nil {
			t.Error(err)
		}
	}
	// Establish the existing profile is otherwise valid. Neither this control
	// nor the rejected selected graph installs migrations or supplies fake owners.
	alternate.PhonePasswordReset, alternate.HTTPPhonePasswordReset = nil, nil
	graph, err := reference.ComposeStores(alternate, deps)
	if err != nil {
		t.Fatal("existing independently selected email-reset schema is invalid", err)
	}
	closeGraph(graph)
	alternate.PhonePasswordReset, alternate.HTTPPhonePasswordReset = c.PhonePasswordReset, c.HTTPPhonePasswordReset
	graph, err = reference.ComposeStores(alternate, deps)
	if err == nil {
		closeGraph(graph)
		t.Fatal("phone reset silently replaced an existing email-reset migration schema")
	}
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field != "reference_phone_password_reset" {
		t.Fatal("mixed-schema profile denied at an unrelated boundary", err)
	}
	emailConfig.Native.Session.Schema = c.PasswordSignin.Native.Session.Schema
	graph, err = reference.ComposeStores(alternate, deps)
	if err != nil {
		t.Fatal("matching reset session schemas failed composition", err)
	}
	closeGraph(graph)
}

func proveReferencePhonePasswordReset(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, factor mfa.FactorID, secret []byte, oldCookies []*http.Cookie) {
	t.Helper()
	if f.phoneResetConsumer == nil {
		t.Fatal("phone reset consumer wiring absent")
	}
	workers, messages := f.phoneResetConsumer.workers, f.phoneResetConsumer.messages
	call := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(data))
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
			t.Fatal("phone reset HTTPS request", err)
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(wire) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("phone reset response bounds/cleanup")
		}
		return response, wire
	}
	start := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, wire := call("/v1/session/preauth-issue", map[string]string{"method": method, "identifier": "+12025550123"}, "", nil)
		var out sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &out) != nil || !out.Issued || len(r.Cookies()) != 2 {
			t.Fatal("selected original recovery browser unavailable", r.StatusCode)
		}
		return out, r.Cookies()
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(oldCookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	old, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !old.Authenticated {
		t.Fatal("actual pre-reset session unavailable", err)
	}
	binding, err := old.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flow, browser := start("phone-reset")
	command, _ := identity.NewCommandID()
	issuance, _ := identity.NewCommandID()
	request := map[string]any{"commandID": command, "riskIssuanceCommandID": issuance, "flowID": flow.FlowID, "number": "+12025550123"}
	r, wire := call("/v1/phone/password-reset-request", request, "original-phone-reset", browser)
	var accepted phonehttp.PasswordResetResponse
	if r.StatusCode != 202 || json.Unmarshal(wire, &accepted) != nil || !accepted.Accepted || accepted.CommandID != command || accepted.CommitOutcome != "" || len(r.Cookies()) != 0 {
		t.Fatal("public phone reset did not preserve enumeration-safe acknowledgment", r.StatusCode, accepted.Error)
	}
	for range 2 {
		out, err := workers.ProcessDeliveryOne(ctx, 1)
		if err != nil || !out.Claimed {
			t.Fatal("genuine phone reset delivery missing", err)
		}
	}
	var code, link string
	for range 2 {
		select {
		case message := <-messages:
			switch {
			case strings.HasPrefix(message, "Phone reset code: "):
				code = strings.TrimPrefix(message, "Phone reset code: ")
			case strings.HasPrefix(message, "Phone reset link: "):
				link = strings.TrimPrefix(message, "Phone reset link: ")
			default:
				t.Fatal("phone reset emitted an unexpected message profile")
			}
		case <-ctx.Done():
			t.Fatal("phone reset sender observation absent")
		}
	}
	uri, err := url.Parse(link)
	if err != nil || len(code) != 6 || uri.Scheme != "https" || uri.Query().Get("token") == "" {
		t.Fatal("captured SMS/link invalid")
	}
	completed, _ := identity.NewCommandID()
	completionRisk, _ := identity.NewCommandID()
	body := map[string]any{"commandID": completed, "riskIssuanceCommandID": completionRisk, "flowID": flow.FlowID, "token": uri.Query().Get("token"), "phoneCode": code, "totpCode": passwordMFAFixtureCode(secret, time.Now().UTC().Add(30*time.Second)), "newPassword": referencePhoneResetPassword}
	readProtected := func() (string, string, int, int) {
		t.Helper()
		var version, step string
		var active, resets int
		err := f.pool.Raw().QueryRow(ctx, `SELECT c.version::text,f.last_step::text,
(SELECT count(*) FROM session_store.sessions WHERE tenant_id=c.tenant_id AND user_id=c.user_id AND state='active'),
(SELECT count(*) FROM session_store.password_resets WHERE tenant_id=c.tenant_id AND user_id=c.user_id)
FROM identity.credential_references c JOIN identity_mfa.totp_factors f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.kind=1 AND f.factor_id=$3`, otpTenant, string(binding.UserID), string(factor)).Scan(&version, &step, &active, &resets)
		if err != nil {
			t.Fatal("protected reset state unavailable", err)
		}
		return version, step, active, resets
	}
	beforeVersion, beforeStep, beforeSessions, beforeResets := readProtected()
	if f.phoneResetRollback {
		// Fail the actual required success audit after provisional protected writes.
		// The sequence survives rollback and proves this reached the intended owner,
		// rather than passing because an earlier admission/risk step denied.
		if _, err := f.pool.Raw().Exec(ctx, `CREATE SEQUENCE audit.reference_phone_reset_reached;
ALTER TABLE audit.records ADD CONSTRAINT reference_phone_reset_stop CHECK(action<>'identity.phone.password-reset-complete' OR outcome<>1 OR nextval('audit.reference_phone_reset_reached')<0) NOT VALID`); err != nil {
			t.Fatal(err)
		}
		cleanupRollback := func() {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, err := f.pool.Raw().Exec(bounded, `ALTER TABLE audit.records DROP CONSTRAINT IF EXISTS reference_phone_reset_stop; DROP SEQUENCE IF EXISTS audit.reference_phone_reset_reached`); err != nil {
				t.Error("reset rollback fixture cleanup", err)
			}
		}
		t.Cleanup(cleanupRollback)
		r, wire = call("/v1/phone/password-reset-complete", body, "", browser)
		var failed phonehttp.PasswordResetResponse
		var reached bool
		if r.StatusCode == 200 || json.Unmarshal(wire, &failed) != nil || failed.Completed || failed.SessionsRevoked || failed.CredentialVersion != 0 || len(r.Cookies()) != 0 {
			t.Fatal("rolled-back HTTP reset claimed success")
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT is_called FROM audit.reference_phone_reset_reached`).Scan(&reached); err != nil || !reached {
			t.Fatal("rollback missed actual success-audit boundary", err)
		}
		v, step, active, resets := readProtected()
		if v != beforeVersion || step != beforeStep || active != beforeSessions || resets != beforeResets {
			t.Fatal("required-audit failure leaked protected reset effects")
		}
		cleanupRollback()
		var challengeState string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT state FROM otp_store.challenges WHERE tenant_id=$1 AND issue_command_purpose='identity.phone.password-reset-request'`, otpTenant).Scan(&challengeState); err != nil || challengeState != "released" {
			t.Fatal("proven noncommit did not close the original SMS reservation", err)
		}
		after, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !after.Authenticated {
			t.Fatal("rolled-back reset invalidated original authentication", err)
		}
		owner, err := features.PhonePasswordReset()
		if err != nil {
			t.Fatal(err)
		}
		var credentialID string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND kind=1`, otpTenant, string(binding.UserID)).Scan(&credentialID); err != nil {
			t.Fatal(err)
		}
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.phone.password-reset-complete", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}}}
		history, err := owner.RecoverPasswordResetComplete(ctx, identity.RecoveryQuery{CommandID: completed, TenantID: otpTenant, UserID: binding.UserID, RecordID: credentialID, ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.phone.password-reset-complete"}, caller)
		if history.Outcome != identity.CommitOutcomeNotCommitted || history.CredentialVersion != 0 || history.SessionsRevoked {
			t.Fatal("rollback recovery invented committed reset effects", err)
		}
		// A new login still uses the original password and genuine unspent TOTP.
		// Recovery does not reopen the terminal released SMS challenge.
		proveReferencePhoneTOTP(t, ctx, f, features, origin, factor, secret)
		*f.phoneResetCompleted = true
		return
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	r, wire = call("/v1/phone/password-reset-complete", body, "", browser)
	if f.completionFault != nil {
		f.completionFault.armed.Store(false)
		var uncertain phonehttp.PasswordResetResponse
		decoded := json.Unmarshal(wire, &uncertain)
		if !f.completionFault.hit.Load() || r.StatusCode != 503 || decoded != nil || uncertain.CommitOutcome != "unknown" || uncertain.Completed || uncertain.SessionsRevoked || uncertain.CredentialVersion != 0 || len(r.Cookies()) != 0 {
			t.Fatal("lost reset COMMIT acknowledgment was not conserved", r.StatusCode, uncertain.Error, uncertain.CommitOutcome, f.completionFault.hit.Load())
		}
		v, step, active, resets := readProtected()
		if v != "2" || step == beforeStep || active != 0 || resets != beforeResets+1 {
			t.Fatal("lost reset acknowledgment lost atomic durable effects")
		}
		// Resolve only the original request. No replacement command, browser,
		// evidence refresh or provider action may stand in for the lost result.
		r, wire = call("/v1/phone/password-reset-complete", body, "", browser)
	}
	var changed phonehttp.PasswordResetResponse
	decoded := json.Unmarshal(wire, &changed)
	if r.StatusCode != 200 || decoded != nil || !changed.Completed || !changed.SessionsRevoked || changed.CredentialVersion != 2 || changed.CommandID != completed || changed.CommitOutcome != "committed" || len(r.Cookies()) != 0 {
		t.Fatal("actual phone reset HTTPS conjunction did not commit", r.StatusCode, changed.Error, changed.CommitOutcome)
	}
	if bytes.Contains(wire, []byte(code)) || bytes.Contains(wire, []byte(referencePhoneResetPassword)) || bytes.Contains(wire, []byte(uri.Query().Get("token"))) {
		t.Fatal("reset response disclosed submitted custody")
	}
	r, wire = call("/v1/phone/password-reset-complete", body, "", browser)
	var replay phonehttp.PasswordResetResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &replay) != nil || replay != changed || len(r.Cookies()) != 0 {
		t.Fatal("HTTP reset retry lost original result", r.StatusCode, replay.Error)
	}
	after, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || after.Authenticated {
		t.Fatal("reset retained genuine source authentication", err)
	}
	owner, err := features.PhonePasswordReset()
	if err != nil {
		t.Fatal(err)
	}
	var credentialID string
	if err = f.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND kind=1`, otpTenant, string(binding.UserID)).Scan(&credentialID); err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.phone.password-reset-complete", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}}}
	history, err := owner.RecoverPasswordResetComplete(ctx, identity.RecoveryQuery{CommandID: completed, TenantID: otpTenant, UserID: binding.UserID, RecordID: credentialID, ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.phone.password-reset-complete"}, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.CredentialVersion != 2 || !history.SessionsRevoked {
		t.Fatal("native original reset history unavailable", err)
	}
	// An actual new phone-password attempt rejects the old password. Its
	// browser is independent of reset; no consumed flow is restored or retagged.
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
	prepared, err := preauth.Prepare(ctx, session.PreAuthPrepareInput{TenantID: otpTenant, CommandID: id, CorrelationID: string(id), IdentifierBinding: bound, Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := preauth.Issue(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	loginFlow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	primary, err := features.PhoneSignin()
	if err != nil {
		t.Fatal(err)
	}
	oldPassword, _ := primitive.NewSecret([]byte("synthetic-registration-password"))
	defer oldPassword.Destroy()
	caller.Request.Action = "identity.phone.password-signin"
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.phone.password-signin"}
	denied, err := primary.Signin(ctx, password.SigninRequest{TenantID: otpTenant, PreAuthID: loginFlow.Binding.ID, Cookie: auth.NewBearerCredential(cookie), Identifier: "+12025550123", Password: oldPassword, Remember: remember, Origin: origin, CallbackURL: loginFlow.Binding.Intent.CallbackURL, Network: "127.0.0.1", Device: "phone-reset-old-password", Caller: caller})
	if err != nil || denied.State != auth.SignInStateRejected || denied.SessionID != "" || denied.Issuance.Token != (session.Token{}) {
		t.Fatal("old password did not produce a real authentication rejection", err)
	}
	// A real reset consumed the only next-step code available after enrollment.
	// Wait for the authenticator's next admissible step; do not advance stored
	// replay state, widen skew or inject factor authority to make signin pass.
	var last string
	if err = f.pool.Raw().QueryRow(ctx, `SELECT last_step FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(binding.UserID), string(factor)).Scan(&last); err != nil {
		t.Fatal(err)
	}
	lastStep, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	wait := time.Until(time.Unix(lastStep*30, 0).Add(10 * time.Millisecond))
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("next independent authenticator step unavailable")
		}
	}
	// The reset fault belongs only to the completed reset. The following real
	// login is the ordinary committed consumer, not another transport fault.
	f.completionFault = nil
	proveReferencePhoneTOTP(t, ctx, f, features, origin, factor, secret)
	*f.phoneResetCompleted = true
}

type phoneResetConsumer struct {
	workers  reference.WorkerSet
	messages <-chan string
}
