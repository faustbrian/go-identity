//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresEmailOTPVerification(t *testing.T) {
	for _, mode := range []string{"otp-verification", "otp-verification-factor-missing", "otp-verification-factor-enrolled", "otp-verification-factor-generation", "otp-verification-rollback", "otp-verification-contention", "otp-verification-link-race", "otp-verification-unknown", "otp-verification-no-otp-signin", "otp-verification-https", "otp-verification-reference-https", "otp-verification-exhaustion", "otp-verification-recovery-withdrawal"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailChangeCase: mode, completionCommitFault: mode == "otp-verification-unknown"})
		})
	}
}

func configureReferenceEmailOTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeEmailVerification, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.NewRequestKeyConfig("reference-email-otp", [32]byte{221}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.Email.OTPVerification = &reference.EmailOTPVerificationConfiguration{Policy: policy, Domain: c.Email.Verification.Native.Domain, SessionKeys: map[uint32][]byte{11: bytes.Repeat([]byte{0x79}, 32)}, FreshnessLimit: 5 * time.Minute, CurrentAttemptKeyVersion: c.OTP.Signin.CurrentAttemptKeyVersion, RequestKeys: keys, IntentKey: [32]byte{222}, IdentifierKey: [32]byte{223}, TemplateID: "email-otp-verification", TemplateVersion: 1, LocaleChain: []string{"en"}}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "email-otp-verification", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128})
}

func proveReferenceEmailOTPVerification(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string, user identity.UserID, pending identity.IdentifierID, cookies []*http.Cookie, readSession func([]*http.Cookie) bool, mode string, old capability.Proof, callback string, config reference.StoreConfiguration, csrf string, selected ...emailOTPHTTPSSelection) {
	t.Helper()
	service, err := features.EmailOTPVerification()
	if err != nil {
		t.Fatal("selected native email OTP workflow", err)
	}
	var token string
	for _, cookie := range cookies {
		if cookie.Name == "__Host-session" {
			token = cookie.Value
		}
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal("actual submitted session token", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("actual fresh original session", err)
	}
	binding, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewSessionSendFlow(binding.SessionID, auth.NewBearerCredential(token))
	if err != nil {
		t.Fatal("actual original possession", err)
	}
	if mode == "otp-verification-https" || mode == "otp-verification-reference-https" {
		proveReferenceEmailOTPHTTPS(t, ctx, f, service, workers, messages, user, pending, cookies, readSession, config, csrf, binding.SessionID, selected...)
		return
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	key, _ := identity.NewIdempotencyKey([]byte("email-otp-original-request"))
	request := otp.EmailVerificationSendRequest{TenantID: otpTenant, UserID: user, AddressID: pending, AddressVersion: 1, Caller: caller, Flow: flow, Network: "127.0.0.1", Device: "native-email-verification", IdempotencyKey: key}
	originalSession, err := service.EmailVerificationSession(ctx, otpTenant, flow)
	if err != nil || !sameOriginalEmailOTPSession(originalSession, current.Session) {
		t.Fatal("original transport possession did not retain native session", err)
	}
	wrongFlow, _ := otp.NewSessionSendFlow(binding.SessionID, auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if record, err := service.EmailVerificationSession(ctx, otpTenant, wrongFlow); err == nil || record != (session.Session{}) {
		t.Fatal("transport source accepted wrong original token")
	}
	destination, err := service.EmailVerificationSendDestination(ctx, request)
	if err != nil || destination.Value() != "additional@example.invalid" {
		t.Fatal("actual pending send source", err)
	}
	foreignSource := request
	foreignSource.UserID = "foreign-user"
	foreignSource.Caller = request.Caller.Clone()
	foreignSource.Caller.Request.Subject.ID = "foreign-user"
	foreignSource.Caller.Request.Resource.ID = "foreign-user"
	if _, err := service.EmailVerificationSendDestination(ctx, foreignSource); err == nil {
		t.Fatal("transport source disclosed another user's pending destination")
	}
	sent, err := service.SendEmailVerification(ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual pending-address OTP issuance", err)
	}
	again, err := service.SendEmailVerification(ctx, request)
	if err != nil || again.CommandID != sent.CommandID || again.Outcome != sent.Outcome {
		t.Fatal("same request regenerated OTP issuance", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("native OTP delivery", err)
	}
	var code auth.OneTimeCode
	var wrong auth.OneTimeCode
	var wrongCodes []auth.OneTimeCode
	select {
	case body := <-messages:
		code, err = auth.NewOneTimeCode(body)
		if err != nil {
			t.Fatal("captured native code", err)
		}
		for _, candidate := range []string{"000000", "000001", "000002", "000003"} {
			if candidate != body {
				bad, _ := auth.NewOneTimeCode(candidate)
				wrongCodes = append(wrongCodes, bad)
			}
		}
		wrong = wrongCodes[0]
	case <-ctx.Done():
		t.Fatal("OTP delivery missing")
	}
	caller.Request.Action = "identity.otp.email-verify"
	completion := otp.EmailVerifyRequest{TenantID: otpTenant, UserID: user, Caller: caller, Flow: flow, SendCommandID: sent.CommandID, Code: code}
	source, err := service.EmailVerificationChallenge(ctx, completion)
	if err != nil || source.UserID != user || source.Lifetime <= 0 || source.Lifetime > 5*time.Minute {
		t.Fatal("authenticated original challenge budget source", err)
	}
	selectedTarget, err := source.Target.Bindings()
	if err != nil || selectedTarget.IdentifierID != pending || selectedTarget.IdentifierVersion != 1 || selectedTarget.VerificationVersion != 1 || selectedTarget.FactorVersion == 0 {
		t.Fatal("source retargeted native OTP scope", err)
	}
	if mode == "otp-verification-factor-missing" || mode == "otp-verification-factor-enrolled" || mode == "otp-verification-factor-generation" {
		// Controlled authoritative-state fault after real issuance. Never restore
		// it into a successful path: this case ends after proving no debit/effect.
		sql := `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`
		if mode == "otp-verification-factor-missing" {
			sql = `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`
		}
		if mode == "otp-verification-factor-enrolled" {
			sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`
		}
		if _, err := f.pool.Raw().Exec(ctx, sql, otpTenant, string(user)); err != nil {
			t.Fatal("owned authority fault", err)
		}
		out, err := service.EmailVerify(ctx, completion)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("changed/unknown/enrolled factors admitted email-only recovery")
		}
		assertEmailOTPUnchanged(t, ctx, f, user, pending, sent.CommandID, 0)
		return
	}
	if mode == "otp-verification-contention" || mode == "otp-verification-link-race" {
		var results [2]bool
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		for n := range 2 {
			go func() {
				defer wg.Done()
				<-start
				if n == 1 && mode == "otp-verification-link-race" {
					owner, e := features.EmailVerification()
					if e != nil {
						return
					}
					id, _ := identity.NewCommandID()
					u, _ := url.Parse(callback)
					c := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
					out, e := owner.VerificationConfirm(ctx, email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: old, Callback: *u, Caller: c, Network: "127.0.0.1"})
					results[n] = e == nil && out.Outcome == identity.CommitOutcomeCommitted
					return
				}
				out, e := service.EmailVerify(ctx, completion)
				results[n] = e == nil && out.Outcome == identity.CommitOutcomeCommitted
			}()
		}
		close(start)
		wg.Wait()
		if results[0] == results[1] {
			t.Fatal("competing verifications did not have exactly one successful consumer")
		}
		var version uint64
		var verified bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT version,verified FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), string(pending)).Scan(&version, &verified); err != nil || !verified || version != 2 {
			t.Fatal("competing verification changed the address more than once", err)
		}
		return
	}
	for name, change := range map[string]func(*otp.EmailVerifyRequest){
		"foreign-user": func(r *otp.EmailVerifyRequest) { r.UserID = "foreign-user" },
		"wrong-bearer": func(r *otp.EmailVerifyRequest) {
			r.Flow, _ = otp.NewSessionSendFlow(binding.SessionID, auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
		},
		"wrong-session": func(r *otp.EmailVerifyRequest) {
			r.Flow, _ = otp.NewSessionSendFlow("foreign-session", auth.NewBearerCredential(token))
		},
		"foreign-send": func(r *otp.EmailVerifyRequest) { r.SendCommandID = "AgICAgICAgICAgICAgICAg" },
		"wrong-action": func(r *otp.EmailVerifyRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Action = "identity.otp.signin"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := completion
			change(&r)
			out, err := service.EmailVerify(ctx, r)
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("foreign scope verified address")
			}
		})
	}
	var used, failed int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 0 || failed != 0 {
		t.Fatal("authority denial charged code", err)
	}
	bad := completion
	bad.Code = wrong
	denied, err := service.EmailVerify(ctx, bad)
	if err == nil || denied.Outcome != identity.CommitOutcomeNotCommitted || denied.Address != (identity.IdentifierProjection{}) {
		t.Fatal("wrong code verified address or lost outcome", err)
	}
	recoveryCaller := caller.Clone()
	recoveryCaller.Request.Action = "identity.otp.email-verify.recover"
	for range 2 {
		history, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: denied.Recovery})
		if err != nil || history.Outcome != identity.CommitOutcomeNotCommitted || history.Address != (identity.IdentifierProjection{}) {
			t.Fatal("wrong-code recovery changed outcome", err)
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 1 || failed != 1 {
		t.Fatal("wrong code or recovery charged incorrectly", err)
	}
	if mode == "otp-verification-recovery-withdrawal" {
		// Withdraw real primary authority after a classified terminal denial.
		// Its original NotCommitted status is not current disclosure permission.
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
			t.Fatal(err)
		}
		history, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: denied.Recovery})
		if err == nil || history.CommandID != "" || history.Address != (identity.IdentifierProjection{}) {
			t.Fatal("original denial bypassed current recovery authority")
		}
		assertEmailOTPUnchanged(t, ctx, f, user, pending, sent.CommandID, 1)
		return
	}
	if mode == "otp-verification-exhaustion" {
		for _, invalidCode := range wrongCodes[1:3] {
			r := completion
			r.Code = invalidCode
			out, err := service.EmailVerify(ctx, r)
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("distinct wrong submission escaped attempt policy", err)
			}
		}
		out, err := service.EmailVerify(ctx, completion)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("correct code bypassed exhausted attempt budget")
		}
		assertEmailOTPUnchanged(t, ctx, f, user, pending, sent.CommandID, 3)
		if err := f.pool.Raw().QueryRow(ctx, `SELECT failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&failed); err != nil || failed != 3 {
			t.Fatal("exhaustion omitted or doubled original comparisons", err)
		}
		if !readSession(cookies) {
			t.Fatal("exhausted challenge changed unrelated session authority")
		}
		return
	}
	if mode == "otp-verification-rollback" {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION identity.reject_email_otp_verification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned email OTP rollback'; END $$; CREATE TRIGGER reject_email_otp_verification BEFORE UPDATE ON identity.identifiers FOR EACH ROW WHEN (NOT OLD.verified AND NEW.verified) EXECUTE FUNCTION identity.reject_email_otp_verification()`); err != nil {
			t.Fatal(err)
		}
		out, err := service.EmailVerify(ctx, completion)
		if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("failed identifier write reported successful verification", err)
		}
		var count int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=1 AND verification_version=1 AND NOT verified`, otpTenant, string(user), string(pending)).Scan(&count); err != nil || count != 1 {
			t.Fatal("failed transaction changed pending address", err)
		}
		if !readSession(cookies) {
			t.Fatal("rolled-back identifier transition revoked original session")
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reject_email_otp_verification ON identity.identifiers; DROP FUNCTION identity.reject_email_otp_verification()`); err != nil {
			t.Fatal(err)
		}
		history, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: out.Recovery})
		if err != nil || history.Outcome != identity.CommitOutcomeNotCommitted || history.Address != (identity.IdentifierProjection{}) {
			t.Fatal("rolled-back original recovery became executable", err)
		}
		// Proven rollback terminally releases this code reservation. Do not
		// reinterpret release as permission to reuse or reissue the old code.
		return
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	verified, err := service.EmailVerify(ctx, otp.EmailVerifyRequest{TenantID: otpTenant, UserID: user, Caller: caller, Flow: flow, SendCommandID: sent.CommandID, Code: code})
	if f.completionFault != nil {
		f.completionFault.armed.Store(false)
		if err == nil || verified.Outcome != identity.CommitOutcomeUnknown || verified.Address != (identity.IdentifierProjection{}) || !f.completionFault.hit.Load() {
			t.Fatal("lost actual commit acknowledgement did not retain original unknown", err)
		}
		history, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: verified.Recovery})
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Address != (identity.IdentifierProjection{}) || history.CommandID != verified.CommandID {
			t.Fatal("original ambiguous verification did not recover metadata-only commit", err)
		}
		var version uint64
		var verified bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT version,verified FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), string(pending)).Scan(&version, &verified); err != nil || !verified || version != 2 {
			t.Fatal("unknown recovery did not preserve original single transition", err)
		}
		return
	}
	if err != nil || verified.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("atomic native email OTP verification", err)
	}
	projection, projectionErr := verified.Address.Bindings()
	if projectionErr != nil || !projection.Verified || projection.Primary || projection.IdentifierID != pending || projection.IdentifierVersion != 2 || projection.VerificationVersion != 2 {
		t.Fatal("actual verified-address projection", projectionErr)
	}
	var auditPath, auditBefore, auditAfter string
	commandBytes, _ := base64.RawURLEncoding.DecodeString(string(verified.CommandID))
	if err := f.pool.Raw().QueryRow(ctx, `SELECT convert_from(r.canonical_record,'UTF8')::jsonb #>> '{attributes,authentication.recovery_path}',convert_from(r.canonical_record,'UTF8')::jsonb #>> '{attributes,aggregate.before_version}',convert_from(r.canonical_record,'UTF8')::jsonb #>> '{attributes,aggregate.after_version}' FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1`, commandBytes).Scan(&auditPath, &auditBefore, &auditAfter); err != nil || auditPath != "email_verification_otp" || auditBefore != "1" || auditAfter != "2" {
		t.Fatal("protected audit lost canonical verification transition", err)
	}
	if readSession(cookies) {
		t.Fatal("old session escaped identifier-authority change")
	}
	again, err = service.SendEmailVerification(ctx, request)
	if err != nil || again.CommandID != sent.CommandID || again.Outcome != sent.Outcome {
		t.Fatal("terminal original Send replay reread mutable pending address", err)
	}
	afterDestination, err := service.EmailVerificationSendDestination(ctx, request)
	if err != nil || afterDestination != destination {
		t.Fatal("transport rate-source reread mutable verified address", err)
	}
	historicalSession, err := service.EmailVerificationSession(ctx, otpTenant, flow)
	if err != nil || !sameOriginalEmailOTPSession(historicalSession, originalSession) {
		t.Fatal("transport recovery lost original session or renewed it", err)
	}
	caller.Request.Action = "identity.otp.email-verify.recover"
	recovered, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: caller, Flow: flow, Recovery: verified.Recovery})
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Address != (identity.IdentifierProjection{}) {
		t.Fatal("original metadata-only OTP recovery", err)
	}
}

func sameOriginalEmailOTPSession(a, b session.Session) bool {
	x, e := a.Bindings()
	y, f := b.Bindings()
	if e != nil || f != nil {
		return false
	}
	ax, e := x.Authority.Bindings()
	ay, f := y.Authority.Bindings()
	if e != nil || f != nil || ax != ay {
		return false
	}
	px, e := x.Remember.Bindings()
	py, f := y.Remember.Bindings()
	if e != nil || f != nil || px != py {
		return false
	}
	cx, e := a.CSRFState().Bindings()
	cy, f := b.CSRFState().Bindings()
	if e != nil || f != nil || cx != cy {
		return false
	}
	x.Authority, x.Remember = y.Authority, y.Remember
	return x == y
}

func assertEmailOTPUnchanged(t *testing.T, ctx context.Context, f liveStores, user identity.UserID, pending identity.IdentifierID, send identity.CommandID, attempts int) {
	t.Helper()
	var used, count int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(send)).Scan(&used); err != nil || used != attempts {
		t.Fatal("authority denial charged code attempt", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=1 AND verification_version=1 AND NOT verified`, otpTenant, string(user), string(pending)).Scan(&count); err != nil || count != 1 {
		t.Fatal("authority denial changed pending address", err)
	}
}
