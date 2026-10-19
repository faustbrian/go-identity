//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestReferencePostgresPhoneRemovalNative(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "native"}, true)
}

func TestReferencePostgresPhoneRemovalBearer(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "bearer"}, true)
}

func TestReferencePostgresPhoneRemovalHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "http"}, true)
}

func TestReferencePostgresPhoneRemovalIndependentRateMigrations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "independent-http"}, true)
}

func TestReferencePostgresPhoneRemovalPopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: "upgrade"}, true)
}

func TestReferencePostgresPhoneRemovalCommitCustody(t *testing.T) {
	for _, mode := range []string{"before-commit", "lost-commit", "contention"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneOTP: "browser", phoneRemoval: mode, completionCommitFault: mode != "contention"}, true)
		})
	}
}

func configureReferencePhoneRemoval(t *testing.T, c *reference.StoreConfiguration, mode string) *atomic.Int32 {
	t.Helper()
	keys, err := kernel.NewRequestKeyConfig("reference-phone-removal", [32]byte{235}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.remove", Audience: "reference-phone-removal"})
	cascade := kernel.IdentifierRemovalCascadeConfig{PolicyVersion: 101, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]kernel.StatusConsumerContract{}}
	for _, id := range identity.IdentifierRemovalConsumers() {
		cascade.ConsumerContracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: sha256.Sum256([]byte("synthetic-phone-removal-contract-v1:" + id))}
	}
	c.PhoneRemoval = &reference.PhoneRemovalConfiguration{Policy: c.Phone.Policy, Primary: passwordpg.ActionPrimaryConfig{Action: "identity.phone.remove", Audience: "reference-phone-removal", MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie}, Native: passwordpg.PhoneRemovalConfig{PolicyID: "reference-phone-removal", ConfigurationID: "reference-phone-removal-v1", MaximumDuration: c.OTP.Timeout, Domain: kernel.PhoneRemovalDomainConfig{Directory: c.Phone.Native.Domain, Cascade: cascade}, RequestKeys: keys, IntentKey: [32]byte{236}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-phone-removal-risk"}, Counters: c.PasswordSignup.Counters, ActiveEnvelopeKeyID: c.Delivery.Enqueue.Custody.ActiveEnvelopeKeyID, Notice: passwordpg.PhoneRemovalNoticeConfig{TemplateID: "phone-removed", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, TTL: time.Hour}}}
	c.PhoneRemoval.Native.Counters.EnforceLockouts = true
	if mode == "bearer" {
		c.PhoneRemoval.Primary.Transport = session.CredentialBearer
	}
	// The protected evaluator and transactional counter owner must share the
	// actual frozen policy, not two independently equal version-9 policies.
	c.DurableAdmission.Policy = c.PhoneRemoval.Native.Counters.CommandCounters.Policy
	c.PasswordSignup.Native.Screening.Policy = registrationRiskPolicy(t, 9, true)
	collect, calls := registrationScreening(t, c.PasswordSignup.Native.Screening.Policy)
	c.PasswordSignup.Native.Screening.Collect = collect
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "phone-removed", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Your phone number was removed.", ContentType: "text/plain", MaxRenderedBytes: 128})
	if mode == "http" || mode == "independent-http" {
		c.HTTPPhoneRemoval = &reference.HTTPPhoneRemovalConfiguration{Origin: string(c.HTTPPhoneVerification.Origin), PolicyRevision: 9}
	}
	return calls
}

func proveReferencePhoneRemoval(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string, client *http.Client, base, origin string, c reference.StoreConfiguration, user identity.UserID, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool, mode string, rebuild func() *reference.PhoneRemovalService) {
	t.Helper()
	owner, err := features.PhoneRemoval()
	if err != nil {
		t.Fatal("selected native removal unavailable", err)
	}
	// Prove both distinct phone login owners once, rather than replaying their
	// entire denial suites inside this lifecycle test and exhausting its budget.
	// Keep one genuinely delivered, unconsumed OTP for the post-removal fence.
	call := func(path string, body any, browser []*http.Cookie, key string, custody ...string) (*http.Response, []byte) {
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
		if len(custody) > 0 {
			r.Header.Set("X-CSRF-Token", custody[0])
		}
		if len(custody) > 1 {
			if custody[1] == "" {
				r.Header.Del("Origin")
			} else {
				r.Header.Set("Origin", custody[1])
			}
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range browser {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("phone removal consumer transport", err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(payload) > 16384 {
			t.Fatal("phone removal response bounds/cleanup")
		}
		return response, payload
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, payload := call("/v1/session/preauth-issue", map[string]any{"method": method, "identifier": "+12025550123"}, nil, "")
		var flow sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(payload, &flow) != nil || !flow.Issued {
			t.Fatal("phone removal original initiation", r.StatusCode)
		}
		return flow, r.Cookies()
	}
	phonePassword := func() (*http.Response, passwordhttp.SigninResponse) {
		t.Helper()
		flow, browser := issue("phone-password")
		r, payload := call("/v1/phone/password-signin", map[string]any{"flowID": flow.FlowID, "phoneNumber": "+12025550123", "password": "synthetic-registration-password", "callbackURL": c.PasswordSignin.PreAuth.CallbackURL}, browser, "")
		var result passwordhttp.SigninResponse
		if json.Unmarshal(payload, &result) != nil {
			t.Fatal("phone password response")
		}
		return r, result
	}
	var beforePassword, beforeOTP *http.Response
	sendOrdinal := 0
	sendOTP := func(key string) (sessionhttp.PreAuthResponse, []*http.Cookie, otphttp.SendResponse, string) {
		t.Helper()
		sendOrdinal++
		flow, browser := issue("phone-otp")
		r, payload := call("/v1/phone/send-signin", map[string]any{"flowID": flow.FlowID, "number": "+12025550123"}, browser, key)
		var sent otphttp.SendResponse
		if r.StatusCode != 202 || json.Unmarshal(payload, &sent) != nil || !sent.Accepted {
			t.Fatal("phone removal precursor SMS", sendOrdinal, r.StatusCode, sent.Error, sent.CommitOutcome)
		}
		if result, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || !result.Claimed {
			t.Fatal("phone precursor SMS delivery", err)
		}
		var code string
		select {
		case code = <-messages:
		case <-ctx.Done():
			t.Fatal("phone precursor SMS missing")
		}
		if len(code) != 6 {
			t.Fatal("phone precursor code shape")
		}
		return flow, browser, sent, code
	}
	var flow sessionhttp.PreAuthResponse
	var browser []*http.Cookie
	var sent otphttp.SendResponse
	var code string
	if !strings.HasPrefix(mode, "fence-") {
		var passwordResult passwordhttp.SigninResponse
		beforePassword, passwordResult = phonePassword()
		if beforePassword.StatusCode != 200 || !passwordResult.SignedIn || !readSession(beforePassword.Cookies()) {
			t.Fatal("phone password was not usable before removal", beforePassword.StatusCode)
		}
		flow, browser, sent, code = sendOTP("phone-removal-before-signin")
		var payload []byte
		beforeOTP, payload = call("/v1/phone/signin", map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": code}, browser, "")
		var otpResult otphttp.SigninResponse
		if beforeOTP.StatusCode != 200 || json.Unmarshal(payload, &otpResult) != nil || !otpResult.SignedIn || !readSession(beforeOTP.Cookies()) {
			t.Fatal("phone OTP was not usable before removal", beforeOTP.StatusCode)
		}
		// The real send-family owner deliberately ignores flow identity; a new
		// browser cannot refill the minimum 30-second destination cooldown. Wait
		// for that policy rather than editing stored history or weakening limits.
		cooldown := time.NewTimer(31 * time.Second)
		defer cooldown.Stop()
		select {
		case <-cooldown.C:
		case <-ctx.Done():
			t.Fatal("phone resend cooldown cancelled")
		}
		flow, browser, sent, code = sendOTP("phone-removal-pending-signin")
	}
	cookies, csrfWire := fresh()
	if !readSession(cookies) {
		t.Fatal("removal lacks genuine current session")
	}
	proofOwner, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "phone-removal-native", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	bearer := auth.NewBearerCredential(cookies[0].Value)
	verified, err := proofOwner.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: bearer, Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.phone.remove", Audience: "reference-phone-removal"}, Caller: caller, Network: "127.0.0.1", Device: "phone-removal-consumer"}, CSRFToken: csrf})
	if err != nil {
		t.Fatal("genuine removal proof", err)
	}
	var id string
	var version, verification uint64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version,verification_version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='phone' AND verified`, otpTenant, string(user)).Scan(&id, &version, &verification); err != nil {
		t.Fatal("genuine verified phone missing", err)
	}
	number, err := c.Phone.Policy.Canonicalize(ctx, "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("phone-removal-native"))
	caller.Request.Action = "identity.phone.remove"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	if c.PhoneRemoval.Primary.Transport == session.CredentialBearer {
		csrf = session.CSRFToken{}
	}
	r, err := phone.NewRemoveRequest(phone.RemoveRequestSpec{TenantID: otpTenant, UserID: user, Number: number, IdentifierID: identity.IdentifierID(id), ExpectedIdentifierVersion: version, ExpectedVerificationVersion: verification, Reason: "user-requested", Session: bearer, Proof: verified.Proof, CSRFToken: csrf, IdempotencyKey: key, Caller: caller, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() [10]uint64 {
		t.Helper()
		var s [10]uint64
		err := f.pool.Raw().QueryRow(ctx, `SELECT u.version,u.identifier_version,
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND identifier_id=$3),
(SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND identifier_id=$3),
(SELECT count(*) FROM identity.status_cascades WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND operation='identity.phone.remove'),
(SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND proof_id=$4 AND consumed_command_id IS NOT NULL),
COALESCE((SELECT used_attempts FROM otp_store.challenges WHERE tenant_id=u.tenant_id AND challenge_id=$5),0),
COALESCE((SELECT failed_attempts FROM otp_store.challenges WHERE tenant_id=u.tenant_id AND challenge_id=$5),0),
(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=u.tenant_id AND purpose='phone-removed')
FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user), id, string(verified.Proof.Proof.ID), string(sent.CommandID)).Scan(&s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &s[7], &s[8], &s[9])
		if err != nil {
			t.Fatal("phone removal effect observation", err)
		}
		return s
	}
	before := snapshot()
	if strings.HasPrefix(mode, "fence-") {
		provePhoneRemovalFinalFence(t, ctx, f, owner, r, snapshot, before, cookies, readSession, c.PhoneRemoval.Native.Counters.Schema, strings.TrimPrefix(mode, "fence-"))
	}
	for _, mode := range []string{"csrf", "forged-proof", "stale-version"} {
		if mode == "csrf" && c.PhoneRemoval.Primary.Transport == session.CredentialBearer {
			continue
		}
		bad, _ := r.Bindings()
		bad.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("phone-remove-denied-" + mode))
		switch mode {
		case "csrf":
			bad.CSRFToken = session.CSRFToken{}
		case "forged-proof":
			bad.Proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAAZQ"
		case "stale-version":
			bad.ExpectedIdentifierVersion--
		}
		request, err := phone.NewRemoveRequest(bad)
		if err != nil {
			t.Fatal("denial fixture structural input", mode, err)
		}
		denied, err := owner.Remove(ctx, request)
		if err == nil || denied.Outcome == identity.CommitOutcomeCommitted || snapshot() != before {
			t.Fatal("phone removal admitted invalid original custody", mode)
		}
	}
	queryFor := func(out identity.CommandResult) identity.RecoveryQuery {
		return identity.RecoveryQuery{CommandID: out.Binding.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.phone.remove", RecordID: id}
	}
	var out identity.CommandResult
	if c.HTTPPhoneRemoval == nil {
		if f.completionFault != nil {
			f.completionFault.armed.Store(true)
		}
		if mode == "contention" {
			type response struct {
				out     identity.CommandResult
				err     error
				request phone.RemoveRequest
			}
			responses := make(chan response, 2)
			start := make(chan struct{})
			var concurrent sync.WaitGroup
			for index := range 2 {
				request := r
				if index == 1 {
					spec, _ := r.Bindings()
					spec.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("phone-removal-competing-key"))
					request, err = phone.NewRemoveRequest(spec)
					if err != nil {
						t.Fatal(err)
					}
				}
				concurrent.Go(func() {
					<-start
					out, err := owner.Remove(ctx, request)
					responses <- response{out, err, request}
				})
			}
			close(start)
			concurrent.Wait()
			close(responses)
			winners := 0
			for result := range responses {
				if result.err == nil && result.out.Outcome == identity.CommitOutcomeCommitted {
					winners++
					out, r = result.out, result.request
				} else if result.out.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("competing phone removal produced a committed error")
				}
			}
			if winners != 1 {
				t.Fatal("phone removal contention did not have exactly one winner", winners)
			}
			err = nil
		} else {
			out, err = owner.Remove(ctx, r)
		}
		if f.completionFault != nil {
			if err == nil || !f.completionFault.hit.Load() || out.Outcome != identity.CommitOutcomeUnknown || out.Cascade != nil || out.Binding.CommandID == "" {
				t.Fatal("phone removal lost COMMIT did not retain credential-free unknown custody", out.Outcome, err)
			}
			f.completionFault.armed.Store(false)
			if mode == "before-commit" && snapshot() != before {
				t.Fatal("uncommitted phone removal leaked atomic effects")
			}
			original := out
			var unavailable identity.UnavailableError
			for {
				out, err = owner.RecoverRemoval(ctx, queryFor(original), caller)
				// The kernel retains dependency-failure classification beside a
				// proven noncommit; that error is not uncertainty or replay failure.
				knownFailure := out.Outcome == identity.CommitOutcomeNotCommitted && errors.As(err, &unavailable)
				if err != nil && !knownFailure || out.Binding != original.Binding {
					t.Fatal("original phone removal reconciliation failed", err)
				}
				if out.Outcome != identity.CommitOutcomeInProgress {
					break
				}
				if out.RetryAfter <= 0 || out.RetryAfter > c.OTP.Coordinator.LeaseDuration {
					t.Fatal("unknown phone removal lost bounded original lease")
				}
				wait := time.NewTimer(out.RetryAfter)
				select {
				case <-wait.C:
				case <-ctx.Done():
					wait.Stop()
					t.Fatal("phone removal reconciliation cancelled")
				}
			}
			if mode == "before-commit" {
				if out.Outcome != identity.CommitOutcomeNotCommitted || snapshot() != before || !readSession(cookies) {
					t.Fatal("rolled-back phone removal did not reconcile without protected effects", out.Outcome)
				}
				if replay, err := owner.Remove(ctx, r); err != nil && !errors.As(err, &unavailable) || replay.Outcome != identity.CommitOutcomeNotCommitted || replay.Binding != original.Binding || snapshot() != before {
					t.Fatal("original rolled-back phone request was executed again", err)
				}
				spec, _ := r.Bindings()
				spec.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("phone-removal-after-rollback"))
				r, err = phone.NewRemoveRequest(spec)
				if err != nil {
					t.Fatal(err)
				}
				out, err = owner.Remove(ctx, r)
			} else if out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("server-committed phone removal did not recover original success", out.Outcome)
			}
		}
	} else {
		body := map[string]string{"number": "+12025550123", "identifierID": id, "expectedIdentifierVersion": strconv.FormatUint(version, 10), "expectedVerificationVersion": strconv.FormatUint(verification, 10), "proofID": string(verified.Proof.Proof.ID), "reason": "user-requested"}
		for _, denial := range [][2]string{{"", origin}, {csrfWire, ""}, {csrfWire, "https://foreign.invalid"}} {
			response, _ := call("/v1/phone/remove", body, cookies, "phone-removal-native", denial[0], denial[1])
			if response.StatusCode != 403 || len(response.Cookies()) != 0 || snapshot() != before {
				t.Fatal("phone removal ignored original Origin/CSRF", response.StatusCode)
			}
		}
		for _, field := range []string{"code", "tenantID", "userID", "commandID", "idempotencyKey", "skipNotification"} {
			bad := make(map[string]string, len(body)+1)
			for key, value := range body {
				bad[key] = value
			}
			bad[field] = "override"
			response, _ := call("/v1/phone/remove", bad, cookies, "phone-removal-native", csrfWire)
			if response.StatusCode != 400 || len(response.Cookies()) != 0 || snapshot() != before {
				t.Fatal("phone removal HTTP accepted out-of-scope input", field, response.StatusCode)
			}
		}
		for _, path := range []string{"/v1/phone/remove", "/v1/phone/remove?commandID=override"} {
			response, _ := call(path, body, cookies, "", csrfWire)
			if response.StatusCode != 400 || snapshot() != before {
				t.Fatal("phone removal accepted absent key/query authority", response.StatusCode)
			}
		}
		response, payload := call("/v1/phone/remove", body, cookies, "phone-removal-native", csrfWire)
		var removed phonehttp.RemovalResponse
		if response.StatusCode != 200 || json.Unmarshal(payload, &removed) != nil || !removed.Removed || removed.CommitOutcome != "committed" || removed.CascadeStatus != "pending" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("phone removal HTTP did not commit selected native owner", response.StatusCode, removed.Error, removed.CommitOutcome)
		}
		query := identity.RecoveryQuery{CommandID: removed.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.phone.remove", RecordID: id}
		out, err = owner.RecoverRemoval(ctx, query, caller)
		if err != nil || out.Cascade == nil || out.Cascade.CascadeID != removed.CascadeID || out.Cascade.Generation != removed.CascadeGeneration {
			t.Fatal("phone removal HTTP/native history detached", err)
		}
		replay, again := call("/v1/phone/remove", body, cookies, "phone-removal-native", csrfWire)
		if replay.StatusCode != 200 || !bytes.Equal(payload, again) {
			t.Fatal("phone removal HTTP original retry changed outcome", replay.StatusCode)
		}
	}
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		var state, terminal string
		var generated, planned bool
		observation := f.pool.Raw().QueryRow(ctx, `SELECT state,COALESCE(terminal_class,''),preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL FROM identity.commands WHERE command_id=decode(translate($1,'-_','+/')||'==','base64')`, string(out.Binding.CommandID)).Scan(&state, &terminal, &generated, &planned)
		t.Log("removal journal", state, terminal, generated, planned, "observation", observation)
		t.Fatal("native phone removal did not commit", out.Outcome, err)
	}
	expected := before
	expected[0]++
	expected[1]++
	expected[2] = 0
	expected[3]++
	expected[4]++
	expected[5] = 1
	expected[9]++
	if snapshot() != expected || out.Cascade == nil || out.Cascade.Status != identity.RevocationPending || out.Cascade.IdentifierID != identity.IdentifierID(id) {
		t.Fatal("phone removal did not conserve exact atomic effects")
	}
	provePhoneRemovalAuditAction(t, ctx, f, out)
	if readSession(cookies) {
		t.Fatal("removed phone left prior identifier authority active")
	}
	if beforePassword != nil && readSession(beforePassword.Cookies()) || beforeOTP != nil && readSession(beforeOTP.Cookies()) {
		t.Fatal("phone removal left previously issued phone sessions authorized")
	}
	afterPassword, deniedPassword := phonePassword()
	if afterPassword.StatusCode != 403 || deniedPassword.CommitOutcome != "not_committed" || deniedPassword.SignedIn || len(afterPassword.Cookies()) != 0 || afterPassword.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("removed phone still authenticated by password")
	}
	if sent.CommandID != "" {
		afterOTP, payload := call("/v1/phone/signin", map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": code}, browser, "")
		var deniedOTP otphttp.SigninResponse
		if afterOTP.StatusCode < 400 || afterOTP.StatusCode == 429 || json.Unmarshal(payload, &deniedOTP) != nil || deniedOTP.CommitOutcome == "committed" || deniedOTP.SignedIn || len(afterOTP.Cookies()) != 0 || afterOTP.Header.Get("X-CSRF-Token") != "" || snapshot() != expected {
			t.Fatal("preissued phone OTP denial lost authority/effect custody", afterOTP.StatusCode, deniedOTP.CommitOutcome, deniedOTP.SignedIn)
		}
	}
	// The historical path must work from a reconstructed graph, after this
	// very operation invalidated its original session. No in-memory outcome,
	// newly issued code/proof or replacement session may stand in for custody.
	owner = rebuild()
	if again, err := owner.Remove(ctx, r); err != nil || again.Binding.CommandID != out.Binding.CommandID || again.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone removal original replay", err)
	}
	conflicting, _ := r.Bindings()
	conflicting.ExpectedIdentifierVersion++
	changed, err := phone.NewRemoveRequest(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := owner.Remove(ctx, changed); err == nil || result.Outcome == identity.CommitOutcomeCommitted || snapshot() != expected {
		t.Fatal("same phone-removal key accepted changed original intent")
	}
	query := identity.RecoveryQuery{CommandID: out.Binding.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.phone.remove", RecordID: id}
	foreign := query
	foreign.TenantID = "foreign"
	if result, err := owner.RecoverRemoval(ctx, foreign, caller); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign scope disclosed original phone removal")
	}
	historyCaller := caller.Clone()
	// Native historical query policy binds the original operation. Recovery
	// is marked by the coordinator's trusted resource attributes, not an alias.
	for range 2 {
		history, err := owner.RecoverRemoval(ctx, query, historyCaller)
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != out.Binding || history.Cascade == nil || history.Cascade.CascadeID != out.Cascade.CascadeID {
			t.Fatal("original code-free removal recovery", err)
		}
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("removed-channel notice", err)
	}
	select {
	case notice := <-messages:
		if notice != "Your phone number was removed." {
			t.Fatal("wrong removed-channel notice")
		}
	case <-ctx.Done():
		t.Fatal("missing removed-channel notice")
	}
	current, _ := fresh()
	if !readSession(current) {
		t.Fatal("retained verified-email signin unavailable")
	}
	proveReferenceEmailResetAfterRemoval(t, ctx, f, features, workers, client, base, origin, current, messages, user, "registered@example.invalid")
}

func provePhoneRemovalAuditAction(t *testing.T, ctx context.Context, f liveStores, result identity.CommandResult) {
	t.Helper()
	id, err := base64.RawURLEncoding.DecodeString(string(result.Binding.CommandID))
	if err != nil {
		t.Fatal("phone removal audit command binding", err)
	}
	var total, canonical int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE r.action='identity.identifier.remove') FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1`, id).Scan(&total, &canonical); err != nil || total != 1 || canonical != 1 {
		t.Fatal("phone removal omitted its sole canonical identifier-removal audit", err, total, canonical)
	}
}
