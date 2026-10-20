//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresPhoneChangeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, phoneChange: true}, true)
}

func configureReferencePhoneChange(t *testing.T, c *reference.StoreConfiguration) *atomic.Int32 {
	t.Helper()
	// Retain the existing application policy shared by all graph owners.
	query := c.OTP.RequestKeys.Policy
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets,
		passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.send-verification", Audience: "reference-phone-change-send"},
		passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.update", Audience: "reference-phone-change-update"})
	keys, err := kernel.NewRequestKeyConfig("reference-phone-change", [32]byte{241}, query)
	if err != nil {
		t.Fatal(err)
	}
	cascade := kernel.IdentifierChangeCascadeConfig{PolicyVersion: 101, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]kernel.StatusConsumerContract{}}
	for _, id := range identity.IdentifierChangeConsumers() {
		cascade.ConsumerContracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: sha256.Sum256([]byte("synthetic-reference-phone-change-v1:" + id))}
	}
	counters := c.PasswordSignup.Counters
	counters.EnforceLockouts = true
	c.PhoneChange = &reference.PhoneChangeConfiguration{Policy: c.Phone.Policy, SendPrimary: passwordpg.ActionPrimaryConfig{Action: "identity.phone.send-verification", Audience: "reference-phone-change-send", MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie}, UpdatePrimary: passwordpg.ActionPrimaryConfig{Action: "identity.phone.update", Audience: "reference-phone-change-update", MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie}, Issuance: c.Phone.Issuance, Native: passwordpg.PhoneChangeConfig{PolicyID: "reference-phone-change", ConfigurationID: "reference-phone-change-v1", Reason: "user-requested", MaximumDuration: c.OTP.Timeout, Domain: kernel.PhoneChangeDomainConfig{Directory: c.Phone.Native.Domain, Cascade: cascade}, RequestKeys: keys, IntentKey: [32]byte{242}, IdentifierKey: [32]byte{243}, AuthenticationRisk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-phone-change-send-risk"}, UpdateRisk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-phone-change-update-risk"}, Counters: counters, ActiveEnvelopeKeyID: c.Delivery.Enqueue.Custody.ActiveEnvelopeKeyID, CurrentAttemptKeyVersion: c.Phone.Native.CurrentAttemptKeyVersion, Notice: passwordpg.PhoneRemovalNoticeConfig{TemplateID: "phone-changed", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, TTL: time.Hour}}}
	c.DurableAdmission.Policy = counters.CommandCounters.Policy
	c.PasswordSignup.Native.Screening.Policy = registrationRiskPolicy(t, 9, true)
	collect, calls := registrationScreening(t, c.PasswordSignup.Native.Screening.Policy)
	c.PasswordSignup.Native.Screening.Collect = collect
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "phone-changed", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Your phone number was changed.", ContentType: "text/plain", MaxRenderedBytes: 128})
	return calls
}

// Reconstruct a populated deployment with replacement selected and enrollment
// disabled. Real bootstrap/migration, proof, SMS, OTP, mutation and recovery
// owners remain supplied by reference; only the external sender captures SMS.
func proveReferencePhoneChangeHTTPS(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, config reference.ReferenceConfig, deps reference.ReferenceDependencies, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, modules []reference.ModuleID, migration reference.ReferenceMigrationApplyRequest, messages <-chan string, user identity.UserID, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool, client *http.Client, base, origin string, replace func(http.Handler)) {
	t.Helper()
	c.Phone, c.HTTPPhoneVerification = nil, nil
	c.HTTPPhoneChange = &reference.HTTPPhoneChangeConfiguration{Origin: origin, Device: *c.HTTPPreAuth.Device, PolicyRevision: 9}
	// A distinct selected old-number notice provider must have its own worker,
	// even when the new-number SMS provider is present. This constructs real
	// owners but performs no mutation or synthetic delivery.
	incomplete := c
	native := *c.PhoneChange
	native.Native.Notice.ProviderVersion = 3
	incomplete.PhoneChange = &native
	deliveryConfig := *c.Delivery
	deliveryConfig.Enqueue.Custody.ProviderProfiles = maps.Clone(c.Delivery.Enqueue.Custody.ProviderProfiles)
	deliveryConfig.Enqueue.Custody.ProviderProfiles[3] = deliveryConfig.Enqueue.Custody.ProviderProfiles[2]
	incomplete.Delivery = &deliveryConfig
	graph, err := reference.ComposeStores(incomplete, deps)
	if err != nil {
		t.Fatal("notice-worker dependency graph", err)
	}
	func() {
		defer func() {
			bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := graph.Close(bounded); err != nil {
				t.Error(err)
			}
		}()
		providers, err := reference.ComposeProviders(graph)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reference.ComposeWorkers(graph, providers, workerConfigs...); err == nil {
			t.Fatal("replacement accepted no worker for its selected old-number notice provider")
		}
	}()
	features := upgradeReferenceEmailGraph(t, ctx, f, c, deps, workerConfigs[0], modules, user, migration, workerConfigs[1:]...)
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("replacement HTTPS composition", err)
	}
	doc := string(server.OpenAPI().JSON())
	for _, path := range []string{"/v1/phone/send-verification", "/v1/phone/update", "/v1/phone/update/recover"} {
		if !strings.Contains(doc, path) {
			t.Fatal("missing replacement route", path)
		}
	}
	for _, path := range []string{"/v1/phone/verify\"", "/v1/phone/verify/recover"} {
		if strings.Contains(doc, path) {
			t.Fatal("replacement implicitly exposed enrollment")
		}
	}
	replace(server.Handler())
	cookies, csrf := fresh()
	call := func(path string, body any, key, token, requestOrigin string, selected []*http.Cookie) (*http.Response, []byte) {
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
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		for _, cookie := range selected {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("replacement transport", err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(payload) > 16384 {
			t.Fatal("replacement response cleanup/bounds")
		}
		return response, payload
	}
	decode := func(r *http.Response, wire []byte) phonehttp.ChangeResponse {
		t.Helper()
		var out phonehttp.ChangeResponse
		if parse := json.Unmarshal(wire, &out); parse != nil || r.Header.Get("Cache-Control") != "no-store" || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("replacement unsafe response", r.Request.URL.Path, r.StatusCode, "JSON", parse == nil, "no-store", r.Header.Get("Cache-Control") == "no-store", "cookies", len(r.Cookies()), "csrf", r.Header.Get("X-CSRF-Token") != "")
		}
		for _, cookie := range cookies {
			if bytes.Contains(wire, []byte(cookie.Value)) {
				t.Fatal("replacement disclosed browser credential")
			}
		}
		return out
	}
	proof := func(action, audience string) string {
		t.Helper()
		r, wire := call("/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": action, "audience": audience}, "", csrf, origin, cookies)
		var out passwordhttp.VerificationResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &out) != nil || !out.Verified || out.Proof == nil {
			t.Fatal("replacement fresh action proof", r.StatusCode, out.Error)
		}
		return out.Proof.ProofID
	}
	// Obtain public session ID through the real native reader and a signed device
	// through explicit initiation; neither grants replacement authority.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/session/get", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var current sessionhttp.GetResponse
	err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&current)
	closed := response.Body.Close()
	if err != nil || closed != nil || response.StatusCode != 200 || !current.Authenticated || current.Session == nil {
		t.Fatal("replacement genuine session")
	}
	r, wire := call("/v1/session/preauth-issue", map[string]string{"method": "password"}, "", "", origin, nil)
	if r.StatusCode != 200 {
		t.Fatal("replacement signed device", r.StatusCode)
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			cookies = append(cookies, cookie)
		}
	}
	var id string
	var version, verification uint64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version,verification_version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, otpTenant, string(user)).Scan(&id, &version, &verification); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"flowID": current.Session.ID, "number": "+12025550125", "previousNumber": "+12025550123", "identifierID": id, "expectedIdentifierVersion": strconv.FormatUint(version, 10), "expectedVerificationVersion": strconv.FormatUint(verification, 10), "proofID": proof("identity.phone.send-verification", "reference-phone-change-send")}
	for _, denial := range []string{"origin", "csrf", "predecessor"} {
		input := map[string]string{}
		for k, v := range body {
			input[k] = v
		}
		selectedOrigin, selectedCSRF := origin, csrf
		if denial == "origin" {
			selectedOrigin = "https://foreign.invalid"
		}
		if denial == "csrf" {
			selectedCSRF = ""
		}
		if denial == "predecessor" {
			input["expectedIdentifierVersion"] = "1"
		}
		r, wire = call("/v1/phone/send-verification", input, "phone-change-denial-"+denial, selectedCSRF, selectedOrigin, cookies)
		if denial == "origin" {
			if r.StatusCode != 403 || string(wire) != "identity.http.origin_denied\n" || r.Header.Get("Cache-Control") != "no-store" || len(r.Cookies()) != 0 {
				t.Fatal("replacement origin denial changed canonical transport contract")
			}
			continue
		}
		out := decode(r, wire)
		if r.StatusCode < 400 || out.Accepted || out.Updated {
			t.Fatal("replacement authority denial", denial, r.StatusCode)
		}
	}
	r, wire = call("/v1/phone/send-verification", body, "phone-change-original-send", csrf, origin, cookies)
	sent := decode(r, wire)
	if r.StatusCode != 202 || !sent.Accepted || sent.CommandID == "" {
		t.Fatal("replacement SMS request", r.StatusCode, sent.Error)
	}
	r, wire = call("/v1/phone/send-verification", body, "phone-change-original-send", csrf, origin, cookies)
	if replay := decode(r, wire); r.StatusCode != 202 || replay.CommandID != sent.CommandID {
		t.Fatal("replacement sending retry changed original")
	}
	if out, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || !out.Claimed {
		t.Fatal("replacement SMS delivery", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("replacement SMS missing")
	}
	if len(code) != 6 {
		t.Fatal("replacement delivered code invalid")
	}
	updateProof := proof("identity.phone.update", "reference-phone-change-update")
	wrong := []byte(code)
	wrong[0] = '0' + (wrong[0]-'0'+1)%10
	completion := map[string]string{"flowID": current.Session.ID, "sendCommandID": string(sent.CommandID), "code": string(wrong), "proofID": updateProof, "reason": "user-requested"}
	clear(wrong)
	r, wire = call("/v1/phone/update", completion, "phone-change-wrong-original", csrf, origin, cookies)
	denied := decode(r, wire)
	if r.StatusCode != 403 || denied.Updated {
		t.Fatal("wrong replacement code accepted", r.StatusCode, denied.Error)
	}
	r, wire = call("/v1/phone/update", completion, "phone-change-wrong-original", csrf, origin, cookies)
	if replay := decode(r, wire); r.StatusCode != 200 || !replay.Replayed || replay.Updated || replay.CommandID != denied.CommandID {
		t.Fatal("wrong-code original retry", r.StatusCode, replay.Error)
	}
	completion["code"] = code
	r, wire = call("/v1/phone/update", completion, "phone-change-success-original", csrf, origin, cookies)
	updated := decode(r, wire)
	if r.StatusCode != 200 || !updated.Updated || updated.CommitOutcome != "committed" || updated.Recovery == nil {
		t.Fatal("replacement did not commit", r.StatusCode, updated.Error, updated.CommitOutcome)
	}
	if bytes.Contains(wire, []byte(code)) {
		t.Fatal("replacement disclosed code")
	}
	r, wire = call("/v1/phone/update", completion, "phone-change-success-original", csrf, origin, cookies)
	if replay := decode(r, wire); r.StatusCode != 200 || !replay.Replayed || replay.Updated || replay.CommandID != updated.CommandID {
		t.Fatal("spent-session successful retry lost original replacement", r.StatusCode, replay.Error)
	}
	completion["code"], code = "", ""
	if readSession(cookies) {
		t.Fatal("replacement left old session authority valid")
	}
	r, wire = call("/v1/phone/update/recover", map[string]any{"flowID": current.Session.ID, "recovery": updated.Recovery}, "", csrf, origin, cookies)
	if history := decode(r, wire); r.StatusCode != 200 || history.Updated || history.CommandID != updated.CommandID || history.Recovery == nil || *history.Recovery != *updated.Recovery {
		t.Fatal("replacement original code-free recovery", r.StatusCode, history.Error)
	}
	var actual bool
	var attempts, failures, notices int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT canonical_value=$3 AND verified AND version=$4::numeric AND verification_version=$5::numeric FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2),(SELECT used_attempts FROM otp_store.challenges WHERE challenge_id=$6),(SELECT failed_attempts FROM otp_store.challenges WHERE challenge_id=$6),(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND purpose='identity.phone.change-notification')`, otpTenant, id, "+12025550125", version+1, verification+1, string(sent.CommandID)).Scan(&actual, &attempts, &failures, &notices); err != nil || !actual || attempts != 2 || failures != 1 || notices != 1 {
		t.Fatal("replacement durable atomic effects", err, actual, attempts, failures, notices)
	}
	if out, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || !out.Claimed {
		t.Fatal("old-number notification delivery", err)
	}
	select {
	case notice := <-messages:
		if notice != "Your phone number was changed." {
			t.Fatal("replacement notice missing")
		}
	case <-ctx.Done():
		t.Fatal("replacement notice missing")
	}
	// Retained independent email/password recovery remains usable.
	newCookies, _ := fresh()
	if !readSession(newCookies) {
		t.Fatal("replacement disabled independent email signin")
	}
	phoneLogin := func(number string, want bool) {
		t.Helper()
		r, wire := call("/v1/session/preauth-issue", map[string]string{"method": "phone-password", "identifier": number}, "", "", origin, nil)
		var flow sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued {
			t.Fatal("replacement bound phone initiation", r.StatusCode)
		}
		r, wire = call("/v1/phone/password-signin", map[string]string{"flowID": string(flow.FlowID), "phoneNumber": number, "password": "synthetic-registration-password", "callbackURL": c.PasswordSignin.PreAuth.CallbackURL}, "", "", origin, r.Cookies())
		var out passwordhttp.SigninResponse
		if json.Unmarshal(wire, &out) != nil || out.SignedIn != want {
			t.Fatal("replacement phone signin outcome", r.StatusCode, out.Error)
		}
		if want {
			if r.StatusCode != 200 || !readSession(r.Cookies()) {
				t.Fatal("new phone session unusable", r.StatusCode)
			}
		} else if r.StatusCode != 403 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("retired phone received authority", r.StatusCode)
		}
	}
	phoneLogin("+12025550123", false)
	phoneLogin("+12025550125", true)
	// Request and delivery prove the retained recovery factor remains usable;
	// this profile does not set a password, so its real HIBP collector stays idle.
	reset, err := features.PasswordReset()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("phone-change-independent-reset"))
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(command), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.password.reset-request", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.reset-request"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	requestReset := password.ResetRequestRequest{TenantID: otpTenant, CommandID: command, Identifier: "registered@example.invalid", CallbackURL: origin + "/reset", IdempotencyKey: key, Caller: caller, Origin: origin, Network: "127.0.0.1", Device: "reference-phone-change-reset"}
	accepted, err := reset.ResetRequest(ctx, requestReset)
	if err != nil || !accepted.Accepted || accepted.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("retained email reset unavailable", err)
	}
	if again, err := reset.ResetRequest(ctx, requestReset); err != nil || again != accepted {
		t.Fatal("retained email reset retry changed original", err)
	}
	if out, err := workers.ProcessDeliveryOne(ctx, 0); err != nil || !out.Claimed {
		t.Fatal("retained email reset delivery", err)
	}
	select {
	case link := <-messages:
		u, err := url.Parse(link)
		if err != nil || u.Scheme != "https" || u.Path != "/password/reset" || u.Query().Get("token") == "" {
			t.Fatal("retained email reset delivery scope")
		}
	case <-ctx.Done():
		t.Fatal("retained email reset missing")
	}
}
