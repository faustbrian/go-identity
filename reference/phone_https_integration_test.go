//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/otp"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresPhoneEnrollmentHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true}, true)
}

func configureReferencePhone(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	if c.PasswordVerification == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil {
		t.Fatal("phone fixture requires genuine proof/session/browser owners")
	}
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePhoneVerification, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	checks, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.NewRequestKeyConfig("reference-phone", [32]byte{231}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.send-verification", Audience: "reference-phone"})
	c.Phone = &reference.PhoneConfiguration{Policy: policy,
		Primary:  passwordpg.ActionPrimaryConfig{Action: "identity.phone.send-verification", Audience: "reference-phone", MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: c.Session.CSRFKeys},
		Native:   passwordpg.PhoneVerificationConfig{PolicyID: "reference-phone", ConfigurationID: "reference-phone-v1", MaximumDuration: c.OTP.Timeout, Domain: kernel.PhoneEnrollmentDomainConfig{NormalizationProfile: policy.Profile().ID, NormalizationVersion: policy.Profile().Version, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {232}}, ReuseCooldown: 30 * 24 * time.Hour}, RequestKeys: keys, IntentKey: [32]byte{233}, IdentifierKey: [32]byte{234}, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-phone-risk-v1", Keys: c.OTP.RiskKeys}, ActiveEnvelopeKeyID: c.Delivery.Enqueue.Custody.ActiveEnvelopeKeyID, CurrentAttemptKeyVersion: c.OTP.Signin.CurrentAttemptKeyVersion},
		Issuance: reference.PhoneIssuanceConfiguration{Policy: checks, SessionKeys: map[uint32][]byte{11: bytes.Repeat([]byte{0x79}, 32)}, FreshnessLimit: 5 * time.Minute, TemplateID: "phone-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}},
	}
	c.Delivery.Enqueue.Custody.ProviderProfiles[2] = deliverypg.ProviderProfile{Provider: "phone-capture", PolicyVersion: 1}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "phone-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "{{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128})
	c.HTTPPhoneVerification = &reference.HTTPPhoneVerificationConfiguration{Origin: origin, Device: *c.HTTPPreAuth.Device, PolicyRevision: 9}
}

// Every identity, password proof, challenge and delivery is created through the
// real graph and HTTPS. The only provider substitution is the declared sender.
func proveReferencePhoneHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string, client *http.Client, base, origin string, server *reference.Server, user identity.UserID, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool, afterVerified func(), selectedRemoval ...bool) {
	t.Helper()
	document := string(server.OpenAPI().JSON())
	for _, path := range []string{"/v1/phone/send-verification", "/v1/phone/verify", "/v1/phone/verify/recover"} {
		if !strings.Contains(document, path) {
			t.Fatal("phone selection omitted its real route")
		}
	}
	for _, path := range []string{"/v1/phone/password-reset", "/v1/phone/update"} {
		if strings.Contains(document, path) {
			t.Fatal("phone selection advertised an unsupported profile")
		}
	}
	if strings.Contains(document, "/v1/phone/remove") != (len(selectedRemoval) == 1 && selectedRemoval[0]) {
		t.Fatal("phone removal HTTP opt-in differs from advertised route")
	}
	if _, err := features.PhoneOTPSignin(); (err == nil) != strings.Contains(document, "/v1/phone/signin") {
		t.Fatal("phone OTP selection and exposed route disagree")
	}
	call := func(method, path string, body any, key, token, requestOrigin string, selected []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		var data []byte
		var err error
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range selected {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("phone HTTPS request", err)
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(wire) > 16384 {
			t.Fatal("phone response bounds/cleanup")
		}
		return response, wire
	}
	r, wire := call("GET", "/v1/session/get", nil, "", "", origin, cookies)
	var current sessionhttp.GetResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &current) != nil || !current.Authenticated || current.Session == nil || current.Principal == nil || current.Principal.UserID != user {
		t.Fatal("phone journey lacks genuine initial session")
	}
	flowID := current.Session.ID
	r, wire = call("POST", "/v1/session/preauth-issue", map[string]string{"method": "password"}, "", "", origin, nil)
	var browser sessionhttp.PreAuthResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &browser) != nil || !browser.Issued {
		t.Fatal("phone journey lacks deliberate signed browser initialization")
	}
	ownedCookies := append([]*http.Cookie{}, cookies...)
	for _, cookie := range r.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			ownedCookies = append(ownedCookies, cookie)
		}
	}
	r, wire = call("POST", "/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": "identity.phone.send-verification", "audience": "reference-phone"}, "", csrf, origin, ownedCookies)
	var proof passwordhttp.VerificationResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &proof) != nil || !proof.Verified || proof.Proof == nil || proof.Proof.Action != "identity.phone.send-verification" {
		t.Fatal("actual phone action proof failed", r.StatusCode, proof.Error)
	}
	body := map[string]string{"flowID": flowID, "number": "+12025550123", "proofID": proof.Proof.ProofID}
	for _, denial := range []string{"origin", "csrf", "override"} {
		input := map[string]string{}
		for k, v := range body {
			input[k] = v
		}
		selectedOrigin, selectedCSRF := origin, csrf
		want := 403
		if denial == "origin" {
			selectedOrigin = "https://foreign.invalid"
		}
		if denial == "csrf" {
			selectedCSRF = ""
		}
		if denial == "override" {
			input["userID"] = "foreign"
			want = 400
		}
		response, _ := call("POST", "/v1/phone/send-verification", input, "phone-https-original", selectedCSRF, selectedOrigin, ownedCookies)
		if response.StatusCode != want {
			t.Fatal("phone transport authority denial failed", denial, response.StatusCode)
		}
	}
	var phones, codes int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE kind='phone'),(SELECT count(*) FROM otp_store.challenges WHERE purpose='phone-verification')`).Scan(&phones, &codes); err != nil || phones != 0 || codes != 0 {
		t.Fatal("denied HTTP phone send left effects", err)
	}
	decode := func(response *http.Response, wire []byte) phonehttp.VerificationResponse {
		t.Helper()
		var out phonehttp.VerificationResponse
		if json.Unmarshal(wire, &out) != nil || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" || bytes.Contains(wire, []byte("+12025550123")) || bytes.Contains(wire, []byte("synthetic-registration-password")) {
			t.Fatal("phone response violated safe wire projection")
		}
		for _, cookie := range ownedCookies {
			if bytes.Contains(wire, []byte(cookie.Value)) {
				t.Fatal("phone response disclosed a browser/session credential")
			}
		}
		return out
	}
	r, wire = call("POST", "/v1/phone/send-verification", body, "phone-https-original", csrf, origin, ownedCookies)
	sent := decode(r, wire)
	if r.StatusCode != 202 || !sent.Accepted || sent.CommitOutcome != "committed" || sent.CommandID == "" {
		t.Fatal("native HTTP phone send failed", r.StatusCode, sent.Error)
	}
	r, wire = call("POST", "/v1/phone/send-verification", body, "phone-https-original", csrf, origin, ownedCookies)
	replayed := decode(r, wire)
	if r.StatusCode != 202 || replayed.CommandID != sent.CommandID {
		t.Fatal("HTTP retry lost original enrollment")
	}
	changed := map[string]string{}
	for k, v := range body {
		changed[k] = v
	}
	changed["number"] = "+12025550124"
	r, _ = call("POST", "/v1/phone/send-verification", changed, "phone-https-original", csrf, origin, ownedCookies)
	if r.StatusCode != 409 {
		t.Fatal("same-key changed phone input did not conflict", r.StatusCode)
	}
	if processed, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || !processed.Claimed {
		t.Fatal("selected real SMS worker failed", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("native SMS missing")
	}
	if len(code) != 6 {
		t.Fatal("captured SMS did not contain the native phone code")
	}
	if processed, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || processed.Claimed {
		t.Fatal("phone replay queued another SMS", err)
	}
	wrong := []byte(code)
	wrong[0] = '0' + (wrong[0]-'0'+1)%10
	completion := map[string]string{"flowID": flowID, "sendCommandID": string(sent.CommandID), "code": string(wrong)}
	clear(wrong)
	r, wire = call("POST", "/v1/phone/verify", completion, "", csrf, origin, ownedCookies)
	denied := decode(r, wire)
	if r.StatusCode != 403 || denied.Verified {
		var used, failed int
		err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed)
		t.Fatal("wrong SMS code was not a uniform denial", r.StatusCode, denied.Error, "outcome", denied.CommitOutcome, "attempt counts", used, failed, "read failed", err != nil)
	}
	var attempts, failures int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&attempts, &failures); err != nil || attempts != 1 || failures != 1 {
		t.Fatal("HTTP wrong-code denial was not one consuming native attempt", err)
	}
	completion["code"] = code
	r, wire = call("POST", "/v1/phone/verify", completion, "", csrf, origin, ownedCookies)
	verified := decode(r, wire)
	if r.StatusCode != 200 || !verified.Verified || verified.IdentifierID == "" || verified.IdentifierVersion != 2 || verified.Recovery == nil {
		t.Fatal("HTTP phone verification did not commit actual native effect", r.StatusCode, verified.Error)
	}
	if bytes.Contains(wire, []byte(code)) {
		t.Fatal("verification response disclosed submitted code")
	}
	completion["code"], code = "", ""
	r, wire = call("POST", "/v1/phone/verify/recover", map[string]any{"flowID": flowID, "recovery": verified.Recovery}, "", csrf, origin, ownedCookies)
	history := decode(r, wire)
	if r.StatusCode != 200 || history.CommitOutcome != "committed" || history.Verified || history.Accepted || history.IdentifierID != "" || history.CommandID != verified.CommandID || history.Recovery == nil || *history.Recovery != *verified.Recovery {
		t.Fatal("original HTTP recovery disclosed or replaced phone verification", r.StatusCode, history.Error)
	}
	var actualVerified bool
	var version, verificationVersion uint64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT verified,version,verification_version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), string(verified.IdentifierID)).Scan(&actualVerified, &version, &verificationVersion); err != nil || !actualVerified || version != 2 || verificationVersion != 2 {
		t.Fatal("HTTP result lacks durable verified phone", err)
	}
	if readSession(cookies) {
		t.Fatal("identifier mutation left original session authority active")
	}
	if afterVerified != nil {
		afterVerified()
	}
	freshCookies, freshCSRF := fresh()
	if !readSession(freshCookies) {
		t.Fatal("verified phone broke ordinary password signin")
	}
	r, _ = call("POST", "/v1/session/signout", map[string]any{}, "", freshCSRF, origin, freshCookies)
	if r.StatusCode != 200 || readSession(freshCookies) {
		t.Fatal("post-phone authenticated session did not logout", r.StatusCode)
	}
	if _, err := features.Phone(); err != nil {
		t.Fatal("selected graph lost native phone handle", err)
	}
}
