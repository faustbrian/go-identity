//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

type referencePhoneSigninPolicy struct{}

func (referencePhoneSigninPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.phone.remove" || c.Request.Action == "identity.phone.remove.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && (c.Request.Action == "identity.phone.password-signin" || c.Request.Action == "identity.phone.password-signin.recover" || c.Request.Action == "identity.phone.signin" || c.Request.Action == "identity.phone.signin.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceUsernamePolicy{}).Decide(ctx, c)
}

func TestReferencePostgresPhonePasswordSigninHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true}, true)
}

func TestReferencePostgresPhonePasswordUsernameCoexistenceHTTPS(t *testing.T) {
	for _, totp := range []bool{false, true} {
		t.Run(map[bool]string{false: "known-empty", true: "username-totp"}[totp], func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phonePassword: true, username: true, usernameTOTP: totp})
		})
	}
}

// Start from the preceding real register/email-confirm/password-proof/encrypted
// SMS/phone-verification journey. No user, credential, phone or factor authority
// is inserted by this test to make signin succeed.
func proveReferencePhonePasswordHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin, callback string, deviceConfig session.BrowserDeviceConfig, user identity.UserID, readSession func([]*http.Cookie) bool) {
	t.Helper()
	call := func(path string, body any, cookies []*http.Cookie, csrf string) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("phone/password HTTPS request failed", err)
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(wire) > 16384 || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(wire, []byte("+12025550123")) || bytes.Contains(wire, []byte("synthetic-registration-password")) {
			t.Fatal("phone/password response violated bounds, cleanup or redaction")
		}
		return response, wire
	}
	for _, remember := range []bool{false, true} {
		start := func() (sessionhttp.PreAuthResponse, []*http.Cookie) {
			t.Helper()
			r, wire := call("/v1/session/preauth-issue", map[string]any{"method": "phone-password", "identifier": "+12025550123", "remember": remember}, nil, "")
			var out sessionhttp.PreAuthResponse
			if r.StatusCode != 200 || json.Unmarshal(wire, &out) != nil || !out.Issued || len(r.Cookies()) != 2 {
				t.Fatal("canonical target-bound phone initiation failed", r.StatusCode)
			}
			return out, r.Cookies()
		}
		flow, original := start()
		body := map[string]any{"flowID": string(flow.FlowID), "phoneNumber": "+12025550124", "password": "synthetic-registration-password", "callbackURL": callback, "remember": remember}
		r, _ := call("/v1/phone/password-signin", body, original, "")
		if r.StatusCode != 403 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("original phone flow could be retargeted", r.StatusCode)
		}
		body["phoneNumber"] = "+12025550123"
		body["password"] = "synthetic-wrong-password"
		r, wire := call("/v1/phone/password-signin", body, original, "")
		var wrong passwordhttp.SigninResponse
		if r.StatusCode != 403 || json.Unmarshal(wire, &wrong) != nil || wrong.SignedIn || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("wrong phone password was not a credential-free denial", r.StatusCode)
		}
		body["password"] = "synthetic-registration-password"
		r, wire = call("/v1/phone/password-signin", body, original, "")
		var out passwordhttp.SigninResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &out) != nil || !out.SignedIn || out.CommitOutcome != "committed" || out.Recovery == nil || len(r.Cookies()) != 1 || r.Header.Get("X-CSRF-Token") == "" {
			t.Fatal("verified phone/password did not deliver its original session", r.StatusCode, out.Error)
		}
		cookie, csrf := r.Cookies(), r.Header.Get("X-CSRF-Token")
		if !cookie[0].Secure || !cookie[0].HttpOnly || cookie[0].Path != "/" || cookie[0].Domain != "" || (cookie[0].MaxAge > 0) != remember || !readSession(cookie) {
			t.Fatal("phone session lost native read or browser/persistent cookie policy")
		}
		var purpose, subject string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT purpose,user_id FROM identity_password.signin_records WHERE tenant_id=$1 AND proof_id=$2`, otpTenant, string(out.CommandID)).Scan(&purpose, &subject); err != nil || purpose != "identity.phone.password-signin" || subject != string(user) {
			t.Fatal("phone response lacks native password provenance", err)
		}
		owner, err := features.PhoneSignin()
		if err != nil || owner == nil {
			t.Fatal("selected graph lost phone signin owner", err)
		}
		codec, err := session.NewBrowserDeviceCodec(deviceConfig)
		if err != nil {
			t.Fatal(err)
		}
		var flowBearer auth.BearerCredential
		var device session.BrowserDevice
		for _, cookie := range original {
			if cookie.Name == "__Host-identity_flow" {
				flowBearer = auth.NewBearerCredential(cookie.Value)
			}
			if cookie.Name == "__Host-identity_device" {
				device, err = codec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		recovery, err := password.NewSigninRecovery(identity.RecoveryQuery{CommandID: out.CommandID, TenantID: otpTenant, AnonymousFlowID: string(flow.FlowID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.phone.password-signin"}, flow.FlowID)
		if err != nil {
			t.Fatal(err)
		}
		history, err := owner.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: recovery, Cookie: flowBearer, Origin: origin, Network: "127.0.0.1", Device: device.DeviceID(), Caller: authorization.DecisionContext{CorrelationID: "phone-history", PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.phone.password-signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.phone.password-signin"}}}})
		if err != nil || history.State != auth.SignInStateAuthenticated || history.SessionID != out.SessionID || !history.Issuance.Replayed || history.Issuance.Token != (session.Token{}) || history.Issuance.Cookie.Name != "" || history.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("phone native history changed original or redelivered credentials", err)
		}
		r, _ = call("/v1/phone/password-signin", body, original, "")
		if r.StatusCode == 200 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("consumed phone flow reissued credentials")
		}
		r, _ = call("/v1/session/signout", map[string]any{}, cookie, csrf)
		if r.StatusCode != 200 || readSession(cookie) {
			t.Fatal("phone/password session remained usable after logout", r.StatusCode)
		}
	}
}
