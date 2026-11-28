//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// Each administrator gets an independent factor and ordinary session through
// the real registration, verification and authentication owners.
func referenceImpersonationAdmin(t *testing.T, ctx context.Context, client *http.Client, base, origin string, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string, profile string) ([]*http.Cookie, string) {
	t.Helper()
	transport := *client
	transport.Jar = nil
	approver := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, profile)

	post := func(path string, body any, cookies []*http.Cookie, csrf, key, variant string) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal("cannot encode impersonation actor request")
		}
		defer clear(wire)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal("cannot construct impersonation actor request")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		if variant != "" {
			request.Header.Set("X-MFA-Variant", variant)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("impersonation actor HTTPS transport unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" || response.StatusCode != http.StatusOK {
			clear(data)
			t.Fatal("impersonation actor operation failed", path, response.StatusCode)
		}
		return response, data
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(approver.csrf)
	if err != nil {
		t.Fatal("registered approver synchronizer unavailable")
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(approver.user)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(approver.user)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	verifier, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	proof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: auth.NewBearerCredential(approver.cookies[0].Value), Password: candidate, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"}, Caller: caller, Network: "127.0.0.1", Device: "reference-enrollment-device"}, CSRFToken: csrf})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("registered approver password reauthentication failed")
	}
	response, wire := post("/v1/mfa/enable", map[string]any{"proofID": proof.Proof.Proof.ID}, approver.cookies, approver.csrf, "reference-"+profile+"-mfa", "")
	var enrollment enrollmentHTTPObservation
	decodeErr := json.Unmarshal(wire, &enrollment)
	clear(wire)
	defer clear(enrollment.RecoveryCodes)
	if decodeErr != nil || !enrollment.Enabled || enrollment.Active || enrollment.CommitOutcome != "committed" || enrollment.EnrollmentID == "" || enrollment.FactorMethod != "totp" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("approver genuine pending TOTP enrollment unavailable")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	response, wire = post("/v1/mfa/totp-uri", map[string]any{"commandID": command, "enrollmentID": enrollment.EnrollmentID}, approver.cookies, approver.csrf, "", "")
	var revealed struct {
		Disclosed          bool
		URI, CommitOutcome string
		CommandID          identity.CommandID
		EnrollmentID       mfa.EnrollmentID
	}
	decodeErr = json.Unmarshal(wire, &revealed)
	clear(wire)
	if decodeErr != nil || !revealed.Disclosed || revealed.URI == "" || revealed.CommitOutcome != "committed" || revealed.CommandID != command || revealed.EnrollmentID != enrollment.EnrollmentID || len(response.Cookies()) != 0 {
		t.Fatal("approver genuine TOTP provisioning URI unavailable")
	}
	uri, err := url.Parse(revealed.URI)
	if err != nil {
		t.Fatal("approver provisioning URI malformed")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(uri.Query().Get("secret"))
	if err != nil || len(secret) != 32 {
		t.Fatal("approver genuine TOTP material unavailable")
	}
	defer clear(secret)
	command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	response, wire = post("/v1/mfa/totp-verify", map[string]any{"commandID": command, "factorID": enrollment.EnrollmentID, "code": passwordMFAFixtureCode(secret, time.Now())}, approver.cookies, approver.csrf, "", "enrollment")
	var activated struct {
		Activated     bool
		CommitOutcome string
		CommandID     identity.CommandID
		FactorID      mfa.FactorID
		Version       uint64
	}
	decodeErr = json.Unmarshal(wire, &activated)
	clear(wire)
	if decodeErr != nil || !activated.Activated || activated.CommitOutcome != "committed" || activated.CommandID != command || activated.FactorID != mfa.FactorID(enrollment.EnrollmentID) || activated.Version == 0 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("approver genuine TOTP activation failed")
	}
	original := organizationHumanFromSession(t, ctx, sessions, approver.cookies, approver.csrf)
	if original.user != approver.user {
		t.Fatal("enrollment changed approver identity")
	}

	response, wire = post("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil, "", "", "")
	var flow sessionhttp.PreAuthResponse
	if json.Unmarshal(wire, &flow) != nil || !flow.Issued {
		t.Fatal("approver genuine password flow unavailable")
	}
	clear(wire)
	flowCookies := response.Cookies()
	response, wire = post("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": profile + "@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, flowCookies, "", "", "")
	var challenge passwordhttp.SigninResponse
	decodeErr = json.Unmarshal(wire, &challenge)
	clear(wire)
	if decodeErr != nil || !challenge.ChallengeRequired || challenge.SignedIn || challenge.ChallengeID == "" || challenge.SessionID != "" || response.Header.Get("X-MFA-Token") == "" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("approver password primary did not require its genuine second factor")
	}
	command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	// The enrollment step has already been consumed; the configured skew admits
	// the next step without waiting or mutating the real factor's replay state.
	response, wire = post("/v1/mfa/totp-verify", map[string]any{"commandID": command, "preAuthID": flow.FlowID, "challengeID": challenge.ChallengeID, "factorID": activated.FactorID, "token": response.Header.Get("X-MFA-Token"), "code": passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)), "callbackURL": origin + "/reset", "trustDevice": false}, flowCookies, "", "", "password")
	var completed mfahttp.TOTPVerifyResponse
	decodeErr = json.Unmarshal(wire, &completed)
	clear(wire)
	approverCookies, approverCSRF := response.Cookies(), response.Header.Get("X-CSRF-Token")
	if decodeErr != nil || !completed.SignedIn || completed.CommitOutcome != "committed" || completed.CommandID != command || completed.SessionID == "" || len(approverCookies) != 1 || approverCSRF == "" {
		t.Fatal("approver genuine password/TOTP session unavailable")
	}
	current := organizationHumanFromSession(t, ctx, sessions, approverCookies, approverCSRF)
	if current.user != approver.user || current.sessionID != completed.SessionID || current.sessionID == approver.sessionID {
		t.Fatal("completed approver session lost its distinct original identity")
	}
	token, err := session.ParseToken(approverCookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !observed.Authenticated || observed.ValidateAt(time.Now()) != nil {
		t.Fatal("completed approver session is not current")
	}
	factor, err := observed.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" || factor.FactorID != string(activated.FactorID) || factor.CommandID != command {
		t.Fatal("completed approver session did not retain its genuine TOTP authentication")
	}
	return approverCookies, approverCSRF
}
