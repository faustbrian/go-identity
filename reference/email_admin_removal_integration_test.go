//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestReferencePostgresAdministrativeEmailRemoval(t *testing.T) {
	for _, mode := range []string{"removal-admin", "removal-admin-http", "removal-admin-rollback", "removal-admin-contention", "removal-admin-unknown", "removal-admin-output-unknown"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, administrativeEmailRemoval: true, emailChangeCase: mode, completionCommitFault: mode == "removal-admin-unknown" || mode == "removal-admin-output-unknown"})
		})
	}
}

// The administrator is a second genuinely registered, verified and signed-in
// account. Application policy grants only the exact action/target pair after
// proving that authentication alone cannot authorize cross-account removal.
func prepareAdministrativeEmailRemoval(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, target identity.UserID, readSession func([]*http.Cookie) bool) (email.RequestPrimary, identity.UserID, []*http.Cookie, string, func()) {
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
			t.Fatal("administrator HTTP request", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("administrator response custody")
		}
		return response, payload
	}
	issue := func(purpose string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, payload := invoke("/v1/session/preauth-issue", map[string]string{"method": purpose}, "", nil)
		var out sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(payload, &out) != nil || out.FlowID == "" {
			t.Fatal("administrator preauthentication", r.StatusCode)
		}
		return out, r.Cookies()
	}
	flow, device := issue("signup")
	r, payload := invoke("/v1/password/signup", map[string]string{"flowID": string(flow.FlowID), "email": "administrator@example.invalid", "password": "synthetic-administrator-password", "callbackURL": origin + "/confirm"}, "administrator-registration", device)
	var registered passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &registered) != nil || !registered.VerificationRequired {
		t.Fatal("administrator registration", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("administrator verification delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("administrator verification absent")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal("administrator verification link")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r, payload = invoke("/v1/email/verification-confirm", map[string]string{"token": u.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(command)}, "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &confirmed) != nil || !confirmed.Confirmed || confirmed.Recovery == nil {
		t.Fatal("administrator verification", r.StatusCode)
	}
	actor := confirmed.Recovery.UserID
	if actor == target || actor == "" {
		t.Fatal("administrator must be a distinct real account")
	}
	flow, device = issue("password")
	r, payload = invoke("/v1/password/signin", map[string]string{"flowID": string(flow.FlowID), "identifier": "administrator@example.invalid", "password": "synthetic-administrator-password", "callbackURL": origin + "/reset"}, "", device)
	var signed passwordhttp.SigninResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &signed) != nil || !signed.SignedIn || len(r.Cookies()) != 1 {
		t.Fatal("administrator signin", r.StatusCode)
	}
	cookies, csrfWire := r.Cookies(), r.Header.Get("X-CSRF-Token")
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal("administrator CSRF custody")
	}
	proofOwner, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte("synthetic-administrator-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	bearer := auth.NewBearerCredential(cookies[0].Value)
	verified, err := proofOwner.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: bearer, Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.email.address-remove", Audience: "reference-managed-email"}, Caller: caller, Network: "127.0.0.1", Device: "administrator-consumer"}, CSRFToken: csrf})
	if err != nil {
		t.Fatal("administrator fresh original proof", err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT ROW(u.version,u.identifier_version,u.credential_version,u.authority_version,(SELECT COALESCE(sum(version),0) FROM identity_password.credentials c WHERE c.tenant_id=u.tenant_id AND c.user_id=u.user_id),(SELECT COALESCE(sum(version),0) FROM identity.identifiers i WHERE i.tenant_id=u.tenant_id AND i.user_id=u.user_id))::text FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(actor)).Scan(&value); err != nil {
			t.Fatal("administrator authority snapshot", err)
		}
		return value
	}
	before := snapshot()
	unchanged := func() {
		t.Helper()
		if snapshot() != before || !readSession(cookies) {
			t.Fatal("target removal changed administrator authority or session")
		}
		token, err := session.ParseToken(cookies[0].Value)
		if err != nil {
			t.Fatal("original administrator session custody")
		}
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		current, err := owner.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !current.Authenticated {
			t.Fatal("administrator session lost after target effects", err)
		}
		binding, err := current.Session.Bindings()
		if err != nil || binding.UserID != actor || binding.UserID == target {
			t.Fatal("administrator session became target", err)
		}
	}
	return email.RequestPrimary{Session: bearer, Proof: verified.Proof, CSRFToken: csrf}, actor, cookies, csrfWire, unchanged
}
