//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresVerificationSignin(t *testing.T) {
	for _, profile := range []string{"browser", "persistent", "browser-http", "persistent-http", "missing-factor", "nonempty-factor-authority", "late-factor", "policy-denied", "policy-denied-http", "late-issuer-expiry", "late-issuer-expiry-http", "blocked-user", "rollback", "verification-rollback", "risk-unavailable", "contention", "child-unknown", "verification-unknown"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, completionCommitFault: strings.HasSuffix(profile, "-unknown")})
		})
	}
}

func proveReferenceVerificationSignin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, profile string) {
	t.Helper()
	post := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(wire))
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
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("bounded no-store response")
		}
		return response, payload
	}
	remember := strings.HasPrefix(profile, "persistent")
	r, wire := post("/v1/session/preauth-issue", map[string]any{"method": "signup", "remember": remember}, "", nil)
	var flow sessionhttp.PreAuthResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued {
		t.Fatal("signup browser initiation", r.StatusCode)
	}
	var browser auth.BearerCredential
	cookies := r.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "__Host-identity_flow" {
			browser = auth.NewBearerCredential(cookie.Value)
		}
	}
	if browser.Token() == "" {
		t.Fatal("original browser custody missing")
	}
	r, wire = post("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": "verified-signin@example.invalid", "password": "synthetic-verification-password", "callbackURL": origin + "/confirm", "remember": remember}, "verification-signin-original", cookies)
	var signup passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &signup) != nil || signup.CommitOutcome != "committed" || !signup.VerificationRequired || len(r.Cookies()) != 0 {
		t.Fatal("pending registration", r.StatusCode, signup.Error)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("actual original email delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("delivered link missing")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal("delivered link invalid")
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("delivered original grant invalid")
	}
	callback, _ := url.Parse(origin + "/confirm")
	id, _ := identity.NewCommandID()
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Action: "identity.email.verification-confirm", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Resource: authorization.Resource{Type: "identity.user"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	owner, err := features.RegistrationVerificationSignin()
	if err != nil {
		t.Fatal("explicit native signin selection", err)
	}
	request := email.VerificationSigninRequest{Confirmation: email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: proof, Callback: *callback, Network: "127.0.0.1", Caller: caller}, Browser: browser, Origin: origin, Device: "verification-signin-device"}
	wrong := request
	wrong.Browser = auth.NewBearerCredential("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	if denied, err := owner.VerificationConfirmAndSignin(ctx, wrong); err == nil || denied.Verification.Outcome != identity.CommitOutcomeInvalid || denied.Issuance.Token != (session.Token{}) {
		t.Fatal("foreign browser verified or authenticated")
	}
	if proveVerificationSigninFault(t, ctx, f, owner, request, signup.CommandID, profile) {
		return
	}
	if strings.HasSuffix(profile, "-http") {
		body := map[string]string{"token": u.Query().Get("token"), "callback": callback.String(), "commandID": string(id)}
		r, _ := post("/v1/email/verification-confirm", body, "", nil)
		if r.StatusCode == 200 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("selected signin accepted absent original browser/device")
		}
		r, wire := post("/v1/email/verification-confirm", body, "", cookies)
		var confirmation emailhttp.ConfirmationResponse
		if profile == "policy-denied-http" || profile == "late-issuer-expiry-http" {
			if r.StatusCode == 200 || json.Unmarshal(wire, &confirmation) != nil || !confirmation.Confirmed || confirmation.CommitOutcome != "committed" || confirmation.Address != nil || confirmation.Signin == nil || confirmation.Signin.SignedIn || confirmation.Signin.SessionID != "" || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
				t.Fatal("HTTPS child denial lost parent verification or disclosed credentials", r.StatusCode, confirmation.CommitOutcome, confirmation.Confirmed)
			}
			if confirmation.Recovery == nil || confirmation.Signin.CommandID == "" || confirmation.Signin.CommitOutcome != "unknown" || confirmation.Signin.Recovery.RecordID != string(id) {
				t.Fatal("HTTPS child refusal lost original recovery correlations")
			}
			var verified, sessions, grants int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND verified),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use WHERE tenant_id=$1)`, otpTenant).Scan(&verified, &sessions, &grants); err != nil || verified != 1 || sessions != 0 || grants != 1 {
				t.Fatal("HTTPS denial disagrees with durable verification/signin outcomes", err, verified, sessions, grants)
			}
			r, wire = post("/v1/email/verification-confirm", body, "", cookies)
			if profile == "late-issuer-expiry-http" {
				if r.StatusCode == 200 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
					t.Fatal("expired HTTPS original browser renewed signin")
				}
				return
			}
			var replay emailhttp.ConfirmationResponse
			if r.StatusCode != 200 || json.Unmarshal(wire, &replay) != nil || !replay.Confirmed || !replay.Replayed || replay.Signin != nil || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
				t.Fatal("HTTPS child-denial replay created replacement credentials", r.StatusCode)
			}
			return
		}
		if r.StatusCode != 200 || json.Unmarshal(wire, &confirmation) != nil || !confirmation.Confirmed || confirmation.CommitOutcome != "committed" || confirmation.Signin == nil || !confirmation.Signin.SignedIn || confirmation.Signin.CommitOutcome != "committed" || len(r.Cookies()) != 1 || r.Header.Get("X-CSRF-Token") == "" || bytes.Contains(wire, []byte(u.Query().Get("token"))) {
			t.Fatal("selected HTTPS verification -> signin", r.StatusCode, confirmation.CommitOutcome, confirmation.Error)
		}
		cookie := r.Cookies()[0]
		if (cookie.MaxAge > 0) != remember || !cookie.Secure || !cookie.HttpOnly {
			t.Fatal("HTTPS signin lost original remember policy")
		}
		token, err := session.ParseToken(cookie.Value)
		if err != nil {
			t.Fatal("HTTPS did not deliver a session credential")
		}
		if _, err := session.ParseCSRFToken(r.Header.Get("X-CSRF-Token")); err != nil {
			t.Fatal("HTTPS did not deliver a synchronizer")
		}
		sessions, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		credential, _ := session.NewCredential(session.CredentialCookie, token)
		current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !current.Authenticated {
			t.Fatal("HTTPS verification credential cannot authenticate", err)
		}
		csrfWire := r.Header.Get("X-CSRF-Token")
		httpSession := func(method, path, synchronizer string) (*http.Response, []byte) {
			t.Helper()
			var body io.Reader
			if method == "POST" {
				body = strings.NewReader("{}")
			}
			request, err := http.NewRequestWithContext(ctx, method, base+path, body)
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(cookie)
			if method == "POST" {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", origin)
			}
			if synchronizer != "" {
				request.Header.Set("X-CSRF-Token", synchronizer)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
			closeErr := response.Body.Close()
			if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("bounded session HTTPS response")
			}
			return response, payload
		}
		r, wire = httpSession("GET", "/v1/session/get", "")
		var read sessionhttp.GetResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || !read.Authenticated || read.Session == nil || read.Session.ID != confirmation.Signin.SessionID {
			t.Fatal("verification signin not readable through HTTPS", r.StatusCode)
		}
		r, wire = post("/v1/email/verification-confirm", body, "", cookies)
		var replay emailhttp.ConfirmationResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &replay) != nil || !replay.Replayed || replay.Signin != nil || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTPS retry reissued credentials", r.StatusCode)
		}
		r, wire = httpSession("POST", "/v1/session/signout", csrfWire)
		var logout sessionhttp.SignOutResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &logout) != nil || !logout.SignedOut || logout.CommitOutcome != "committed" {
			t.Fatal("HTTPS-issued session cannot logout through HTTPS", r.StatusCode)
		}
		current, err = sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err == nil && current.Authenticated {
			t.Fatal("HTTPS-issued session survived logout")
		}
		return
	}
	out, err := owner.VerificationConfirmAndSignin(ctx, request)
	if err != nil || out.Validate() != nil || out.Verification.Outcome != identity.CommitOutcomeCommitted || out.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || out.Issuance.Token == (session.Token{}) || out.CSRFToken == (session.CSRFToken{}) {
		t.Fatal("registration verification -> native signin", out.Verification.Outcome, out.Issuance.CommitOutcome, err)
	}
	spec, _ := out.Issuance.Session.Bindings()
	if (spec.Remember.Choice() == session.PersistentSession) != remember || (out.Issuance.Cookie.MaxAge > 0) != remember || out.Issuance.Cookie.Value != "" || !out.Issuance.Cookie.Secure || !out.Issuance.Cookie.HttpOnly {
		t.Fatal("original remember choice or cookie policy changed")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, out.Issuance.Token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("issued verification session cannot authenticate", err)
	}
	again, err := owner.VerificationConfirmAndSignin(ctx, request)
	if err != nil || !again.Verification.Replayed || again.Issuance.Token != (session.Token{}) || again.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("confirmation retry reissued credentials", err)
	}
	// Recovery is metadata-only and remains separately authorized for the child.
	queryCaller := caller.Clone()
	queryCaller.Request.Action = "identity.email.verification-signin"
	queryCaller.Request.Resource.ID = authorization.ResourceID(out.Recovery.UserID)
	recovered, err := owner.VerificationSigninRecover(ctx, out.Recovery, queryCaller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("child signin metadata recovery", err)
	}
	logoutID, _ := identity.NewCommandID()
	signedOut, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: logoutID, CorrelationID: string(logoutID), Transport: session.CredentialCookie, Credential: credential}, out.CSRFToken)
	if err != nil || !signedOut.SignedOut || !signedOut.ClearCookie || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("verification session cannot logout", err)
	}
	current, err = sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err == nil && current.Authenticated {
		t.Fatal("verification session remained authenticated after logout")
	}
}
