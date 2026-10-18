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
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
	primitive "github.com/faustbrian/go-password/v2"
)

type referenceUsernamePolicy struct{}

func (referenceUsernamePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 {
		if c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" {
			switch c.Request.Action {
			case "identity.username.signup", "identity.username.signup.recover", "identity.username.signin", "identity.username.signin.recover":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
		if c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.username.update" || c.Request.Action == "identity.username.update.recover") && (c.Request.Resource.Type == "identity.user" && string(c.Request.Resource.ID) == string(c.Request.Subject.ID) || c.Request.Resource.Type == "identity.request-admission" && string(c.Request.Resource.ID) == string(c.Request.Action)) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceUsername(t *testing.T, c *reference.StoreConfiguration, origin string, totp ...bool) {
	t.Helper()
	configureReferencePasswordProtection(t, c, origin)
	c.PasswordChange, c.HTTPPasswordChange = nil, nil
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.username.update", Audience: "reference-username-rename"}
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, target)
	policy := registrationRiskPolicy(t, 9, true, true)
	emailScreen, _ := registrationScreening(t, policy)
	usernameScreen, _ := registrationScreening(t, policy, "identity.username.signup")
	c.PasswordSignup.Native.Screening.Policy = policy
	c.PasswordSignup.Native.Screening.Collect = func(ctx context.Context, scope risk.Context, secret primitive.Secret) ([]risk.Signal, error) {
		if scope.Operation == "identity.username.signup" {
			return usernameScreen(ctx, scope, secret)
		}
		return emailScreen(ctx, scope, secret)
	}
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	domain := kernel.UsernameRenameDomainConfig{NormalizationProfile: string(username.ProfileID), NormalizationVersion: username.ProfileVersion, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {122}}, ReuseCooldown: 30 * 24 * time.Hour}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{203}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	available := passwordpg.UsernameAvailabilityConfig{Domain: domain, Counters: riskpg.DurableCounterConfig{Schema: c.Velocity.Schema, Namespace: "reference-username-available", Policy: registrationRiskPolicy(t, 9, false), Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{204}, 32), Tenants: []string{otpTenant}, MaximumRecords: 1000, Timeout: time.Second}, PolicyID: string(policyID), MaximumDuration: 3 * time.Second, RiskTimeout: 2 * time.Second, OnAuditLoss: func(context.Context, risk.DecisionDelivery) error { return nil }}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-username-rename", [32]byte{201}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	counters := c.PasswordSignup.Counters
	counters.EnforceLockouts = true
	shared := registrationRiskPolicy(t, 9, false)
	c.Velocity.Native.Policy = shared
	commands := *counters.CommandCounters
	commands.Policy = shared
	counters.CommandCounters = &commands
	c.Username = &reference.UsernameConfiguration{Policy: p, Signup: true, Signin: true, Availability: &available, Rename: &reference.UsernameRenameConfiguration{Primary: passwordpg.ActionPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: c.PasswordVerification.CSRFKeys}, Native: passwordpg.UsernameRenameConfig{PolicyID: "reference-username-rename", ConfigurationID: "reference-username-rename-v1", MaximumDuration: 4 * time.Second, Domain: domain, RequestKeys: requestKeys, IntentKey: [32]byte{202}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-username-rename-v1", Keys: c.OTP.RiskKeys}, Counters: counters, ActiveEnvelopeKeyID: "issue-envelope"}}}
	c.HTTPUsername = &reference.HTTPUsernameConfiguration{Signup: true, Signin: true, Availability: true, ActorID: c.HTTPPasswordSignup.ActorID, PolicyRevision: 9, Rename: &reference.HTTPPasswordProtectionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-username-rename", RateKey: [32]byte{205}}}
	if len(totp) == 1 && totp[0] {
		configureReferenceMFAEnrollment(t, c, origin)
		configureReferencePasswordMFA(t, c, origin)
		c.Username.TOTP = &reference.UsernameTOTPConfiguration{Challenge: *c.PasswordSignin.MFA, Completion: *c.PasswordSignin.TOTP}
		c.HTTPMFA.UsernameTOTPVerify = true
	}
}

func TestReferencePostgresUsernameHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, username: true})
}

func TestReferencePostgresUsernameTOTPHTTPS(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "browser"
		if persistent {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, username: true, usernameTOTP: true, usernameTOTPPersistent: persistent})
		})
	}
}

func TestReferencePostgresUsernameTOTPCommitRecoveryHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, username: true, usernameTOTP: true, completionCommitFault: true})
}

func TestReferencePostgresUsernameTOTPIndependentHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, username: true, usernameTOTP: true, usernameTOTPOnly: true})
}

func TestReferencePostgresUsernameTOTPWithdrawalsHTTPS(t *testing.T) {
	for _, authority := range []string{"user", "identifier", "factor"} {
		t.Run(authority, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, username: true, usernameTOTP: true, usernameTOTPWithdrawal: authority})
		})
	}
}

// The existing graph/bootstrap/worker fixture supplies actual native owners.
// Only external HIBP IO and the application's email sender are controlled.
func proveReferenceUsername(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	call := func(method, path string, body any, key, csrf string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		var input []byte
		if body != nil {
			var err error
			input, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("username response custody")
		}
		return response, payload
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, data := call("POST", "/v1/session/preauth-issue", map[string]string{"method": method}, "", "", nil)
		var out sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(data, &out) != nil || !out.Issued {
			t.Fatal("username original flow", method, r.StatusCode)
		}
		return out, r.Cookies()
	}
	available := func(name string, want bool) {
		t.Helper()
		r, data := call("GET", "/v1/username/available?username="+url.QueryEscape(name), nil, "", "", nil)
		var out struct {
			Available bool `json:"available"`
		}
		if r.StatusCode != 200 || json.Unmarshal(data, &out) != nil || out.Available != want {
			t.Fatal("native advisory occupancy", r.StatusCode)
		}
	}
	// Both original registrations coexist in this same router/native graph.
	// Confirm a base email registration first, so username selection cannot
	// silently replace that owner's operation-specific encrypted input.
	emailFlow, emailCookies := issue("signup")
	emailResponse, emailData := call("POST", "/v1/password/signup", map[string]any{"flowID": string(emailFlow.FlowID), "email": "email-profile@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}, "email-profile-original", "", emailCookies)
	var emailSignup passwordhttp.SignupResponse
	if emailResponse.StatusCode != 200 || json.Unmarshal(emailData, &emailSignup) != nil || !emailSignup.VerificationRequired || len(emailResponse.Cookies()) != 0 {
		t.Fatal("username selection replaced email signup", emailResponse.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("coexisting email delivery", err)
	}
	var emailLink string
	select {
	case emailLink = <-messages:
	case <-ctx.Done():
		t.Fatal("coexisting email delivery absent")
	}
	emailURL, err := url.Parse(emailLink)
	if err != nil || emailURL.Query().Get("token") == "" {
		t.Fatal("coexisting email original proof absent")
	}
	emailCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	emailResponse, emailData = call("POST", "/v1/email/verification-confirm", map[string]string{"commandID": string(emailCommand), "token": emailURL.Query().Get("token"), "callback": origin + "/confirm"}, "", "", nil)
	var emailConfirmed emailhttp.ConfirmationResponse
	if emailResponse.StatusCode != 200 || json.Unmarshal(emailData, &emailConfirmed) != nil || !emailConfirmed.Confirmed || emailConfirmed.Address == nil || len(emailResponse.Cookies()) != 0 {
		t.Fatal("shared username graph lost email confirmation", emailResponse.StatusCode)
	}
	available("Straße", true)
	flow, cookies := issue("username-signup")
	body := map[string]any{"flowID": string(flow.FlowID), "email": "username@example.invalid", "username": "Straße", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}
	r, data := call("POST", "/v1/username/signup", body, "username-registration-original", "", cookies)
	var signup passwordhttp.SignupResponse
	decodeErr := json.Unmarshal(data, &signup)
	if r.StatusCode != 200 || decodeErr != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(r.Cookies()) != 0 {
		t.Fatal("username signup", r.StatusCode, signup.Error, "decode", decodeErr, "type", r.Header.Get("Content-Type"), "bytes", len(data), "outcome", signup.CommitOutcome, "correlated", signup.CommandID != "")
	}
	available("STRASSE", false)
	login := func(name string, want bool) (*http.Response, passwordhttp.SigninResponse, []*http.Cookie) {
		t.Helper()
		flow, cookies := issue("username")
		r, data := call("POST", "/v1/username/signin", map[string]any{"flowID": string(flow.FlowID), "username": name, "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, "", "", cookies)
		var out passwordhttp.SigninResponse
		if json.Unmarshal(data, &out) != nil || out.SignedIn != want || want && (r.StatusCode != 200 || len(r.Cookies()) != 1 || r.Header.Get("X-CSRF-Token") == "") || !want && (r.StatusCode != 403 || len(r.Cookies()) != 0) {
			t.Fatal("username signin", r.StatusCode, out.Error)
		}
		var browser []*http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "__Host-identity_device" {
				browser = append(browser, cookie)
			}
		}
		return r, out, browser
	}
	login("STRASSE", false)
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("username actual encrypted delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("username verification delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Query().Get("token") == "" {
		t.Fatal("username original delivery")
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r, data = call("POST", "/v1/email/verification-confirm", map[string]string{"commandID": string(id), "token": u.Query().Get("token"), "callback": origin + "/confirm"}, "", "", nil)
	var verified emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(data, &verified) != nil || !verified.Confirmed || verified.Address == nil || len(r.Cookies()) != 0 {
		t.Fatal("username original verification", r.StatusCode)
	}
	r, signed, browser := login("STRASSE", true)
	currentCookies, currentCSRF := append(browser, r.Cookies()...), r.Header.Get("X-CSRF-Token")
	if f.usernameTOTP {
		proveReferenceMFAEnrollment(t, ctx, f, features, client, base, origin, r.Cookies(), currentCSRF, signed.SessionID, false)
		return
	}
	readSession := func(cookies []*http.Cookie, want bool) sessionhttp.GetResponse {
		t.Helper()
		r, data := call("GET", "/v1/session/get", nil, "", "", cookies)
		var out sessionhttp.GetResponse
		if r.StatusCode != 200 || json.Unmarshal(data, &out) != nil || out.Authenticated != want {
			t.Fatal("username session authority", r.StatusCode)
		}
		return out
	}
	current := readSession(currentCookies, true)
	r, data = call("POST", "/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": "identity.username.update", "audience": "reference-username-rename"}, "", currentCSRF, currentCookies)
	var proof passwordhttp.VerificationResponse
	if r.StatusCode != 200 || json.Unmarshal(data, &proof) != nil || !proof.Verified || proof.Proof == nil {
		t.Fatal("username fresh proof", r.StatusCode, proof.Error)
	}
	// Trusted backend composition reads the actual public directory snapshot
	// for this freshly authenticated self principal. No application SQL/store
	// or caller-selected subject manufactures identifier/version custody.
	var identifier identity.IdentifierID
	var version, verification uint64
	if current.Principal == nil || current.Principal.TenantID != otpTenant || current.Principal.UserID != verified.Address.UserID {
		t.Fatal("username session changed confirmed self principal")
	}
	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: current.Principal.TenantID, UserID: current.Principal.UserID, MaximumIdentifiers: 128})
	if err != nil {
		t.Fatal("public native identifier snapshot", err)
	}
	for i, candidate := range snapshot.Identifiers {
		if candidate.Kind == identity.IdentifierUsername {
			if identifier != "" {
				t.Fatal("ambiguous username metadata")
			}
			identifier, version, verification = candidate.ID, candidate.Version, snapshot.Verifications[i].Version
		}
	}
	if identifier == "" {
		t.Fatal("public native username metadata absent")
	}
	rename := map[string]any{"proofID": proof.Proof.ProofID, "identifierID": identifier, "expectedIdentifierVersion": version, "expectedVerificationVersion": verification, "username": "renamed-name"}
	r, _ = call("POST", "/v1/username/update", rename, "username-rename-original", "", currentCookies)
	if r.StatusCode != 403 {
		t.Fatal("username rename bypassed CSRF", r.StatusCode)
	}
	r, data = call("POST", "/v1/username/update", rename, "username-rename-original", currentCSRF, currentCookies)
	var changed passwordhttp.UsernameRenameResponse
	if r.StatusCode != 200 || json.Unmarshal(data, &changed) != nil || !changed.Changed || changed.IdentifierVersion != version+1 || len(r.Cookies()) != 0 {
		t.Fatal("username protected rename", r.StatusCode, changed.Error)
	}
	readSession(currentCookies, false)
	r, data = call("POST", "/v1/username/update", rename, "username-rename-original", currentCSRF, currentCookies)
	var replay passwordhttp.UsernameRenameResponse
	if r.StatusCode != 200 || json.Unmarshal(data, &replay) != nil || !replay.Changed || replay.CommandID != changed.CommandID || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("username original rename recovery", r.StatusCode, replay.Error)
	}
	available("STRASSE", false)
	login("STRASSE", false)
	r, signed, browser = login("RENAMED-NAME", true)
	proveRegistrationSessionLogout(t, ctx, client, base, origin, append(browser, r.Cookies()...), r.Header.Get("X-CSRF-Token"), signed.SessionID, f, features)
}
