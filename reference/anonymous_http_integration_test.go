//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This is the application's declared policy, not credential/session authority.
// Real native owners still establish every possession and protected transition.
type referenceAnonymousPolicy struct{}

func (referenceAnonymousPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && (strings.HasPrefix(string(c.Request.Action), "identity.anonymous.") || c.Request.Action == "identity.user.create" && c.Request.Subject.Kind == authorization.SubjectServiceAccount) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceAnonymous(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	p := c.PasswordSignin.Native
	policy, err := anonymous.NewPolicy(anonymous.Config{DisplayName: "Guest", PlaceholderEmailDomain: "anonymous.invalid", TTL: 24 * time.Hour, Cleanup: anonymous.CleanupAnonymize})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_guest", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{201}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{202}, 32))
	if err != nil {
		t.Fatal(err)
	}
	query := c.OTP.RequestKeys.Policy
	requestKeys, err := kernel.NewRequestKeyConfig("reference-anonymous", [32]byte{203}, query)
	if err != nil {
		t.Fatal(err)
	}
	config := anonymouspg.Config{Schema: "anonymous_store", MaximumDuration: 2 * time.Second}
	profile := sessionpg.AnonymousAdmissionConfig{GlobalAuthorityID: p.Profile.GlobalAuthorityID, PolicyNamespace: p.Profile.PolicyNamespace, Audience: p.Profile.Audience}
	preauth := *c.PasswordSignin.PreAuth
	preauth.CallbackURL = ""
	issuer := session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}
	counters := c.PasswordSignup.Counters
	commandCounters := *counters.CommandCounters
	commandCounters.Policy = c.Velocity.Native.Policy
	counters.CommandCounters = &commandCounters
	retention, err := identity.NewPolicyEvaluator(identity.PolicySet{Authorize: query.Authorization, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
		return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
	}, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
	}, DecideRetention: func(_ context.Context, in identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		d := identity.RetentionAllow
		if in.LegalHold {
			d = identity.RetentionBlockLegalHold
		}
		return identity.RetentionPolicyDecision{Disposition: d, PolicyID: "guest-retention", PolicyVersion: 9, Reasons: []identity.PolicyReason{"self-request"}}, nil
	}}, identity.PolicyEvaluatorConfig{PolicyID: "guest-retention", PolicyVersion: 9, Reasons: []identity.PolicyReason{"self-request"}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.Anonymous = &reference.AnonymousConfiguration{Signin: anonymouspg.SigninConfig{Repository: config, Sessions: p.Session, Profile: profile, Policy: policy, ConfigurationID: "reference-anonymous-v1", PolicyID: "anonymous-signin", DisplayNameField: "name", Fields: c.PasswordSignup.Native.Fields, FieldSchema: c.PasswordSignup.Native.FieldSchema, FlowKeys: p.FlowKeys, Origins: []string{origin}, CallbackURLs: []string{""}, RequestKeys: requestKeys, IntentKey: [32]byte{204}, ActiveEnvelopeKeyID: "issue-envelope", Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "anonymous-risk", Keys: c.OTP.RiskKeys}, Coordinator: p.Coordinator, Issuer: issuer, CSRF: csrf}, Validation: validation, PreAuth: preauth, Deletion: &anonymouspg.DeletionConfig{Repository: config, Sessions: p.Session, Profile: profile, CSRFKeys: []session.CSRFKey{csrf}, Origins: []string{origin}, Reasons: []string{"self-request"}, ConfigurationID: "reference-anonymous-delete-v1", PolicyID: "anonymous-delete", Retention: retention, RetentionPolicyVersion: 9, RequestKeys: requestKeys, Coordinator: p.Coordinator, Risk: counters, IntentKey: [32]byte{205}, ActiveEnvelopeKeyID: "issue-envelope"}}
	c.HTTPAnonymous = &reference.HTTPAnonymousConfiguration{Signin: true, Read: true, Deletion: true, SecretNamespace: "reference-anonymous-secret", SecretKey: [32]byte{206}}
}

func TestReferencePostgresAnonymousSigninReadDeleteHTTP(t *testing.T) {
	proveReferenceAnonymousHTTP(t, false, false)
}

func TestReferencePostgresAnonymousUpgradeHTTP(t *testing.T) {
	proveReferenceAnonymousHTTP(t, true, false)
}

func TestReferencePostgresAnonymousNativeWithoutHTTP(t *testing.T) {
	proveReferenceAnonymousHTTP(t, false, true)
}

func proveReferenceAnonymousHTTP(t *testing.T, upgrade, nativeOnly bool) {
	t.Helper()
	ctx, stop := context.WithTimeout(t.Context(), 60*time.Second)
	defer stop()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	configureReferenceSignin(t, &c)
	network := httptest.NewUnstartedServer(nil)
	t.Cleanup(network.Close)
	origin := "https://" + network.Listener.Addr().String()
	c.OTP.PreAuth.Origin, c.OTP.PreAuth.ActorID = origin, "AAAAAAAAAAAAAAAAAAAAAw"
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "anonymous-reference", IdentifierKey: [32]byte{207}, MaximumDuration: time.Second, Timeout: time.Second, LockTimeout: time.Second, RollbackTimeout: time.Second}
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	deviceKey, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{208}, 32))
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "reference-anonymous", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}}
	configureReferencePasswordResetPolicy(t, &c, origin, f.pool, 9, true)
	screens := configureReferenceRegistration(t, &c, origin, referenceAnonymousPolicy{})
	// This graph uses risk revision 9 for both admission and candidate
	// screening. The reusable registration helper defaults its separate
	// baseline profile to revision 3; native screening rejects mixed revisions.
	c.PasswordSignup.Native.Screening.Policy = registrationRiskPolicy(t, 9, true)
	c.PasswordSignup.Native.Screening.Collect, screens = registrationScreening(t, c.PasswordSignup.Native.Screening.Policy)
	p := c.PasswordSignin.Native
	c.Session = &reference.SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: p.Session, Profile: sessionpg.IssueAdmissionConfig(p.Profile), Coordinator: p.Coordinator, Authorization: c.OTP.RequestKeys.Policy.Authorization, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: p.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{p.Issuance.LookupKey}}, Cookie: p.Issuance.Cookie, MaximumDuration: 3 * time.Second}, CSRFKeys: []session.CSRFKey{p.CSRFKey}}
	c.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "anonymous-reference-safe", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
		t.Error("unexpected degraded rate owner")
		return nil
	}}
	configureReferenceAnonymous(t, &c, origin)
	messages := make(chan string, 4)
	deps.DeliverySender = nativeBrowserCodeSender{codes: messages}
	if upgrade {
		configureReferencePasswordProtection(t, &c, origin)
		c.PasswordChange, c.HTTPPasswordChange = nil, nil
		c.PasswordVerification.Native.Targets = []passwordpg.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: "identity.anonymous.upgrade", Audience: p.Profile.Audience}}
		issuer := c.PasswordSignup.Issuer
		issuer.Audience = p.Profile.Audience
		c.Anonymous.Upgrade = &reference.AnonymousUpgradeConfiguration{Primary: passwordpg.ActionPrimaryConfig{Action: "identity.anonymous.upgrade", Audience: p.Profile.Audience, MaximumAge: time.Minute, Transport: session.CredentialCookie}, ProofAudience: p.Profile.Audience, Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: p.Issuance.LookupKey, TokenSize: 32, Cookie: p.Issuance.Cookie}, CSRF: p.CSRFKey, Capability: issuer, CapabilityPreparation: c.PasswordSignup.Preparation}
		c.HTTPAnonymous.Upgrade = true
	}
	if !upgrade {
		// Independent anonymous transport must bootstrap its own dependencies,
		// not borrow atomic rate history from unrelated authentication routes.
		c.HTTPPasswordReset, c.HTTPPasswordSignin, c.HTTPPasswordSignup = nil, nil, nil
		c.HTTPRegistrationVerification = nil
	}
	if nativeOnly {
		c.HTTPAnonymous, c.HTTPPreAuth, c.HTTPRate, c.HTTPSession = nil, nil, nil, nil
	}
	selectDurableReferenceAdmission(&c)
	if upgrade {
		lookup, err := session.NewDigestKey(2, bytes.Repeat([]byte{209}, 32))
		if err != nil {
			t.Fatal(err)
		}
		csrf, err := session.NewCSRFKey(2, bytes.Repeat([]byte{210}, 32))
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-unreadable_upgrade", SameSite: http.SameSiteLaxMode})
		if err != nil {
			t.Fatal(err)
		}
		candidate := func() reference.StoreConfiguration {
			selected := c
			a := *c.Anonymous
			u := *a.Upgrade
			a.Upgrade = &u
			selected.Anonymous = &a
			return selected
		}
		for _, mismatch := range []struct {
			name string
			set  func(*reference.AnonymousUpgradeConfiguration)
		}{
			{"lookup-key", func(u *reference.AnonymousUpgradeConfiguration) { u.Issuer.LookupKey = lookup }},
			{"csrf-key", func(u *reference.AnonymousUpgradeConfiguration) { u.CSRF = csrf }},
			{"cookie-policy", func(u *reference.AnonymousUpgradeConfiguration) { u.Issuer.Cookie = cookie }},
		} {
			t.Run("reject-unreadable-upgrade/"+mismatch.name, func(t *testing.T) {
				selected := candidate()
				mismatch.set(selected.Anonymous.Upgrade)
				stores, err := reference.ComposeStores(selected, deps)
				if err == nil {
					if closeErr := stores.Close(ctx); closeErr != nil {
						t.Error("rejected-candidate cleanup", closeErr)
					}
					t.Fatal("composition admitted an unreadable upgrade issuer")
				}
			})
		}
		// Selecting a retained issuer is valid when reading/signout retain both
		// original and rotated custody. Prove this through the full journey.
		selected := candidate()
		sessions := *c.Session
		sessions.Native.Validation.LookupKeys = append(append([]session.DigestKey{}, sessions.Native.Validation.LookupKeys...), lookup)
		sessions.CSRFKeys = append(append([]session.CSRFKey{}, sessions.CSRFKeys...), csrf)
		selected.Session = &sessions
		selected.Anonymous.Upgrade.Issuer.LookupKey = lookup
		selected.Anonymous.Upgrade.CSRF = csrf
		c = selected
		if t.Failed() {
			return
		}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("anonymous graph configuration", invalid.Field)
		}
		t.Fatal("anonymous graph", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(bounded, `DROP OWNED BY audit_writer,audit_reader,audit_retention;DROP ROLE audit_writer,audit_reader,audit_retention`); err != nil {
			t.Error("audit role cleanup", err)
		}
	})
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity", "identity/anonymous/postgres"}
	if c.HTTPRate != nil {
		modules = append(modules, "rate-limit/postgres")
	}
	apply := applyRequest(t, ctx, stores, modules)
	if out, err := stores.ReferenceMigrationApply(ctx, apply); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("selected anonymous native histories", err, out.Result.State())
	}
	if nativeOnly {
		proveReferenceAnonymousNative(t, ctx, stores, features, c.Anonymous.PreAuth.ActorID, origin)
		return
	}
	policies := identity.PolicySet{Authorize: c.OTP.RequestKeys.Policy.Authorization, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
		return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
	}, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
	}, DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
	}}
	server, err := reference.NewServer(reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Anonymous reference", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: &nativeServerTenant{}}}, deps, features)
	if err != nil {
		t.Fatal("anonymous server", err)
	}
	network.Config.Handler = server.Handler()
	network.StartTLS()
	client := network.Client()
	client.Timeout = 5 * time.Second
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if ready := server.Readiness(ctx); !ready.Ready {
		t.Fatal("selected guest schema readiness", ready.Failures)
	}
	call := func(method, path, body, key, csrf string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, network.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
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
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(wire) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("bounded guest response")
		}
		return response, wire
	}
	response, wire := call("POST", "/v1/session/preauth-issue", `{"method":"anonymous"}`, "", "", nil)
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued {
		t.Fatal("guest preauth", response.StatusCode)
	}
	cookies := response.Cookies()
	body, _ := json.Marshal(map[string]string{"flowID": string(flow.FlowID), "callbackURL": ""})
	response, wire = call("POST", "/v1/anonymous/signin", string(body), "original-reference-guest", "", cookies)
	var signin anonymoushttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &signin) != nil || !signin.SignedIn {
		t.Fatal("guest HTTP signin", response.StatusCode, signin.Error)
	}
	guestCSRF := response.Header.Get("X-CSRF-Token")
	guestCookies := response.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "__Host-identity_device" {
			guestCookies = append(guestCookies, cookie)
		}
	}
	response, wire = call("GET", "/v1/session/get", "", "", "", guestCookies)
	var read sessionhttp.GetResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || read.Authenticated || read.Anonymous == nil || !read.Anonymous.Recognized {
		t.Fatal("explicit guest recognition", response.StatusCode)
	}
	response, wire = call("POST", "/v1/anonymous/delete", `{"expectedVersion":1,"reason":"self-request"}`, "original-reference-delete", guestCSRF, guestCookies)
	var deleted anonymoushttp.DeletionResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &deleted) != nil || !deleted.Deleted {
		t.Fatal("guest HTTP deletion", response.StatusCode, deleted.Error)
	}
	response, wire = call("POST", "/v1/anonymous/delete", `{"expectedVersion":1,"reason":"self-request"}`, "original-reference-delete", guestCSRF, guestCookies)
	var deletionReplay anonymoushttp.DeletionResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &deletionReplay) != nil || !deletionReplay.Deleted || !deletionReplay.Replayed || deletionReplay.CommandID != deleted.CommandID || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("original deletion retry repeated or lost the native command", response.StatusCode, deletionReplay.Error)
	}
	anonymousOwner, err := features.Anonymous()
	if err != nil || deleted.Recovery == nil {
		t.Fatal("selected public anonymous recovery handle", err)
	}
	guestCustody := func(cookies []*http.Cookie, csrf string) (session.Credential, session.CSRFToken, string) {
		t.Helper()
		codec, e := session.NewBrowserDeviceCodec(*c.HTTPPreAuth.Device)
		if e != nil {
			t.Fatal(e)
		}
		var credential session.Credential
		var deviceID string
		for _, cookie := range cookies {
			if cookie.Name == "__Host-identity_guest" {
				token, e := session.ParseToken(cookie.Value)
				if e != nil {
					t.Fatal("original guest token")
				}
				credential, e = session.NewCredential(session.CredentialCookie, token)
				if e != nil {
					t.Fatal(e)
				}
			}
			if cookie.Name == "__Host-identity_device" {
				device, e := codec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
				if e != nil {
					t.Fatal("original signed browser device")
				}
				deviceID = device.DeviceID()
			}
		}
		synchronizer, e := session.ParseCSRFToken(csrf)
		if e != nil || credential == (session.Credential{}) || deviceID == "" {
			t.Fatal("original guest recovery custody absent")
		}
		return credential, synchronizer, deviceID
	}
	query := func(q *anonymoushttp.CommandRecovery) identity.RecoveryQuery {
		return identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID}
	}
	credential, synchronizer, deviceID := guestCustody(guestCookies, guestCSRF)
	recoveryRequest := anonymous.DeletionRecoveryRequest{Recovery: query(deleted.Recovery), Credential: credential, CSRFToken: synchronizer, Origin: origin, Network: "127.0.0.1", Device: deviceID}
	recoveredDeletion, err := anonymousOwner.RecoverDeletion(ctx, recoveryRequest)
	if err != nil || recoveredDeletion.Outcome != identity.CommitOutcomeCommitted || !recoveredDeletion.Replayed || recoveredDeletion.Recovery != recoveryRequest.Recovery {
		t.Fatal("public original deletion recovery", err)
	}
	foreignRecovery := recoveryRequest
	foreignRecovery.Recovery.TenantID = "foreign"
	if _, err := anonymousOwner.RecoverDeletion(ctx, foreignRecovery); err == nil {
		t.Fatal("foreign tenant disclosed guest deletion history")
	}
	response, wire = call("GET", "/v1/session/get", "", "", "", guestCookies)
	read = sessionhttp.GetResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || read.Authenticated || read.Anonymous != nil {
		t.Fatal("deleted guest still recognized", response.StatusCode)
	}
	if !upgrade {
		if err := stores.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := anonymousOwner.RecoverDeletion(ctx, recoveryRequest); err == nil {
			t.Fatal("closed reference graph still disclosed native history")
		}
		return
	}
	// The permanent target is created, delivered and verified through real
	// public workflows before password signin. No authority/proof rows are seeded.
	response, wire = call("POST", "/v1/session/preauth-issue", `{"method":"signup"}`, "", "", nil)
	var registration sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &registration) != nil || !registration.Issued {
		t.Fatal("target registration initiation", response.StatusCode)
	}
	registrationBody, _ := json.Marshal(map[string]string{"flowID": string(registration.FlowID), "email": "upgrade-target@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"})
	registrationCookies := response.Cookies()
	response, wire = call("POST", "/v1/password/signup", string(registrationBody), "upgrade-target-signup", "", registrationCookies)
	var signup passwordhttp.SignupResponse
	if decode := json.Unmarshal(wire, &signup); response.StatusCode != 200 || decode != nil || !signup.VerificationRequired {
		t.Fatal("target registration", response.StatusCode, signup.Error, signup.CommitOutcome, "decode", decode, "screening", screens.Load())
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("target verification delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("target verification delivery absent")
	}
	delivered, err := url.Parse(link)
	if err != nil || delivered.Scheme != "https" || delivered.Query().Get("token") == "" {
		t.Fatal("invalid native target verification delivery")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	confirmation, _ := json.Marshal(map[string]string{"token": delivered.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(command)})
	response, wire = call("POST", "/v1/email/verification-confirm", string(confirmation), "", "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &confirmed) != nil || !confirmed.Confirmed {
		t.Fatal("target verification", response.StatusCode, confirmed.Error)
	}
	// Preserve the new guest's signed device throughout target signin and proof
	// issuance, so both sessions genuinely belong to this browser.
	response, wire = call("POST", "/v1/session/preauth-issue", `{"method":"anonymous"}`, "", "", nil)
	flow = sessionhttp.PreAuthResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued {
		t.Fatal("upgrade guest initiation", response.StatusCode)
	}
	cookies = response.Cookies()
	body, _ = json.Marshal(map[string]string{"flowID": string(flow.FlowID), "callbackURL": ""})
	response, wire = call("POST", "/v1/anonymous/signin", string(body), "upgrade-original-guest", "", cookies)
	signin = anonymoushttp.SigninResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &signin) != nil || !signin.SignedIn {
		t.Fatal("upgrade guest signin", response.StatusCode, signin.Error)
	}
	guestCSRF, guestCookies = response.Header.Get("X-CSRF-Token"), response.Cookies()
	var device []*http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "__Host-identity_device" {
			device = append(device, cookie)
		}
	}
	guestCookies = append(guestCookies, device...)
	response, wire = call("GET", "/v1/session/get", "", "", "", guestCookies)
	read = sessionhttp.GetResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || read.Anonymous == nil || !read.Anonymous.Recognized {
		t.Fatal("upgrade original guest recognition", response.StatusCode)
	}
	guestID := read.Anonymous.Principal.UserID
	response, wire = call("POST", "/v1/session/preauth-issue", `{"method":"password"}`, "", "", device)
	var targetFlow sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &targetFlow) != nil || !targetFlow.Issued {
		t.Fatal("target signin initiation", response.StatusCode)
	}
	loginBody, _ := json.Marshal(map[string]string{"flowID": string(targetFlow.FlowID), "identifier": "upgrade-target@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"})
	response, wire = call("POST", "/v1/password/signin", string(loginBody), "", "", append(response.Cookies(), device...))
	var targetLogin passwordhttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &targetLogin) != nil || !targetLogin.SignedIn {
		t.Fatal("permanent target signin", response.StatusCode, targetLogin.Error)
	}
	targetCookies, targetCSRF := append(response.Cookies(), device...), response.Header.Get("X-CSRF-Token")
	verificationBody, _ := json.Marshal(map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": "identity.anonymous.upgrade", "audience": p.Profile.Audience})
	response, wire = call("POST", "/v1/password/verify", string(verificationBody), "", targetCSRF, targetCookies)
	var verified passwordhttp.VerificationResponse
	if response.StatusCode != 200 || json.Unmarshal(wire, &verified) != nil || !verified.Verified || verified.Proof == nil {
		t.Fatal("upgrade target action-bound proof", response.StatusCode, verified.Error)
	}
	upgradeBody, _ := json.Marshal(map[string]any{"guestID": guestID, "expectedVersion": 1, "proofID": verified.Proof.ProofID, "conflicts": []any{}})
	request, err := http.NewRequestWithContext(ctx, "POST", network.URL+"/v1/anonymous/upgrade", bytes.NewReader(upgradeBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Idempotency-Key", "reference-guest-upgrade")
	request.Header.Set("X-CSRF-Token", guestCSRF)
	request.Header.Set("X-Target-CSRF-Token", targetCSRF)
	for _, cookie := range guestCookies {
		request.AddCookie(cookie)
	}
	for _, cookie := range targetCookies {
		if cookie.Name == "__Host-session" {
			request.AddCookie(cookie)
		}
	}
	upgradeCall := func(key, targetSynchronizer string) (*http.Response, anonymoushttp.UpgradeResponse) {
		t.Helper()
		r := request.Clone(ctx)
		r.Body, err = request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Idempotency-Key", key)
		if key == "" {
			r.Header.Del("Idempotency-Key")
		}
		r.Header.Set("X-Target-CSRF-Token", targetSynchronizer)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		var result anonymoushttp.UpgradeResponse
		decode := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&result)
		closed := response.Body.Close()
		if decode != nil || closed != nil || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("bounded upgrade response")
		}
		return response, result
	}
	for _, denial := range []struct {
		key, csrf string
		status    int
	}{{"", targetCSRF, 400}, {"upgrade-wrong-target-csrf", guestCSRF, 0}} {
		r, result := upgradeCall(denial.key, denial.csrf)
		// The native owner intentionally redacts some invalid proof/custody
		// failures as unavailable. Neither classification permits an effect or
		// credential delivery; do not reinterpret an opaque outcome as rollback.
		statusDenied := r.StatusCode == denial.status
		if denial.status == 0 {
			statusDenied = r.StatusCode == 403 || r.StatusCode == 503
		}
		if !statusDenied || result.Upgraded || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("upgrade request custody bypass", r.StatusCode, result.Error)
		}
	}
	// Fail only the protected consuming transition's required outbox effect;
	// the separate native issuance preparation is allowed to commit unchanged.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION anonymous_upgrade_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
IF NEW.topic='anonymous.upgraded.v1' THEN RAISE EXCEPTION 'synthetic anonymous upgrade rollback'; END IF; RETURN NEW; END $$;
CREATE TRIGGER anonymous_upgrade_fixture_fail BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION anonymous_upgrade_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	r, failed := upgradeCall("reference-guest-upgrade-rollback", targetCSRF)
	if r.StatusCode == 200 || failed.Upgraded || failed.CommitOutcome != "not_committed" || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("upgrade required-effect rollback", r.StatusCode, failed.Error, failed.CommitOutcome)
	}
	var transitions, revoked, proofs int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM anonymous_store.upgrades WHERE tenant_id=$1),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND consumed_command_id IS NOT NULL)`, otpTenant, string(guestID)).Scan(&transitions, &revoked, &proofs); err != nil || transitions != 0 || revoked != 0 || proofs != 0 {
		t.Fatal("upgrade rollback leaked protected effects", err, transitions, revoked, proofs)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER anonymous_upgrade_fixture_fail ON public.outbox_messages; DROP FUNCTION anonymous_upgrade_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	response, upgraded := upgradeCall("reference-guest-upgrade", targetCSRF)
	if response.StatusCode != 200 || !upgraded.Upgraded || upgraded.CommitOutcome != "committed" || upgraded.Recovery == nil || upgraded.Preparation == nil {
		t.Fatal("guest upgrade HTTP", response.StatusCode, upgraded.Error, upgraded.CommitOutcome)
	}
	var permanent []*http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-session" {
			permanent = append(permanent, cookie)
		}
		if cookie.Name == "__Host-identity_guest" && cookie.MaxAge != -1 {
			t.Fatal("upgrade did not clear the guest cookie")
		}
	}
	permanentCSRF := response.Header.Get("X-CSRF-Token")
	if len(permanent) != 1 || permanentCSRF == "" {
		t.Fatal("fresh upgrade omitted permanent credential custody")
	}
	permanent = append(permanent, device...)
	r, replay := upgradeCall("reference-guest-upgrade", targetCSRF)
	if r.StatusCode != 200 || replay.Upgraded || !replay.Replayed || replay.CommitOutcome != "committed" || replay.Preparation == nil || replay.Recovery == nil || *replay.Preparation != *upgraded.Preparation || *replay.Recovery != *upgraded.Recovery || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("upgrade same-key retry reissued credentials or changed command", r.StatusCode, replay.Error)
	}
	r, used := upgradeCall("reference-guest-upgrade-reused-proof", targetCSRF)
	if r.StatusCode == 200 || used.Upgraded || len(r.Cookies()) != 0 {
		t.Fatal("one-use target proof admitted another command", r.StatusCode)
	}
	credential, synchronizer, deviceID = guestCustody(guestCookies, guestCSRF)
	targetSynchronizer, err := session.ParseCSRFToken(targetCSRF)
	if err != nil {
		t.Fatal(err)
	}
	var targetCredential auth.BearerCredential
	for _, cookie := range targetCookies {
		if cookie.Name == "__Host-session" {
			targetCredential = auth.NewBearerCredential(cookie.Value)
		}
	}
	historical, err := anonymousOwner.RecoverUpgrade(ctx, anonymous.UpgradeRecoveryRequest{Preparation: query(upgraded.Preparation), Recovery: query(upgraded.Recovery), TargetSession: targetCredential, TargetCSRF: targetSynchronizer, Guest: credential, GuestCSRF: synchronizer, Origin: origin, Network: "127.0.0.1", Device: deviceID})
	if err != nil || historical.Outcome != identity.CommitOutcomeCommitted || !historical.Replayed || historical.Session.Token != (session.Token{}) || historical.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("public upgrade recovery lost outcome or redelivered", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM anonymous_store.upgrades WHERE tenant_id=$1),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND consumed_command_id IS NOT NULL)`, otpTenant, string(guestID)).Scan(&transitions, &revoked, &proofs); err != nil || transitions != 1 || revoked != 1 || proofs != 1 {
		t.Fatal("upgrade omitted or duplicated protected effects", err, transitions, revoked, proofs)
	}
	response, wire = call("GET", "/v1/session/get", "", "", "", guestCookies)
	read = sessionhttp.GetResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || read.Authenticated || read.Anonymous != nil {
		t.Fatal("upgraded guest custody retained authority", response.StatusCode)
	}
	response, wire = call("GET", "/v1/session/get", "", "", "", permanent)
	read = sessionhttp.GetResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || !read.Authenticated || read.Anonymous != nil {
		t.Fatal("upgraded permanent session was not authenticated", response.StatusCode)
	}
	response, _ = call("POST", "/v1/session/signout", `{}`, "", permanentCSRF, permanent)
	if response.StatusCode != 200 {
		t.Fatal("upgraded permanent logout", response.StatusCode)
	}
	response, wire = call("GET", "/v1/session/get", "", "", "", permanent)
	read = sessionhttp.GetResponse{}
	if response.StatusCode != 200 || json.Unmarshal(wire, &read) != nil || read.Authenticated || read.Anonymous != nil {
		t.Fatal("upgraded session survived logout", response.StatusCode)
	}
}

func proveReferenceAnonymousNative(t *testing.T, ctx context.Context, stores reference.StoreSet, features reference.FeatureSet, actor identity.ActorID, origin string) {
	t.Helper()
	preauth, err := features.AnonymousPreAuth()
	if err != nil {
		t.Fatal("native-only anonymous initiation", err)
	}
	owner, err := features.Anonymous()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	input := session.PreAuthPrepareInput{CommandID: id, TenantID: otpTenant, CorrelationID: string(id), Remember: remember}
	if _, err := preauth.Prepare(ctx, input); err == nil {
		t.Fatal("uninitialized native graph prepared anonymous flow")
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	foreign := input
	foreign.TenantID = "foreign"
	if _, err := preauth.Prepare(ctx, foreign); err == nil {
		t.Fatal("foreign tenant prepared anonymous flow")
	}
	prepared, err := preauth.Prepare(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	command, ok := prepared.Command()
	if !ok {
		t.Fatal("native anonymous initiation omitted command custody")
	}
	issued, err := preauth.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("native anonymous initiation", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil || flow.Binding.Intent.Action != "identity.anonymous.signin" {
		t.Fatal("native anonymous flow changed action", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-only-anonymous-signin"))
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(actor)}, Action: "identity.anonymous.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.anonymous.signin"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	signed, err := owner.Signin(ctx, anonymous.SigninRequest{TenantID: otpTenant, PreAuthID: flow.Binding.ID, Cookie: auth.NewBearerCredential(wire), Remember: remember, Origin: origin, Caller: caller, Network: "127.0.0.1", Device: "native-anonymous-browser", IdempotencyKey: key})
	if err != nil || signed.Outcome != identity.CommitOutcomeCommitted || signed.Replayed {
		t.Fatal("native anonymous signin without HTTP", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, signed.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	read, err := owner.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !read.Recognized {
		t.Fatal("native anonymous recognition", err)
	}
	key, err = identity.NewIdempotencyKey([]byte("native-only-anonymous-delete"))
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := owner.Delete(ctx, anonymous.DeletionRequest{TenantID: otpTenant, Credential: credential, CSRFToken: signed.CSRFToken, ExpectedVersion: 1, Reason: "self-request", Origin: origin, Network: "127.0.0.1", Device: "native-anonymous-browser", IdempotencyKey: key})
	if err != nil || deleted.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native anonymous deletion", err)
	}
	read, err = owner.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || read.Recognized {
		t.Fatal("native deleted guest retained authority", err)
	}
	history, err := preauth.Recover(ctx, command)
	if err != nil || history.CommitOutcome != identity.CommitOutcomeCommitted || !history.Replayed || history.Token != (session.Token{}) {
		t.Fatal("native initiation recovery renewed custody", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := preauth.Prepare(ctx, input); err == nil {
		t.Fatal("retained anonymous initiator survived graph close")
	}
	if _, err := features.AnonymousPreAuth(); err == nil {
		t.Fatal("closed graph exported anonymous initiator")
	}
}
