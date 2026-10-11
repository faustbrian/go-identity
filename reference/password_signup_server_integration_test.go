//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
)

type referenceRegistrationPolicy struct{}

func (referenceRegistrationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" {
		switch c.Request.Action {
		case "identity.password.signup", "identity.user.create", "identity.email.verification-confirm", "identity.password.signup.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.session.revoke-one" || c.Request.Action == "identity.session.revoke-one.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceResetPolicy{}).Decide(ctx, c)
}

func registrationRiskPolicy(t *testing.T, version uint64, screening bool) risk.Policy {
	t.Helper()
	c := risk.PolicyConfig{Version: version, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	if screening {
		c.HIBP = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup"}}
	}
	p, err := risk.NewPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Only provider IO is synthetic. The owned client derives padded SHA-1-prefix
// requests and binds results to the actual native command before hashing.
func registrationScreening(t *testing.T, policy risk.Policy) (func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error), *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || r.Header.Get("Add-Padding") != "true" || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
			t.Error("HIBP transport leaked candidate/custody")
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("0", 35)+":0\r\n")
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	owner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-reference/synthetic-registration", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1024, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: time.Second, PolicyVersion: "reference-signup-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 1024, DisableCache: true}, owner, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	native := checker.(*hibp.Client)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := native.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	provider, err := hibp.NewSignalProvider(native, policy)
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, b risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(b.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: "identity.password.signup", TenantID: identity.TenantID(b.Tenant), Action: b.Operation, Purpose: "signup", SubjectScope: "password-signup", PolicyVersion: "reference-signup-v1", ReplayID: command, Candidate: candidate})
		return []risk.Signal{signal}, err
	}, &calls
}

func configureReferenceRegistration(t *testing.T, c *reference.StoreConfiguration, origin string) *atomic.Int32 {
	t.Helper()
	query := kernel.CommandQueryPolicy{Authorization: referenceRegistrationPolicy{}, Clock: clock.System{}, PolicyVersion: 9}
	c.OTP.RequestKeys.Policy = query
	c.OTP.Signin.Coordinator.QueryPolicy = &query
	c.PasswordSignin.Native.Coordinator.QueryPolicy, c.PasswordSignin.Native.Coordinator.AdmissionPolicy = &query, &query
	n := c.PasswordReset.Native
	coordinator := n.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	schema := identity.AttributeSchema{ID: "reference-signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "registered"}}}}}
	fields, err := identity.NewAttributeProcessor(schema, query.Authorization, func(ctx context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, ctx.Err()
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 9, ValidateCanonicalUserID: func(ctx context.Context, user identity.UserID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := identity.ParseSubjectID(string(user)); err != nil {
			return err
		}
		return nil
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	callback := origin + "/confirm"
	verification, err := email.NewRegistrationVerificationPolicy(email.RegistrationVerificationConfig{Address: c.PasswordSignin.Native.Address, Issuer: origin, Audience: "email", MaximumLifetime: 5 * time.Minute, Redirects: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {118}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("reference-signup", bytes.Repeat([]byte{119}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{119}, 32))
	resolver, err := capability.NewKeySet([]capability.Key{{ID: "reference-signup", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-signup", [32]byte{120}, query)
	if err != nil {
		t.Fatal(err)
	}
	screening := n.Screening
	screening.Policy = registrationRiskPolicy(t, 3, true)
	var calls *atomic.Int32
	screening.Collect, calls = registrationScreening(t, screening.Policy)
	digest, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{121}, 32))
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "registration", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	c.PasswordSignup = &reference.PasswordSignupConfiguration{
		Native: passwordpg.SignupConfig{Repository: n.Repository, Registration: password.RegistrationPolicy{Enabled: true, RequireVerifiedEmail: true, MinimumBytes: 8, MaximumBytes: 128}, ConfigurationID: "reference-signup-v1", PolicyID: "password-signup", Fields: fields, FieldSchema: schema, Address: n.Request.Address, SelectUser: func(ctx context.Context) (identity.UserID, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			id, err := identity.NewSubjectID()
			return identity.UserID(id), err
		}, Session: c.OTP.Signin.Session, FlowKeys: c.PasswordSignin.Native.FlowKeys, Origins: []string{origin}, CallbackURLs: []string{callback}, RegistrationDomain: kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "reference-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {122}}}, RequestKeys: requestKeys, IntentKey: [32]byte{123}, ActiveEnvelopeKeyID: "issue-envelope", Screening: screening, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-signup-v1", Keys: c.OTP.RiskKeys}, Coordinator: coordinator, Verification: passwordpg.SignupVerificationConfig{Policy: verification, Lifetime: time.Minute}, Delivery: passwordpg.SignupDeliveryConfig{Resolver: resolver, Endpoint: origin + "/email/confirm", TemplateID: "registration", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{124}, Timeout: time.Second}},
		Issuer:      issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {125}}, PreparationTimeout: time.Second},
		Preparation: issuerpg.IssuancePreparationConfig{Deployment: "deployment", ActiveEnvelopeKey: "signup-issuer", EnvelopeKeys: map[string][]byte{"signup-issuer": bytes.Repeat([]byte{126}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "reference-signup", HMAC: bytes.Repeat([]byte{119}, 32)}}, Clock: time.Now},
		Counters:    riskpg.Config{Schema: c.Velocity.Schema, PolicyVersion: 9, EvidenceKeys: c.OTP.RiskKeys, EnvelopeKeys: map[string][]byte{"counter": bytes.Repeat([]byte{127}, 32)}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: registrationRiskPolicy(t, 9, false), Keys: []risk.CounterDigestKey{digest}}},
		PreAuth:     &reference.PasswordPreAuthConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", Origin: origin, CallbackURL: callback, FlowKeyIndex: 0, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: c.OTP.PreAuth.Cookie},
	}
	c.HTTPPasswordSignup = &reference.HTTPPasswordSignupConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9}
	c.PasswordSignup.Native.AuthorizationNamespace = c.PasswordSignin.Native.Profile.PolicyNamespace
	c.HTTPRegistrationVerification = &reference.HTTPRegistrationVerificationConfiguration{Origin: origin, ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, VerificationNamespace: "reference-registration", VerificationKey: [32]byte{128}}
	c.PasswordReset, c.HTTPPasswordReset = nil, nil
	return calls
}

// Actual public HTTP orchestration and migrations create the first account;
// no user, password, factor-authority or original-flow fixture supplies it.
func TestReferenceServerNativePasswordSignup(t *testing.T) {
	t.Run("rollback", func(t *testing.T) { proveReferenceSignupGraph(t, false) })
	t.Run("competing", func(t *testing.T) { proveReferenceSignupGraph(t, true) })
}

func proveReferenceSignupGraph(t *testing.T, competing bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	configureReferenceSignin(t, &c)
	network := httptest.NewUnstartedServer(nil)
	t.Cleanup(network.Close)
	origin := "https://" + network.Listener.Addr().String()
	c.OTP.PreAuth.Origin = origin
	c.Velocity.LeaseDuration = 10 * time.Second
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-registration", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{107}, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "reference-registration", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie}}
	configureReferencePasswordReset(t, &c, origin, f.pool, true)
	calls := configureReferenceRegistration(t, &c, origin)
	signin := c.PasswordSignin.Native
	c.Session = &reference.SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: signin.Session, Profile: sessionpg.IssueAdmissionConfig(signin.Profile), Coordinator: signin.Coordinator, Authorization: c.OTP.RequestKeys.Policy.Authorization, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: signin.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signin.Issuance.LookupKey}}, Cookie: signin.Issuance.Cookie, MaximumDuration: 3 * time.Second}, CSRFKeys: []session.CSRFKey{signin.CSRFKey}}
	c.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-session", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
		t.Error("unexpected shared rate degradation")
		return nil
	}}
	messages := make(chan string, 4)
	deps.DeliverySender = nativeBrowserCodeSender{codes: messages}
	for _, namespace := range []string{"", "other-users"} {
		invalid, selected := c, *c.PasswordSignup
		selected.Native.AuthorizationNamespace = namespace
		invalid.PasswordSignup = &selected
		if graph, err := reference.ComposeStores(invalid, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("registration accepted absent or mismatched signin authority namespace")
		}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("registration graph", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
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
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, `DO $$
DECLARE owned_role text;
BEGIN
  FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = owned_role) THEN
      EXECUTE format('DROP OWNED BY %I', owned_role);
      EXECUTE format('DROP ROLE %I', owned_role);
    END IF;
  END LOOP;
END $$`); err != nil {
			t.Error("owned audit cleanup", err)
		}
	})
	if out, err := stores.ReferenceMigrationApply(ctx, applyRequest(t, ctx, stores, modules)); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("fresh selected registration migration", err)
	}
	policies := identity.PolicySet{Authorize: c.OTP.RequestKeys.Policy.Authorization, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) { panic("unused") }, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		panic("unused")
	}, DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		panic("unused")
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		panic("unused")
	}}
	config := reference.ReferenceConfig{Profile: reference.PostgresWithValkey, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}, PublicHosts: []string{"localhost"}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Registration reference", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: &nativeServerTenant{}}}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		if invalid, ok := err.(identity.InvalidInputError); ok {
			t.Fatal("registration HTTP server", invalid.Field)
		}
		t.Fatal("registration HTTP server", err)
	}
	seen := map[string]bool{}
	for _, op := range server.OpenAPI().Operations() {
		seen[op.Record.OperationID] = true
	}
	if !seen["identity.password.signup"] || !seen["identity.email.verification-confirm"] || !seen["identity.password.signin"] || !seen["identity.session.get"] || !seen["identity.session.signout"] || len(seen) != 8 {
		t.Fatal("selected public registration routes missing")
	}
	network.Config.Handler = server.Handler()
	network.StartTLS()
	client := network.Client()
	client.Timeout = 5 * time.Second
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.RecoverVelocity(ctx, otpTenant); err == nil {
		t.Fatal("fresh journal fabricated coverage")
	}
	// Historical velocity warmup is explicit; account and flow creation are not.
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '61 minutes' WHERE tenant_id=$1 AND state='replaying'", otpTenant); err != nil {
		t.Fatal(err)
	}
	wait(ctx, t, 11*time.Second)
	if _, err := stores.RecoverVelocity(ctx, otpTenant); err != nil {
		t.Fatal("native velocity activation", err)
	}
	if r := server.Readiness(ctx); !r.Ready {
		t.Fatal("selected native readiness", r.Failures)
	}
	proveReferenceRegistration(t, ctx, f, features, workers, client, network.URL, origin, messages, calls, competing)
}

func proveReferenceRegistration(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, screens *atomic.Int32, competing bool) {
	t.Helper()
	invoke := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(data))
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
		if err != nil || closeErr != nil || len(payload) > 16384 {
			t.Fatal("bounded response")
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential response cacheable")
		}
		return response, payload
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, p := invoke("/v1/session/preauth-issue", map[string]string{"method": method}, "", nil)
		var out sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(p, &out) != nil || !out.Issued {
			t.Fatal("original method initiation", r.StatusCode)
		}
		return out, r.Cookies()
	}
	flow, cookies := issue("signup")
	body := map[string]any{"flowID": string(flow.FlowID), "email": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}
	// Fail after password/factor/authorization initialization and issuer staging.
	// The sole native transaction must roll every business effect back together.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION registration_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic registration rollback'; END $$;
CREATE TRIGGER registration_fixture_fail BEFORE INSERT ON identity.delivery_intents FOR EACH ROW EXECUTE FUNCTION registration_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	failed, payload := invoke("/v1/password/signup", body, "registration-rollback-key", cookies)
	if failed.StatusCode == 200 || len(failed.Cookies()) != 0 || bytes.Contains(payload, []byte("synthetic-registration-password")) {
		t.Fatal("failed signup disclosed credentials or succeeded")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users)+(SELECT count(*) FROM identity_password.credentials)+(SELECT count(*) FROM identity_mfa.factor_authorities)+(SELECT count(*) FROM authorization_subject_authorities)+(SELECT count(*) FROM identity.delivery_intents)+(SELECT count(*) FROM capability_identity_one_use)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("signup rollback leaked account/authority/credential/delivery effects", effects, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER registration_fixture_fail ON identity.delivery_intents; DROP FUNCTION registration_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	r, p := invoke("/v1/password/signup", body, "registration-original-key", cookies)
	var signup passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(r.Cookies()) != 0 {
		t.Fatal("native public signup", r.StatusCode)
	}
	var users, passwords, factors, deliveries, grants int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity_password.credentials),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE active_factors=0 AND version=1),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM capability_identity_one_use)`).Scan(&users, &passwords, &factors, &deliveries, &grants); err != nil || users != 1 || passwords != 1 || factors != 1 || deliveries != 1 || grants != 1 {
		t.Fatal("signup did not atomically create actual owners", err)
	}
	screened := screens.Load()
	if screened != 2 {
		t.Fatal("rollback and successful original signup were not screened exactly once each")
	}
	r, p = invoke("/v1/password/signup", body, "registration-original-key", cookies)
	var replay passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &replay) != nil || !replay.Replayed || replay.CommandID != signup.CommandID || screens.Load() != screened || len(r.Cookies()) != 0 {
		t.Fatal("keyed signup replay regenerated effects", r.StatusCode)
	}
	changed := map[string]any{"flowID": string(flow.FlowID), "email": "changed@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}
	r, _ = invoke("/v1/password/signup", changed, "registration-original-key", cookies)
	if r.StatusCode == 200 {
		t.Fatal("changed keyed signup replaced original input")
	}
	login, loginCookies := issue("password")
	loginBody := map[string]any{"flowID": string(login.FlowID), "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}
	r, _ = invoke("/v1/password/signin", loginBody, "", loginCookies)
	if r.StatusCode == 200 || len(r.Cookies()) != 0 {
		t.Fatal("unverified registration authenticated")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("actual encrypted delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" {
		t.Fatal("invalid delivered link")
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatal("native issuer token absent")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	confirmationBody := map[string]string{"token": token, "callback": origin + "/confirm", "commandID": string(command)}
	wrong := map[string]string{"token": token, "callback": origin + "/foreign", "commandID": string(command)}
	r, p = invoke("/v1/email/verification-confirm", wrong, "", nil)
	if r.StatusCode == 200 || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
		t.Fatal("foreign callback reached confirmation")
	}
	r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &confirmed) != nil || !confirmed.Confirmed || confirmed.Address == nil || confirmed.Replayed || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
		t.Fatal("public native confirmation", r.StatusCode)
	}
	r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
	var repeated emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &repeated) != nil || !repeated.Confirmed || !repeated.Replayed || repeated.Address != nil || len(r.Cookies()) != 0 {
		t.Fatal("confirmation replay disclosed/reconsumed", r.StatusCode)
	}
	if confirmed.Recovery == nil {
		t.Fatal("committed confirmation lost recovery correlation")
	}
	correlation := confirmed.Recovery
	recovery, err := email.NewVerificationRecovery(identity.RecoveryQuery{CommandID: confirmed.CommandID, TenantID: correlation.TenantID, UserID: correlation.UserID, RecordID: correlation.RecordID, ActorID: correlation.ActorID, ActorKind: correlation.ActorKind, OperationID: "identity.email.verification-confirm"})
	if err != nil {
		t.Fatal(err)
	}
	confirmationOwner, err := features.RegistrationVerification()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(otpTenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(correlation.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	recovered, err := confirmationOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: recovery, Caller: caller})
	if err != nil || recovered.Validate() != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Recovery != recovery {
		t.Fatal("selected typed confirmation recovery", err)
	}
	foreign := caller
	foreign.Request.Tenant = "foreign-tenant"
	if _, err := confirmationOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: recovery, Caller: foreign}); err == nil {
		t.Fatal("foreign tenant disclosed confirmation recovery")
	}
	var verified, consumed, charges, confirmationRows int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM risk_store.counter_charges)`).Scan(&verified, &consumed, &charges); err != nil || verified != 1 || consumed != 1 || charges != 1 {
		t.Fatal("confirmation atomic effects/replay", err)
	}
	login, loginCookies = issue("password")
	var policyAuthorities int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace='users'`, otpTenant).Scan(&policyAuthorities); err != nil || policyAuthorities != 1 {
		t.Fatal("new registration has no native authorization authority for signin", policyAuthorities, err)
	}
	loginBody["flowID"] = string(login.FlowID)
	r, p = invoke("/v1/password/signin", loginBody, "", loginCookies)
	var signed passwordhttp.SigninResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &signed) != nil || signed.CommitOutcome != "committed" || signed.SessionID == "" || len(r.Cookies()) != 1 {
		t.Fatal("verified registration did not produce usable login", r.StatusCode, signed.CommitOutcome, signed.Error, signed.CommandID != "", signed.SessionID != "")
	}
	logoutID := proveRegistrationSessionLogout(t, ctx, client, base, origin, r.Cookies(), r.Header.Get("X-CSRF-Token"), signed.SessionID, f, features)
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(logoutID))
	if err != nil {
		t.Fatal("logout command identity malformed")
	}
	var revocations, audits, events int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, commandBytes).Scan(&revocations, &audits, &events); err != nil || revocations != 1 || audits != 1 || events != 1 {
		t.Fatal("logout omitted or repeated protected effects", err)
	}
	if screens.Load() != screened {
		t.Fatal("confirmation/login repeated password creation screening")
	}
	if !competing {
		// A distinct real account supplies the rollback grant. Proven abort retires
		// that grant; it must never be reissued by resetting fixture state.
		flow, cookies = issue("signup")
		body["flowID"], body["email"] = string(flow.FlowID), "rollback@example.invalid"
		r, p = invoke("/v1/password/signup", body, "confirmation-rollback-signup", cookies)
		if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || signup.CommitOutcome != "committed" {
			t.Fatal("rollback account signup", r.StatusCode)
		}
		if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case link = <-messages:
		case <-ctx.Done():
			t.Fatal("rollback delivery absent")
		}
		u, err = url.Parse(link)
		if err != nil {
			t.Fatal("invalid rollback delivery")
		}
		token = u.Query().Get("token")
		command, err = identity.NewCommandID()
		if err != nil || token == "" {
			t.Fatal("rollback proof or command absent")
		}
		confirmationBody["token"], confirmationBody["commandID"] = token, string(command)
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION confirmation_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic confirmation rollback'; END $$;
CREATE TRIGGER confirmation_fixture_fail BEFORE INSERT ON identity.email_verifications FOR EACH ROW EXECUTE FUNCTION confirmation_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
		if r.StatusCode == 200 || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
			t.Fatal("failed confirmation disclosed credentials or succeeded")
		}
		// Failed protected attempts remain charged to prevent unlimited retries.
		// The first account stays verified; the failed grant has no committed use.
		var abortedCharges, released int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM identity.email_verifications),(SELECT count(*) FROM risk_store.counter_charges),(SELECT count(*) FROM risk_store.counter_charges r JOIN identity.commands c USING(command_id) WHERE c.state='aborted'),(SELECT count(*) FROM capability_identity_one_use WHERE state='released' AND uses=0)`).Scan(&verified, &consumed, &confirmationRows, &charges, &abortedCharges, &released); err != nil || verified != 1 || consumed != 1 || confirmationRows != 1 || charges != 2 || abortedCharges != 1 || released != 1 {
			t.Fatal("confirmation rollback lost atomic effects or attempt custody", verified, consumed, confirmationRows, charges, abortedCharges, released, err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER confirmation_fixture_fail ON identity.email_verifications; DROP FUNCTION confirmation_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		r, _ = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
		if r.StatusCode == 200 || len(r.Cookies()) != 0 {
			t.Fatal("aborted confirmation proof revived")
		}
		return
	}
	// Competing public native commands share the exact delivered grant, not a
	// test-created reservation. Only one may commit its proof and address effects.
	flow, cookies = issue("signup")
	body["flowID"], body["email"] = string(flow.FlowID), "competing@example.invalid"
	r, p = invoke("/v1/password/signup", body, "competing-confirmation-signup", cookies)
	if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || signup.CommitOutcome != "committed" {
		t.Fatal("competing account signup", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("competing delivery absent")
	}
	u, err = url.Parse(link)
	if err != nil {
		t.Fatal("invalid competing delivery")
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("competing delivered proof invalid")
	}
	callback, err := url.Parse(origin + "/confirm")
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Resource.ID = ""
	caller.Request.Environment.Time = time.Now().UTC()
	type attemptResult struct {
		out email.VerificationConfirmResult
		err error
	}
	completed := make(chan attemptResult, 2)
	start := make(chan struct{})
	for range 2 {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		request := email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: proof, Callback: *callback, Network: "127.0.0.1", Caller: caller}
		request.Caller.CorrelationID = string(id)
		go func() {
			<-start
			out, err := confirmationOwner.VerificationConfirm(ctx, request)
			completed <- attemptResult{out: out, err: err}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		select {
		case result := <-completed:
			if result.err == nil && result.out.Outcome == identity.CommitOutcomeCommitted {
				winners++
			} else if result.out.Outcome == identity.CommitOutcomeCommitted || result.out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("losing command disclosed successful effects")
			}
		case <-ctx.Done():
			t.Fatal("competing native confirmation did not terminate")
		}
	}
	if winners != 1 {
		t.Fatal("competing proof had no unique committed owner", winners)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM identity.email_verifications)`).Scan(&verified, &consumed, &confirmationRows); err != nil || verified != 2 || consumed != 2 || confirmationRows != 2 {
		t.Fatal("competing confirmation duplicated or lost protected effects", err)
	}
}

func proveRegistrationSessionLogout(t *testing.T, ctx context.Context, client *http.Client, base, origin string, cookies []*http.Cookie, csrf, sessionID string, f liveStores, features reference.FeatureSet) identity.CommandID {
	t.Helper()
	call := func(method, path, token string) (*http.Response, []byte) {
		var body io.Reader
		if method == "POST" {
			body = strings.NewReader("{}")
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable session response")
		}
		return response, payload
	}
	r, p := call("GET", "/v1/session/get", "")
	var read sessionhttp.GetResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || !read.Authenticated || read.Session == nil || read.Session.ID != sessionID {
		t.Fatal("new login session not readable", r.StatusCode)
	}
	r, _ = call("POST", "/v1/session/signout", "")
	if r.StatusCode != 403 || len(r.Cookies()) != 0 {
		t.Fatal("active logout bypassed CSRF or cleared cookie", r.StatusCode)
	}
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || !read.Authenticated {
		t.Fatal("CSRF denial revoked session")
	}
	if csrf == "" {
		t.Fatal("login did not deliver synchronizer token")
	}
	owner, err := features.Sessions()
	if err != nil {
		t.Fatal("selected native session port absent", err)
	}
	recoverOutcome := func(result sessionhttp.SignOutResponse, want identity.CommitOutcome) {
		t.Helper()
		if result.Recovery == nil || result.Recovery.CommandID != result.CommandID || result.Recovery.TenantID != otpTenant || result.Recovery.RecordID != sessionID {
			t.Fatal("logout lost original recovery scope")
		}
		q := result.Recovery
		query := identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID, LinkMode: q.LinkMode}
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Action: authorization.Action(q.OperationID), Tenant: authorization.TenantID(q.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
		historical, err := owner.RecoverSignOut(ctx, query, caller)
		var unavailable identity.UnavailableError
		errorMatches := err == nil
		if want == identity.CommitOutcomeNotCommitted {
			// Terminal dependency-failure history preserves its original error,
			// not a fabricated successful recovery or permission to reexecute.
			errorMatches = errors.As(err, &unavailable)
		}
		if !errorMatches || historical.Outcome != want || historical.Binding.CommandID != query.CommandID || historical.Binding.RecordID != sessionID {
			t.Fatal("selected logout recovery lost terminal history", err)
		}
		foreign := caller
		foreign.Request.Tenant = "foreign-tenant"
		if _, err := owner.RecoverSignOut(ctx, query, foreign); err == nil {
			t.Fatal("foreign tenant acquired logout history")
		}
	}
	// Reject the downstream lifecycle binding after the native revocation has
	// been staged. No cookie clearing or successful effect may escape rollback.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.session_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic session rollback'; END $$;
CREATE TRIGGER session_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.session_fixture_fail()`); err != nil {
		t.Fatal("session failure fixture", err)
	}
	cleanup := func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS session_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS public.session_fixture_fail()`); err != nil {
			t.Error("session failure fixture cleanup", err)
		}
	}
	t.Cleanup(cleanup)
	r, p = call("POST", "/v1/session/signout", csrf)
	var aborted sessionhttp.SignOutResponse
	if json.Unmarshal(p, &aborted) != nil || r.StatusCode != 503 || aborted.CommitOutcome != "not_committed" || aborted.SignedOut || len(r.Cookies()) != 0 {
		t.Fatal("failed lifecycle falsely cleared logout", r.StatusCode)
	}
	cleanup()
	abortedID, err := base64.RawURLEncoding.DecodeString(string(aborted.CommandID))
	if err != nil {
		t.Fatal("aborted logout lost command identity")
	}
	var transitions, successfulAudits, lifecycle int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, abortedID, int64(audit.OutcomeSucceeded)).Scan(&transitions, &successfulAudits, &lifecycle); err != nil || transitions != 0 || successfulAudits != 0 || lifecycle != 0 {
		t.Fatal("failed lifecycle leaked successful protected effects", err)
	}
	recoverOutcome(aborted, identity.CommitOutcomeNotCommitted)
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if json.Unmarshal(p, &read) != nil || r.StatusCode != 200 || !read.Authenticated {
		t.Fatal("failed lifecycle revoked active session")
	}
	r, p = call("POST", "/v1/session/signout", csrf)
	var logout sessionhttp.SignOutResponse
	decodeErr := json.Unmarshal(p, &logout)
	if r.StatusCode != 200 || decodeErr != nil || !logout.SignedOut || logout.CommitOutcome != "committed" || len(r.Cookies()) != 1 || r.Cookies()[0].MaxAge != -1 {
		var shape map[string]json.RawMessage
		_ = json.Unmarshal(p, &shape)
		keys := make([]string, 0, len(shape))
		for key := range shape {
			keys = append(keys, key)
		}
		t.Fatal("native logout failed", r.StatusCode, logout.Error, logout.CommitOutcome, "JSON", json.Valid(p), "decode", decodeErr != nil, "fields", keys, "bytes", len(p))
	}
	recoverOutcome(logout, identity.CommitOutcomeCommitted)
	command := logout.CommandID
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || read.Authenticated || read.Session != nil || read.Principal != nil {
		t.Fatal("revoked session still authenticated")
	}
	r, p = call("POST", "/v1/session/signout", "")
	logout = sessionhttp.SignOutResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &logout) != nil || !logout.SignedOut {
		t.Fatal("repeated logout was not neutral", r.StatusCode)
	}
	return command
}
