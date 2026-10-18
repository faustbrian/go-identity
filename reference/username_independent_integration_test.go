//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
	primitive "github.com/faustbrian/go-password/v2"
)

// Availability has its own counter owner. Neither the graph's counter schema
// nor an unrelated registration/email selection may supply its prerequisites.
func TestReferenceUsernameAvailabilityIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	c.Velocity.PrimaryTimeout, c.Velocity.LeaseDuration = 5*time.Second, 10*time.Second
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{203}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	available := passwordpg.UsernameAvailabilityConfig{
		Domain:   kernel.UsernameRenameDomainConfig{NormalizationProfile: string(username.ProfileID), NormalizationVersion: username.ProfileVersion, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {122}}, ReuseCooldown: 30 * 24 * time.Hour},
		Counters: riskpg.DurableCounterConfig{Schema: "username_counters", Namespace: "username-availability", Policy: registrationRiskPolicy(t, 9, false), Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{204}, 32), Tenants: []string{otpTenant}, MaximumRecords: 1000, Timeout: time.Second},
		PolicyID: string(policyID), MaximumDuration: 3 * time.Second, RiskTimeout: 2 * time.Second, OnAuditLoss: func(context.Context, risk.DecisionDelivery) error { return nil },
	}
	c.Username = &reference.UsernameConfiguration{Policy: p, Availability: &available}
	selectDurableReferenceAdmission(&c)
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("independent native availability composition", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
		if _, err := f.pool.Raw().Exec(cleanup, `DO $$ DECLARE owned_role text; BEGIN
 FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
 IF EXISTS (SELECT FROM pg_roles WHERE rolname=owned_role) THEN
 EXECUTE format('DROP OWNED BY %I',owned_role); EXECUTE format('DROP ROLE %I',owned_role);
 END IF; END LOOP; END $$`); err != nil {
			t.Error("owned audit cleanup", err)
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
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity"}
	request := applyRequest(t, ctx, stores, modules)
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("independent availability selected migration", err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	owner, err := features.UsernameAvailability()
	if err != nil {
		t.Fatal(err)
	}
	result, err := owner.Available(ctx, username.AvailabilityRequest{TenantID: otpTenant, Username: "IndependentName", Network: "127.0.0.1"})
	if err != nil || !result.Available {
		var counters, retirements bool
		if queryErr := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('username_counters.durable_counter_scopes') IS NOT NULL, to_regclass('identity.identifier_retirements') IS NOT NULL").Scan(&counters, &retirements); queryErr != nil {
			t.Fatal(queryErr)
		}
		t.Fatal("fresh independent availability cannot query selected owners", err, "counters", counters, "retirements", retirements)
	}
	if _, err := features.UsernameSignup(); err == nil {
		t.Fatal("availability implicitly selected signup")
	}
}

func TestReferenceUsernameNativeRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	const origin = "https://identity.example.invalid"
	configureReferencePreAuth(t, &c)
	configureReferenceSignin(t, &c)
	c.Velocity.PrimaryTimeout, c.Velocity.LeaseDuration = 5*time.Second, 10*time.Second
	configureReferencePasswordResetPolicy(t, &c, origin, f.pool, 3, true)
	configureReferenceRegistration(t, &c, origin, referenceUsernamePolicy{})
	configureReferenceUsername(t, &c, origin)
	c.Username.Availability, c.Username.Rename = nil, nil
	c.PasswordVerification = nil
	c.HTTPUsername, c.HTTPPreAuth, c.HTTPPasswordSignup, c.HTTPPasswordSignin = nil, nil, nil, nil
	c.HTTPRegistrationVerification, c.HTTPPasswordVerification = nil, nil
	selectDurableReferenceAdmission(&c)
	messages := make(chan string, 2)
	deps.DeliverySender = nativeBrowserCodeSender{codes: messages}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("native-only username graph", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
		if _, err := f.pool.Raw().Exec(cleanup, `DO $$ DECLARE owned_role text; BEGIN
 FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
 IF EXISTS (SELECT FROM pg_roles WHERE rolname=owned_role) THEN
 EXECUTE format('DROP OWNED BY %I',owned_role); EXECUTE format('DROP ROLE %I',owned_role);
 END IF; END LOOP; END $$`); err != nil {
			t.Error("owned audit cleanup", err)
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
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	if out, err := stores.ReferenceMigrationApply(ctx, applyRequest(t, ctx, stores, modules)); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("native-only username migrations", err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(owner reference.PreAuthService) (identity.PreAuthTransactionID, auth.BearerCredential) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := owner.Prepare(ctx, session.PreAuthPrepareInput{CommandID: id, TenantID: otpTenant, CorrelationID: string(id), Remember: remember})
		if err != nil {
			t.Fatal("native original flow preparation", err)
		}
		out, err := owner.Issue(ctx, prepared)
		if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("native original flow", err)
		}
		b, err := out.Flow.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		wire, err := out.Token.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		return b.Binding.ID, auth.NewBearerCredential(wire)
	}
	caller := func(action, resource string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "native-username", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: authorization.Action(action), Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(action)}}}
	}
	secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	preauth, err := features.UsernameSignupPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	flow, cookie := issue(preauth)
	key, err := identity.NewIdempotencyKey([]byte("native-username-original"))
	if err != nil {
		t.Fatal(err)
	}
	signup, err := features.UsernameSignup()
	if err != nil {
		t.Fatal(err)
	}
	created, err := signup.Signup(ctx, password.SignupRequest{TenantID: otpTenant, PreAuthID: flow, Cookie: cookie, Email: "native-username@example.invalid", Username: "NativeName", Password: secret, RememberPolicy: remember, Origin: origin, CallbackURL: origin + "/confirm", Caller: caller("identity.username.signup", "identity.request-admission"), Network: "127.0.0.1", Device: "native-device", IdempotencyKey: key})
	if err != nil || created.Outcome != identity.CommitOutcomeCommitted || !created.VerificationRequired {
		t.Fatal("native username signup", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("native original delivery absent")
	}
	address, err := url.Parse(link)
	if err != nil {
		t.Fatal("native delivery link")
	}
	proof, err := capability.ParseProof(address.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("native original proof")
	}
	confirmation, err := features.UsernameRegistrationVerification()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(origin + "/confirm")
	confirmationCaller := caller("identity.email.verification-confirm", "identity.user")
	confirmationCaller.Request.Resource.ID = ""
	confirmed, err := confirmation.VerificationConfirm(ctx, email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: proof, Callback: *callback, Caller: confirmationCaller, Network: "127.0.0.1"})
	if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native-only original username confirmation", err)
	}
	loginFlow, err := features.UsernameSigninPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	flow, cookie = issue(loginFlow)
	identifier, err := identifier.NewInput("NATIVENAME")
	if err != nil {
		t.Fatal(err)
	}
	signin, err := features.UsernameSignin()
	if err != nil {
		t.Fatal(err)
	}
	logged, err := signin.Signin(ctx, password.SigninRequest{TenantID: otpTenant, PreAuthID: flow, Cookie: cookie, Identifier: identifier, Password: secret, Remember: remember, Origin: origin, CallbackURL: c.PasswordSignin.PreAuth.CallbackURL, Caller: caller("identity.username.signin", "identity.request-admission"), Network: "127.0.0.1", Device: "native-device"})
	if err != nil || logged.State != auth.SignInStateAuthenticated || logged.SessionID == "" || logged.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("native-only verified username session", err)
	}
}
