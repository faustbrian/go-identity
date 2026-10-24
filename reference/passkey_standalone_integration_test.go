//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// This graph starts with no password, OTP, delivery, sender or envelope owner.
// It exercises the same public HTTP signup/discovery/session journey as the
// retained deployment, rather than seeding accounts or borrowing its services.
func TestReferencePostgresPasskeyStandalone(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
			proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{})
		})
	}
}

func TestReferencePostgresPasskeyConditional(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, upgrade := range []bool{false, true} {
			t.Run(map[bool]string{false: "browser", true: "persistent"}[persistent]+"/"+map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
				proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{conditional: true, persistent: persistent})
			})
		}
	}
}

func TestReferencePostgresPasskeySessionManagement(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
			proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{management: true})
		})
	}
}

func TestReferencePostgresPasskeyHTTPSessionManagement(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
			proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{management: true, httpManagement: true})
		})
	}
}

func TestReferencePostgresPasskeySessionEnrollment(t *testing.T) {
	for _, transport := range []struct {
		name string
		kind session.CredentialKind
	}{{"cookie", session.CredentialCookie}, {"bearer", session.CredentialBearer}} {
		t.Run(transport.name, func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
					proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{enrollment: true, enrollmentTransport: transport.kind})
				})
			}
		})
	}
}

func TestReferencePostgresPasskeyHTTPSessionEnrollment(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
			proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{enrollment: true, enrollmentTransport: session.CredentialCookie, httpEnrollment: true})
		})
	}
}

type standalonePasskeyJourney struct {
	httpDeletion                                                    bool
	sessionDeletion                                                 bool
	conditional, persistent, management, httpManagement, enrollment bool
	enrollmentTransport                                             session.CredentialKind
	httpEnrollment                                                  bool
}

func proveReferencePasskeyStandalone(t *testing.T, upgrade bool, selected standalonePasskeyJourney) {
	t.Helper()
	conditional, persistent, management, httpManagement := selected.conditional, selected.persistent, selected.management, selected.httpManagement
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c := standalonePasskeyConfiguration(t, f.config)
	c.HTTPPasskey.Conditional = conditional
	c.HTTPPasskey.SessionUpdate = httpManagement
	c.HTTPPasskey.SessionEnrollment = selected.httpEnrollment
	c.HTTPPasskey.SessionDeletion = selected.httpDeletion
	if management {
		c.Passkey.SessionManagement = &reference.PasskeySessionManagementConfiguration{Transport: session.CredentialCookie}
	}
	if selected.enrollment {
		c.Passkey.SessionEnrollment = &reference.PasskeySessionEnrollmentConfiguration{Transport: selected.enrollmentTransport}
	}
	if selected.sessionDeletion {
		c.Passkey.SessionDeletion = &reference.PasskeySessionDeletionConfiguration{Transport: selected.enrollmentTransport}
	}
	deps := reference.ReferenceDependencies{PostgreSQL: f.pool}
	if selected.httpDeletion && !upgrade {
		minimal := c
		minimal.HTTPPreAuth = nil
		minimal.HTTPPasskey = &reference.HTTPPasskeyConfiguration{SessionDeletion: true}
		graph, err := reference.ComposeStores(minimal, deps)
		if err != nil {
			t.Fatal("session-only removal acquired a browser-flow/device dependency", err)
		}
		if err := graph.Close(ctx); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"native-disabled", "bearer-native", "competing-password-profile", "missing-csrf"} {
			changed := c
			p, removal, h, sessions := *c.Passkey, *c.Passkey.SessionDeletion, *c.HTTPPasskey, *c.Session
			changed.Passkey, changed.HTTPPasskey, changed.Session, p.SessionDeletion = &p, &h, &sessions, &removal
			switch mode {
			case "native-disabled":
				p.SessionDeletion = nil
			case "bearer-native":
				removal.Transport = session.CredentialBearer
			case "competing-password-profile":
				h.Delete = true
			case "missing-csrf":
				sessions.CSRFKeys = nil
			}
			if graph, err := reference.ComposeStores(changed, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("incomplete HTTP session removal composed", mode)
			}
		}
	}
	if selected.sessionDeletion && !upgrade {
		for _, mode := range []string{"missing-keyed-owner", "invalid-transport", "missing-csrf"} {
			changed := c
			p, removal, sessions := *c.Passkey, *c.Passkey.SessionDeletion, *c.Session
			changed.Passkey, changed.Session, p.SessionDeletion = &p, &sessions, &removal
			switch mode {
			case "missing-keyed-owner":
				p.KeyedOptions = nil
			case "invalid-transport":
				removal.Transport = 0
			case "missing-csrf":
				if removal.Transport != session.CredentialCookie {
					continue
				}
				sessions.CSRFKeys = nil
			}
			if graph, err := reference.ComposeStores(changed, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("incomplete native session removal composed", mode)
			}
		}
	}
	if selected.httpEnrollment && !upgrade {
		for _, mode := range []string{"native-disabled", "bearer-native", "competing-password-profile", "no-csrf"} {
			changed := c
			p, e, h, s := *c.Passkey, *c.Passkey.SessionEnrollment, *c.HTTPPasskey, *c.Session
			p.SessionEnrollment = &e
			changed.Passkey, changed.HTTPPasskey, changed.Session = &p, &h, &s
			switch mode {
			case "native-disabled":
				p.SessionEnrollment = nil
			case "bearer-native":
				e.Transport = session.CredentialBearer
			case "competing-password-profile":
				h.Registration = true
			case "no-csrf":
				s.CSRFKeys = nil
			}
			if graph, err := reference.ComposeStores(changed, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("unsupported HTTP session enrollment composed", mode)
			}
		}
		// This selected branch borrows current session authority, not signup's
		// anonymous browser admission or signed device cookie.
		sessionOnly := c
		sessionOnly.HTTPPreAuth = nil
		sessionOnly.HTTPPasskey = &reference.HTTPPasskeyConfiguration{SessionEnrollment: true}
		graph, err := reference.ComposeStores(sessionOnly, deps)
		if err != nil {
			t.Fatal("session-only enrollment acquired a browser/pre-auth dependency", err)
		}
		if err := graph.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if selected.enrollment && !upgrade {
		for _, mode := range []string{"missing-keyed-owner", "invalid-transport", "missing-csrf"} {
			changed := c
			p, enrollment, sessions := *c.Passkey, *c.Passkey.SessionEnrollment, *c.Session
			changed.Passkey, changed.Session, p.SessionEnrollment = &p, &sessions, &enrollment
			switch mode {
			case "missing-keyed-owner":
				p.KeyedOptions = nil
			case "invalid-transport":
				enrollment.Transport = 0
			case "missing-csrf":
				sessions.CSRFKeys = nil
			}
			if graph, err := reference.ComposeStores(changed, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("incomplete native session enrollment composed", mode)
			}
		}
	}
	if management && !upgrade {
		for _, mode := range []string{"missing-keyed-owner", "invalid-transport"} {
			selected := c
			p, m := *c.Passkey, *c.Passkey.SessionManagement
			p.SessionManagement = &m
			selected.Passkey = &p
			if mode == "missing-keyed-owner" {
				p.KeyedOptions = nil
			} else {
				m.Transport = 0
			}
			if graph, err := reference.ComposeStores(selected, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("incomplete native session management composed", mode)
			}
		}
	}
	if httpManagement && !upgrade {
		for _, mode := range []string{"native-disabled", "bearer-native", "competing-password-profile", "no-csrf"} {
			selected := c
			p, m, h, s := *c.Passkey, *c.Passkey.SessionManagement, *c.HTTPPasskey, *c.Session
			p.SessionManagement = &m
			selected.Passkey, selected.HTTPPasskey, selected.Session = &p, &h, &s
			switch mode {
			case "native-disabled":
				p.SessionManagement = nil
			case "bearer-native":
				m.Transport = session.CredentialBearer
			case "competing-password-profile":
				h.Update = true
			case "no-csrf":
				s.CSRFKeys = nil
			}
			if graph, err := reference.ComposeStores(selected, deps); err == nil {
				_ = graph.Close(ctx)
				t.Fatal("unsupported HTTP update composed", mode)
			}
		}
	}
	if !upgrade {
		for name, edit := range map[string]func(*reference.StoreConfiguration){
			"absent session issuer": func(c *reference.StoreConfiguration) { c.Session.Passkey = false },
			"absent signup":         func(c *reference.StoreConfiguration) { c.Passkey.Signup = nil },
			"selected OTP":          func(c *reference.StoreConfiguration) { c.OTP = &reference.OTPSendConfiguration{} },
			"selected password":     func(c *reference.StoreConfiguration) { c.PasswordSignin = &reference.PasswordSigninConfiguration{} },
			"selected delivery":     func(c *reference.StoreConfiguration) { c.Delivery = &reference.DeliveryConfiguration{} },
			"password HTTP": func(c *reference.StoreConfiguration) {
				c.HTTPPasswordSignin = &reference.HTTPPasswordSigninConfiguration{}
			},
			"enrollment HTTP": func(c *reference.StoreConfiguration) { c.HTTPPasskey.Registration = true },
			"identified HTTP": func(c *reference.StoreConfiguration) { c.HTTPPasskey.DiscoverableOnly = false },
			"discovery off":   func(c *reference.StoreConfiguration) { c.HTTPPasskey.Discoverable = false },
			"conditional without discovery": func(c *reference.StoreConfiguration) {
				c.HTTPPasskey.Conditional, c.HTTPPasskey.Discoverable, c.HTTPPasskey.DiscoverableOnly = true, false, false
			},
			"audit exceeds risk": func(c *reference.StoreConfiguration) { c.Passkey.Standalone.AuditTimeout = 3 * time.Second },
			"session-risk-schema-overlap": func(c *reference.StoreConfiguration) {
				c.Session.Native.Execution.Repository.Schema = c.DurableAdmission.Schema
			},
			"risk exceeds operation": func(c *reference.StoreConfiguration) {
				c.Passkey.Standalone.RiskTimeout = 4 * time.Second
			},
		} {
			t.Run(name, func(t *testing.T) {
				changed := c
				p, standalone, sessions, h := *c.Passkey, *c.Passkey.Standalone, *c.Session, *c.HTTPPasskey
				p.Standalone = &standalone
				changed.Passkey, changed.Session, changed.HTTPPasskey = &p, &sessions, &h
				edit(&changed)
				got, err := reference.ComposeStores(changed, deps)
				if err == nil {
					cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					_ = got.Close(cleanup)
					t.Fatal("unsupported selection silently composed")
				}
			})
		}
	}
	var preservedCounters string
	if upgrade {
		// Populate the prior public kernel/risk deployment before selecting any
		// passkey history. No password/OTP/delivery graph supplies prerequisites.
		prior := f.config
		prior.Velocity.PrimaryTimeout = 5 * time.Second
		prior.Migrations = c.Migrations
		selectDurableReferenceAdmission(&prior)
		old, err := reference.ComposeStores(prior, deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := old.Close(cleanup); err != nil {
				t.Error(err)
			}
		})
		request := applyRequest(t, ctx, old, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
		if out, err := old.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
			t.Fatal("prior kernel/risk deployment", err)
		}
		n := prior.DurableAdmission
		counter, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: f.pool, Schema: n.Schema, Namespace: n.Namespace, Policy: n.Policy, Keys: n.Keys, ReplayKey: n.ReplayKey, Tenants: n.Tenants, MaximumRecords: n.MaximumRecords, Timeout: n.Timeout})
		if err != nil {
			t.Fatal(err)
		}
		coordinator := liveCoordinator(t, f, counter)
		command := liveCommand(t, coordinator, "standalone-prior-counter")
		result, err := counter.Mutate(ctx, command)
		outcome, counts, declared := result.Declaration(command)
		if err != nil || declared != nil || outcome != risk.CounterCommitted || len(counts) != 4 {
			t.Fatal("populate prior durable authority", err, declared)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(w) ORDER BY to_jsonb(w)::text)::text FROM risk_store.durable_counter_windows w`).Scan(&preservedCounters); err != nil || preservedCounters == "" {
			t.Fatal("capture populated native counters", err)
		}
		if err := old.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		var input identity.InvalidInputError
		if errors.As(err, &input) {
			t.Fatal("passkey-only store composition", input.Field)
		}
		t.Fatal("passkey-only store composition", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, `DO $$ DECLARE owned_role text; BEGIN FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=owned_role) THEN EXECUTE format('DROP OWNED BY %I',owned_role); EXECUTE format('DROP ROLE %I',owned_role); END IF; END LOOP; END $$`); err != nil {
			t.Error("owned standalone audit cleanup", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers)
	if err != nil {
		t.Fatal("unselected delivery requires a delivery worker", err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/session/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/mfa/postgres", "passkey/postgres", "webauthn/postgres"}
	request := applyRequest(t, ctx, stores, modules)
	if upgrade {
		request.CommandID = "migration_command_0002"
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("passkey-only-populated-kernel"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("passkey-only owned migration apply", err)
	}
	if management {
		owner, err := features.Passkeys()
		if err != nil {
			t.Fatal(err)
		}
		manager, err := owner.SessionManagement()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := manager.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{}); err == nil || out.CommandID != "" {
			t.Fatal("pre-initialization handle executed")
		}
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("passkey-only startup", err)
	}
	if upgrade {
		var current string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(w) ORDER BY to_jsonb(w)::text)::text FROM risk_store.durable_counter_windows w`).Scan(&current); err != nil || current != preservedCounters {
			t.Fatal("upgrade changed existing native counter authority", err)
		}
	}
	if _, err := features.OTP(); err == nil {
		t.Fatal("passkey-only graph exposed OTP")
	}
	if _, err := features.PasswordSignin(); err == nil {
		t.Fatal("passkey-only graph exposed password signin")
	}
	if _, err := features.PasswordSignup(); err == nil {
		t.Fatal("passkey-only graph exposed password signup")
	}
	policies := identity.PolicySet{Authorize: referenceRegistrationPolicy{}, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) { panic("unused") }, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		panic("unused")
	}, DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		panic("unused")
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		panic("unused")
	}}
	config := reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "identity.example", TenantID: otpTenant}}, PublicHosts: []string{"localhost"}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Passkey-only reference", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: &nativeServerTenant{}}}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("passkey-only HTTP composition", err)
	}
	selectedUpdate, selectedDelete := false, false
	for _, op := range server.OpenAPI().Operations() {
		id := op.Record.OperationID
		selectedUpdate = selectedUpdate || id == "identity.passkey.update"
		selectedDelete = selectedDelete || id == "identity.passkey.delete"
		if strings.HasPrefix(id, "identity.password.") || strings.HasPrefix(id, "identity.otp.") || strings.HasPrefix(id, "identity.delivery.") {
			t.Fatal("unselected authentication workflow advertised", id)
		}
	}
	if selectedUpdate != httpManagement {
		t.Fatal("native selection enabled unselected HTTP update")
	}
	if selectedDelete != selected.httpDeletion {
		t.Fatal("native selection enabled unselected HTTP deletion")
	}
	if status := server.Readiness(ctx); !status.Ready {
		t.Fatal("passkey-only readiness", status.Failures)
	}
	if selected.sessionDeletion && !upgrade {
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE webauthn.effects RENAME COLUMN removal_after_credential TO removal_successor_missing`); err != nil {
			t.Fatal(err)
		}
		status := server.Readiness(ctx)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE webauthn.effects RENAME COLUMN removal_successor_missing TO removal_after_credential`); err != nil {
			t.Fatal("restore owned removal successor column", err)
		}
		if status.Ready {
			t.Fatal("removal readiness ignored missing compound successor storage")
		}
		if status := server.Readiness(ctx); !status.Ready {
			t.Fatal("restored removal readiness", status.Failures)
		}
	}
	if selected.enrollment && !upgrade {
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE webauthn.ceremonies RENAME COLUMN authorization_expires_at TO enrollment_expiry_missing`); err != nil {
			t.Fatal(err)
		}
		status := server.Readiness(ctx)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE webauthn.ceremonies RENAME COLUMN enrollment_expiry_missing TO authorization_expires_at`); err != nil {
			t.Fatal("restore owned enrollment expiry column", err)
		}
		if status.Ready {
			t.Fatal("enrollment readiness ignored missing original authorization storage")
		}
		if status := server.Readiness(ctx); !status.Ready {
			t.Fatal("restored enrollment readiness", status.Failures)
		}
	}
	if !upgrade {
		// A selected verification limiter is a real startup prerequisite even
		// when no password endpoint incidentally supplies its atomic migration.
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE public.rate_limit_atomic_commands RENAME TO standalone_rate_missing`); err != nil {
			t.Fatal(err)
		}
		status := server.Readiness(ctx)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE public.standalone_rate_missing RENAME TO rate_limit_atomic_commands`); err != nil {
			t.Fatal("restore owned rate fixture", err)
		}
		if status.Ready {
			t.Fatal("standalone readiness ignored missing verification authority")
		}
		if status := server.Readiness(ctx); !status.Ready {
			t.Fatal("restored standalone readiness", status.Failures)
		}
	}
	proveReferencePasskeySignupHTTPRemember(t, ctx, features, c, server.Handler(), server.OpenAPI().JSON(), f.pool, persistent)
}

func standalonePasskeyConfiguration(t *testing.T, c reference.StoreConfiguration) reference.StoreConfiguration {
	t.Helper()
	policy := registrationRiskPolicyConfig(3, false)
	policy.PasskeyDiscovery = true
	c.Velocity.Native.Policy, _ = risk.NewPolicy(policy)
	c.Velocity.Tenants = []string{otpTenant}
	c.Velocity.PrimaryTimeout = 5 * time.Second
	query := kernel.CommandQueryPolicy{Authorization: referenceRegistrationPolicy{}, Clock: clock.System{}, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 4 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &query, AdmissionPolicy: &query}
	lookup, _ := session.NewDigestKey(11, bytes.Repeat([]byte{0x79}, 32))
	csrf, _ := session.NewCSRFKey(12, bytes.Repeat([]byte{0x7a}, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	store := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := sessionpg.IssueAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "passkey", CredentialKind: identity.CredentialPasskey, CredentialOwner: "passkey"}
	c.Session = &reference.SessionConfiguration{Passkey: true, Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: store, Profile: profile, Coordinator: coordinator, Authorization: query.Authorization, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}, Cookie: cookie, MaximumDuration: 3 * time.Second}, CSRFKeys: []session.CSRFKey{csrf}}
	challenge, _ := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{218}, 32))
	flowKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{219}, 32))
	flowCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	protectedKey, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{121}, 32))
	protected := riskpg.Config{Schema: c.Velocity.Schema, PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": bytes.Repeat([]byte{127}, 32)}, CurrentEnvelopeKey: "counter", EnforceLockouts: true, CommandCounters: &risk.CommandCounterPolicyConfig{Policy: registrationRiskPolicy(t, 9, false), Keys: []risk.CounterDigestKey{protectedKey}}}
	flow := session.PreAuthIssuerConfig{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", Action: "identity.passkey.signin-verify", Origin: "https://identity.example", PolicyID: "session-signout", PolicyVersion: 9, Purpose: session.PreAuthSessionIssuance, MaximumDuration: 3 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: flowCookie}
	signup := flow
	signup.Action = "identity.passkey.register-verify"
	c.Passkey = &reference.PasskeyConfiguration{Standalone: &reference.PasskeyStandaloneConfiguration{BootstrapTenantIDs: []identity.TenantID{otpTenant}, RiskTimeout: 2 * time.Second, AuditTimeout: time.Second, RiskPolicyID: otpTenant}, Signup: &reference.PasskeySignupConfiguration{Flow: signup, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-passkey-signup", Keys: []risk.EvidenceKey{evidence}}}, Protocol: webauthn.Config{TenantID: otpTenant, RelyingParty: webauthn.RelyingParty{ID: "identity.example", Name: "Reference", Origins: []string{"https://identity.example"}, Version: 1}, ChallengeKey: challenge, MaximumDuration: 3 * time.Second}, RPNamespace: "reference-rp", Protected: protected, Flow: flow, Issuer: session.IssuerConfig{MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, CSRF: csrf, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-passkey", Keys: []risk.EvidenceKey{evidence}}, IdentifierKey: bytes.Repeat([]byte{220}, 32), SessionPredecessor: "session_issuances_purpose_v2"}
	configureReferencePasskeyKeyed(t, &c)
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-passkey-only", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	deviceKey, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{107}, 32))
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "reference-passkey-only", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: deviceCookie}}
	c.HTTPPasskey = &reference.HTTPPasskeyConfiguration{Signup: true, Signin: true, Discoverable: true, DiscoverableOnly: true, Inventory: true}
	c.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{"https://identity.example"}, RateNamespace: "reference-session", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
		t.Error("unexpected rate degradation")
		return nil
	}}
	selectDurableReferenceAdmission(&c)
	return c
}
