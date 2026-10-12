//go:build integration

package magiclinkpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5"
)

const requestTestTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
const requestTestUser = "AAAAAAAAAAAAAAAAAAAAAg"

// Configured ingress/source boundaries are deliberate test inputs, not durable
// identity/capability/session replacements. This suite makes no risk-store claim.
type requestTestPolicy struct{}

type requestTestWorkerPolicy struct{}

func (requestTestWorkerPolicy) Decide(_ context.Context, _ authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: 3}, nil
}

type requestTestSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (s requestTestSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return s(ctx, a)
}

func (requestTestPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

type requestTestSignals struct{}

func (requestTestSignals) Mutate(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	b := c.Bindings()
	var counters []risk.Counter
	for _, target := range b.Targets {
		counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt, WindowExpiresAt: b.PreparedAt.Add(b.Window)})
	}
	return risk.NewCounterResult(c, risk.CounterCommitted, counters)
}
func (requestTestSignals) Append(_ context.Context, r audit.Record) (audit.AppendResult, error) {
	return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
}
func (requestTestSignals) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch")
}

type requestTestTx struct{ pool *database.Pool }

func (t requestTestTx) Query(ctx context.Context, q string, args ...any) (pgx.Rows, error) {
	return t.pool.Raw().Query(ctx, q, args...)
}
func (t requestTestTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	tag, err := t.pool.Raw().Exec(ctx, q, args...)
	return tag.RowsAffected(), err
}

func requestTestRisk(t *testing.T) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{71}, 32))
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Store: requestTestSignals{}, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{k}})
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := identity.NewCommandID()
	e, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: p, Clock: time.Now, Timeout: time.Second, Counters: &counters, Sources: []risk.Source{{Name: "status", Version: "magic-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
	}}}, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: requestTestSignals{}, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{72}, 32), bytes.Repeat([]byte{73}, 32))
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "magic-test-v1", Keys: []risk.EvidenceKey{key}}
}

func TestNativeMagicLinkRequestPostgres(t *testing.T) {
	port, file := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT"), os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE")
	material, err := os.ReadFile(file)
	if err != nil || port == "" {
		t.Fatal("isolated primary required")
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(material))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/identity_test", RawQuery: "sslmode=disable"}).String()
	clear(material)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("primary unavailable")
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if pool.Close(stop) != nil {
			t.Error("pool cleanup")
		}
	}()
	base := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12, GlobalAuthorityID: "magic-deployment", TenantIDs: []identity.TenantID{requestTestTenant}}
	preparation := kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: base, Version: 13}, Version: 14}, Version: 15}, Version: 16}
	storage := sessionpg.Config{Schema: "magic_sessions", MaximumDuration: time.Second}
	for _, source := range []migrations.Source{preparation, mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, sessionpg.MigrationSource{Schema: storage.Schema, Version: 1}, sessionpg.PreAuthMigrationSource{Schema: storage.Schema, Version: 2}} {
		history, e := source.Load(ctx)
		if e != nil {
			t.Fatal("migration", e)
		}
		for _, m := range history {
			if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
				t.Fatal("migration execution", m.Version(), e)
			}
		}
	}
	// Install the session owner's actual forward histories, rather than a test
	// substitute for retained issuance or magic-link provenance.
	for _, source := range []migrations.Source{
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: storage.Schema, Version: 1}, Version: 3}, Version: 4},
		sessionpg.CSRFMigrationSource{Schema: storage.Schema, Version: 5},
		sessionpg.OTPMigrationSource{Schema: storage.Schema, Version: 6},
		sessionpg.CredentialContinuationMigrationSource{Schema: storage.Schema, Version: 7},
		sessionpg.OTPIssueMigrationSource{Schema: storage.Schema, Version: 8},
		sessionpg.PasswordSigninMigrationSource{Schema: storage.Schema, Version: 9},
		sessionpg.PasswordSignupMigrationSource{Schema: storage.Schema, Version: 10},
		sessionpg.MagicLinkMigrationSource{Schema: storage.Schema, Version: 11},
		sessionpg.MagicLinkSigninMigrationSource{Schema: storage.Schema, Version: 12},
	} {
		history, e := source.Load(ctx)
		if e != nil {
			t.Fatal("session history", e)
		}
		for _, m := range history {
			if m.Version() > 2 {
				if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
					t.Fatal("session history execution", m.Version(), e)
				}
			}
		}
	}
	authorityMigration, err := authoritypg.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, authorityMigration.Up); err != nil {
		t.Fatal("authorization history", err)
	}
	history, e := (deliverypg.MigrationSource{Base: preparation, Version: 20}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range history {
		if m.Version() == 20 {
			if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
				t.Fatal("delivery migration", e)
			}
		}
	}
	if _, err = pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations(), issuerpg.Migrations()} {
		files, e := fs.ReadDir(source, ".")
		if e != nil {
			t.Fatal(e)
		}
		for _, file := range files {
			wire, e := fs.ReadFile(source, file.Name())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); e != nil {
				t.Fatal("effect migration", file.Name(), e)
			}
		}
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','magic-email','email','person@example.test',true,true,1,2,1,clock_timestamp());
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'AAAAAAAAAAAAAAAAAAAAAQ','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'AAAAAAAAAAAAAAAAAAAAAQ','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg',1,0,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal("primary fixture", err)
	}
	keys, _ := keyring.New(map[string][]byte{"magic-mail": bytes.Repeat([]byte{91}, 32)})
	if _, err := authoritypg.InitializeAuthority(ctx, pool.Raw(), authoritypg.AuthorityScope{TenantID: requestTestTenant, PolicyNamespace: "users", SubjectID: requestTestUser}, time.Second); err != nil {
		t.Fatal("authorization bootstrap", err)
	}
	crypto, _ := envelope.NewService(keys)
	mail, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "magic-mail", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {92}}, ActiveEnvelopeKeyID: "magic-mail", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "magic-link", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Sign in: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://app.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("magic-test", bytes.Repeat([]byte{93}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{93}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{ID: "magic-test", Verifier: verifier}})
	normalization, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "magic-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	address, _ := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization})
	policy := kernel.CommandQueryPolicy{Authorization: requestTestPolicy{}, Clock: clock.System{}, PolicyVersion: 3}
	requestKeys, _ := kernel.NewRequestKeyConfig("magic-test", [32]byte{94}, policy)
	flowKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{95}, 32))
	config := RequestConfig{MaximumDuration: 3 * time.Second, ConfigurationID: "magic-test", PolicyID: "login", GlobalAuthorityID: "magic-deployment", IssuerURL: "https://issuer.test", Origins: []string{"https://app.test"}, Callbacks: []string{"https://app.test/login"}, Lifetime: time.Minute, Address: address, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {96}}, AdmissionPolicy: &policy, QueryPolicy: &policy}, RequestKeys: requestKeys, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {97}}, PreparationTimeout: time.Second}, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "magic-test", ActiveEnvelopeKey: "magic-issuer", EnvelopeKeys: map[string][]byte{"magic-issuer": bytes.Repeat([]byte{98}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "magic-test", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now}, Risk: requestTestRisk(t), Session: storage, CookieKeys: map[uint32]session.DigestKey{1: flowKey}, IntentKey: [32]byte{99}, ActiveEnvelopeKeyID: "magic-mail", Delivery: RequestDeliveryConfig{Owner: mail, Renderer: renderer, Endpoint: "https://app.test/magic", TemplateID: "magic-link", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{100}, Timeout: time.Second}}
	service, err := NewRequestService(pool, config, keys)
	if err != nil {
		t.Fatal("public composition", err)
	}
	var public magiclink.RequestService = service
	workerHistoryInstalled := false
	for _, mode := range []string{"commit", "absent", "missing-factor", "enrolled-factor", "foreign-cookie", "audit-failure", "mfa-enabled"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "mfa-enabled" {
				selected := config
				selected.MFAContinuation = true
				native, e := NewRequestService(pool, selected, keys)
				if e != nil {
					t.Fatal(e)
				}
				public = native
				defer func() { public = service }()
			}
			if _, e := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, requestTestTenant, requestTestUser); e != nil {
				t.Fatal(e)
			}
			if mode != "missing-factor" {
				active := 0
				if mode == "enrolled-factor" || mode == "mfa-enabled" {
					active = 1
				}
				if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES($1,$2,1,$3,decode(repeat('01',16),'hex'),'identity.password.signup')`, requestTestTenant, requestTestUser, active); e != nil {
					t.Fatal(e)
				}
				if mode == "mfa-enabled" {
					// Confirmed factor metadata is fixture bootstrap; this test issues
					// a challenge but never claims to verify its factor ciphertext.
					enrollment, _ := identity.NewCommandID()
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.mfa.enable',decode(repeat('02',32),'hex'),1,decode('01','hex'))`, mustCommandBytes(t, enrollment), requestTestTenant); e != nil {
						t.Fatal(e)
					}
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.mfa.enable')`, mustCommandBytes(t, enrollment), requestTestTenant); e != nil {
						t.Fatal(e)
					}
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,'AgICAgICAgICAgICAgICAg',2,1,1,'SHA1',6,30,1,'fixture',decode('01','hex'),$3,'identity.mfa.enable',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',clock_timestamp())`, requestTestTenant, requestTestUser, mustCommandBytes(t, enrollment)); e != nil {
						t.Fatal(e)
					}
				}
			}
			id, _ := identity.NewCommandID()
			flowID, _ := identity.NewPreAuthTransactionID()
			rawCookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{101}, 32))
			token, _ := session.ParseToken(rawCookie)
			cookie := auth.NewBearerCredential(rawCookie)
			remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
			now := time.Now().UTC().Truncate(time.Microsecond)
			binding := session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: requestTestTenant, Action: "identity.magic-link.consume", Origin: "https://app.test", CallbackURL: "https://app.test/login", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			digest, _ := token.PreAuthDigest(flowKey, binding)
			flow, _ := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
			if e := sessionpg.InsertPreAuth(ctx, requestTestTx{pool}, storage, flow); e != nil {
				t.Fatal(e)
			}
			key, _ := identity.NewIdempotencyKey([]byte("magic-request-" + mode))
			caller := authorization.DecisionContext{PolicyRevision: 3, CorrelationID: string(id), Request: authorization.Request{Tenant: requestTestTenant, Action: "identity.magic-link.request", Subject: authorization.Subject{ID: "ingress", Kind: authorization.SubjectServiceAccount}}}
			r := magiclink.RequestRequest{TenantID: requestTestTenant, CommandID: id, Email: "person@example.test", Intent: magiclink.SignInOnly, Callback: "https://app.test/login", IdempotencyKey: key, PreAuthID: flowID, Cookie: cookie, Caller: caller, Origin: "https://app.test", Network: "192.0.2.1", Device: "fixture"}
			if mode == "absent" {
				r.Email = "absent@example.test"
			}
			if mode == "foreign-cookie" {
				r.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{102}, 32)))
			}
			if mode == "audit-failure" {
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.records ADD CONSTRAINT magic_test_reject CHECK(action<>'identity.magic-link.request') NOT VALID`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.records DROP CONSTRAINT magic_test_reject`); e != nil {
						t.Error("fixture constraint cleanup", e)
					}
				}()
			}
			if mode == "commit" {
				type result struct {
					out magiclink.RequestResult
					err error
				}
				start := make(chan struct{})
				observed := make(chan result, 2)
				for range 2 {
					go func() { <-start; out, e := public.Request(ctx, r); observed <- result{out, e} }()
				}
				close(start)
				winners := 0
				for range 2 {
					result := <-observed
					if result.err == nil && result.out.Accepted {
						winners++
					} else if result.out.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("competing identical request failed outside bounded busy outcome", result.err)
					}
				}
				if winners == 0 {
					t.Fatal("competing original request had no winner")
				}
			}
			out, e := public.Request(ctx, r)
			if mode == "foreign-cookie" {
				if e == nil || out.Accepted {
					t.Fatal("foreign browser accepted")
				}
				return
			}
			if mode == "audit-failure" {
				if e == nil || out.Accepted {
					t.Fatal("failed mandatory audit acknowledged request")
				}
				if _, e := identity.ParseCommandID(string(out.CommandID)); e != nil {
					t.Fatal("failed request lost original recovery identity", e)
				}
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$1)+(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$2)+(SELECT count(*) FROM audit.records WHERE correlation_id=$1)`, string(out.CommandID), mustCommandBytes(t, out.CommandID)).Scan(&effects); e != nil || effects != 0 {
					t.Fatal("failed protected audit left issuance/delivery effects", e)
				}
				return
			}
			if e != nil || !out.Accepted || out.Validate() != nil {
				t.Fatal("public request", e)
			}
			again, e := public.Request(ctx, r)
			if e != nil || again != out {
				t.Fatal("retry changed original request", e)
			}
			commandBytes, _ := base64.RawURLEncoding.DecodeString(string(out.CommandID))
			var messages, grants int
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, commandBytes, string(out.CommandID)).Scan(&messages, &grants); e != nil {
				t.Fatal(e)
			}
			want := 0
			if mode == "commit" || mode == "mfa-enabled" {
				want = 1
			}
			if messages != want || grants != want {
				t.Fatal("suppression/retry did not preserve atomic single effects")
			}
			q := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: out.CommandID, AnonymousFlowID: string(r.PreAuthID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.request"}
			if recovered, e := public.RecoverRequest(ctx, q, caller); e != nil || recovered != out {
				t.Fatal("proof-free recovery changed acknowledgement", e)
			}
			changedEmail := r
			changedEmail.Email = "foreign@example.test"
			var conflict identity.ConflictError
			if _, e := public.Request(ctx, changedEmail); !errors.As(e, &conflict) {
				t.Fatal("changed raw intent reused original request key", e)
			}
			if mode == "commit" {
				proof := captureMagicLinkDelivery(t, ctx, pool, config, crypto)
				workerHistoryInstalled = true
				verifierService, e := capability.NewService(config.Issuer.Crypto)
				if e != nil {
					t.Fatal(e)
				}
				inspector, e := magiclink.NewInspector(magiclink.InspectionConfig{Verifier: verifierService, Tenant: requestTestTenant, Issuer: config.IssuerURL, Audience: config.Issuer.Audience, Callbacks: config.Callbacks, MaximumLifetime: config.Lifetime, Timeout: time.Second})
				if e != nil {
					t.Fatal(e)
				}
				for range 2 {
					if inspection, e := inspector.Inspect(ctx, magiclink.InspectionRequest{Token: proof, Callback: r.Callback}); e != nil || !inspection.SignatureValid {
						t.Fatal("captured delivery cannot be safely inspected", e)
					}
				}
				var remaining uint32
				if e = pool.Raw().QueryRow(ctx, `SELECT max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(out.CommandID)).Scan(&remaining); e != nil || remaining != 1 {
					t.Fatal("scanner inspection consumed delivered grant", e)
				}
				t.Run("original MFA primary reconstruction", func(t *testing.T) {
					testMFAOriginalPrimaryReconstruction(t, ctx, pool, service, proof, flow, caller)
				})
				lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{104}, 32))
				csrf, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{105}, 32))
				cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-magic", SameSite: http.SameSiteLaxMode})
				consumer, e := NewConsumeService(service, ConsumeConfig{ConfigurationID: "magic-consume-v1", PolicyNamespace: "users", Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookiePolicy}, CSRF: csrf})
				if e != nil {
					t.Fatal("consumer composition", e)
				}
				consumeID, _ := identity.NewCommandID()
				consumeCaller := caller
				consumeCaller.Request.Action = "identity.magic-link.consume"
				consumeCaller.CorrelationID = string(consumeID)
				consume := magiclink.ConsumeRequest{TenantID: r.TenantID, CommandID: consumeID, Token: proof, Callback: r.Callback, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: consumeCaller, Origin: r.Origin, Network: r.Network, Device: r.Device}
				for range 2 {
					user, challenge, lifetime, e := consumer.ConsumeRateSource(ctx, consume)
					if e != nil || user != requestTestUser || challenge == "" || lifetime != config.Lifetime {
						t.Fatal("native rate source lost original grant identity or lifetime", e)
					}
					if e = pool.Raw().QueryRow(ctx, `SELECT max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(out.CommandID)).Scan(&remaining); e != nil || remaining != 1 {
						t.Fatal("rate-source lookup consumed or renewed grant", e)
					}
				}
				for name, mutate := range map[string]func(*magiclink.ConsumeRequest){
					"stale-query-revision": func(r *magiclink.ConsumeRequest) { r.Caller.PolicyRevision = 2 },
					"foreign-query-resource": func(r *magiclink.ConsumeRequest) {
						r.Caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: "foreign"}
					},
				} {
					t.Run(name, func(t *testing.T) {
						denied := consume
						denied.Caller = consume.Caller.Clone()
						mutate(&denied)
						if user, challenge, lifetime, e := consumer.ConsumeRateSource(ctx, denied); e == nil || user != "" || challenge != "" || lifetime != 0 {
							t.Fatal("unauthorized original-source disclosure", e)
						}
					})
				}
				cancelled, stop := context.WithCancel(ctx)
				stop()
				if user, challenge, lifetime, e := consumer.ConsumeRateSource(cancelled, consume); !errors.Is(e, context.Canceled) || user != "" || challenge != "" || lifetime != 0 {
					t.Fatal("cancelled original-source disclosure", e)
				}
				assertUnconsumed := func(t *testing.T) {
					t.Helper()
					var sessions, remaining int
					if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_sessions.sessions),max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(out.CommandID)).Scan(&sessions, &remaining); e != nil || sessions != 0 || remaining != 1 {
						t.Fatal("denial left session or consumed original grant", e)
					}
				}
				for name, mutate := range map[string]func(*magiclink.ConsumeRequest){
					"foreign-cookie": func(c *magiclink.ConsumeRequest) {
						c.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{106}, 32)))
					},
					"foreign-callback": func(c *magiclink.ConsumeRequest) { c.Callback = "https://app.test/login?foreign=1" },
					"foreign-origin":   func(c *magiclink.ConsumeRequest) { c.Origin = "https://foreign.test" },
					"foreign-tenant": func(c *magiclink.ConsumeRequest) {
						c.TenantID = "AAAAAAAAAAAAAAAAAAAAAw"
						c.Caller.Request.Tenant = "AAAAAAAAAAAAAAAAAAAAAw"
					},
				} {
					t.Run(name, func(t *testing.T) {
						denied := consume
						denied.Caller = consume.Caller.Clone()
						denied.CommandID, _ = identity.NewCommandID()
						mutate(&denied)
						if user, challenge, lifetime, e := consumer.ConsumeRateSource(ctx, denied); e == nil || user != "" || challenge != "" || lifetime != 0 {
							t.Fatal("foreign source exposed rate identity", e)
						}
						result, e := consumer.Consume(ctx, denied)
						if e == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
							t.Fatal("foreign consume input authenticated or delivered custody", e)
						}
						assertUnconsumed(t)
					})
				}
				t.Run("enrolled-after-delivery", func(t *testing.T) {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, requestTestTenant, requestTestUser); e != nil {
						t.Fatal(e)
					}
					denied := consume
					denied.CommandID, _ = identity.NewCommandID()
					result, e := consumer.Consume(ctx, denied)
					if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("post-delivery MFA enrollment bypassed", e)
					}
					assertUnconsumed(t)
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0 WHERE tenant_id=$1 AND user_id=$2`, requestTestTenant, requestTestUser); e != nil {
						t.Fatal(e)
					}
				})
				t.Run("late-audit-rollback", func(t *testing.T) {
					// A durable abort retires its one-use grant; it does not reset
					// the proof for a different command. Give this attempt its own
					// genuinely requested and delivered link/browser flow.
					failedRequest := r
					failedRequest.CommandID, _ = identity.NewCommandID()
					failedRequest.PreAuthID, _ = identity.NewPreAuthTransactionID()
					failedRequest.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("magic-consume-audit-failure"))
					failedBinding := binding
					failedBinding.ID = failedRequest.PreAuthID
					failedDigest, e := token.PreAuthDigest(flowKey, failedBinding)
					if e != nil {
						t.Fatal(e)
					}
					failedFlow, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: failedBinding, Cookie: failedDigest, Version: 1})
					if e != nil {
						t.Fatal(e)
					}
					if e = sessionpg.InsertPreAuth(ctx, requestTestTx{pool}, storage, failedFlow); e != nil {
						t.Fatal(e)
					}
					failedIssued, e := public.Request(ctx, failedRequest)
					if e != nil || !failedIssued.Accepted {
						t.Fatal("rollback link request", e)
					}
					failedProof := captureMagicLinkDelivery(t, ctx, pool, config, crypto, true)
					// Reject the provisional success audit, but permit the mandatory
					// failure audit needed to durably abort and release the reservation.
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.records ADD CONSTRAINT magic_consume_reject CHECK(action<>'identity.magic-link.consume' OR outcome<>1) NOT VALID`); e != nil {
						t.Fatal(e)
					}
					denied := consume
					denied.CommandID, _ = identity.NewCommandID()
					denied.PreAuthID, denied.Token = failedRequest.PreAuthID, failedProof
					result, e := consumer.Consume(ctx, denied)
					if _, cleanup := pool.Raw().Exec(ctx, `ALTER TABLE audit.records DROP CONSTRAINT magic_consume_reject`); cleanup != nil {
						t.Fatal("audit fixture cleanup", cleanup)
					}
					if e == nil || result.Outcome != identity.CommitOutcomeNotCommitted || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
						t.Fatal("mandatory audit failure delivered a session", e)
					}
					assertUnconsumed(t)
					var state string
					var uses int
					if e := pool.Raw().QueryRow(ctx, `SELECT state,uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(failedIssued.CommandID)).Scan(&state, &uses); e != nil || state != "released" || uses != 0 {
						t.Fatal("rollback did not retain retired one-use evidence", e)
					}
				})
				type consumeAttempt struct {
					result magiclink.ConsumeResult
					err    error
				}
				startConsume := make(chan struct{})
				attempts := make(chan consumeAttempt, 2)
				for range 2 {
					go func() {
						<-startConsume
						result, err := consumer.Consume(ctx, consume)
						attempts <- consumeAttempt{result, err}
					}()
				}
				close(startConsume)
				var consumed magiclink.ConsumeResult
				deliveries := 0
				for range 2 {
					attempt := <-attempts
					if attempt.err != nil || (attempt.result.Outcome != identity.CommitOutcomeCommitted && attempt.result.Outcome != identity.CommitOutcomeInProgress) {
						t.Fatal("competing consumption failed outside bounded busy outcome", attempt.err)
					}
					if attempt.result.Session.Token != (session.Token{}) {
						deliveries++
						consumed = attempt.result
					}
				}
				if deliveries != 1 {
					t.Fatal("competing original consume did not deliver exactly one session")
				}
				e = nil
				if e != nil || consumed.Outcome != identity.CommitOutcomeCommitted || consumed.Session.Replayed {
					var invalid identity.InvalidInputError
					if errors.As(e, &invalid) {
						t.Log("invalid boundary", invalid.Field)
					}
					t.Fatal("public consumption", e)
				}
				if _, e := consumed.Session.Session.Bindings(); e != nil {
					t.Fatal("missing issued session", e)
				}
				bearer, e := consumed.Session.Token.Reveal()
				if e != nil || bearer == "" || consumed.Session.Cookie.Name != "__Host-magic" || !consumed.Session.Cookie.Secure || !consumed.Session.Cookie.HttpOnly || consumed.Session.Cookie.Value != "" {
					t.Fatal("committed session missing exact transport custody", e)
				}
				if _, e := consumed.CSRFToken.Reveal(); e != nil {
					t.Fatal("committed browser session missing CSRF custody", e)
				}
				parsed, e := session.ParseToken(bearer)
				if e != nil {
					t.Fatal("issued bearer invalid", e)
				}
				credential, e := session.NewCredential(session.CredentialCookie, parsed)
				if e != nil {
					t.Fatal(e)
				}
				reader, e := sessionpg.NewMagicLinkSessionService(pool, sessionpg.MagicLinkSessionServiceConfig{Repository: storage, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: "magic-deployment", PolicyNamespace: "users", Audience: "identity"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
				if e != nil {
					t.Fatal("native session reader composition", e)
				}
				if live, e := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); e != nil || !live.Authenticated {
					t.Fatal("issued session cannot authenticate through current authority", e)
				}
				if e = pool.Raw().QueryRow(ctx, `SELECT max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(out.CommandID)).Scan(&remaining); e != nil || remaining != 0 {
					t.Fatal("session issuance did not consume original grant", e)
				}
				replayed, e := consumer.Consume(ctx, consume)
				if e != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Session.Replayed || replayed.Session.Cookie.Value != "" {
					t.Fatal("consumption retry recreated transport custody", e)
				}
				if _, e := replayed.Session.Token.Reveal(); e == nil {
					t.Fatal("consumption retry revealed bearer")
				}
				if _, e := replayed.CSRFToken.Reveal(); e == nil {
					t.Fatal("consumption retry revealed CSRF")
				}
				consumeQuery := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: consumeID, AnonymousFlowID: string(r.PreAuthID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.consume"}
				if recovered, e := consumer.RecoverConsume(ctx, consumeQuery, consumeCaller); e != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Cookie.Value != "" {
					t.Fatal("proof-free consumption recovery changed original acknowledgement", e)
				}
				t.Run("actual-http-postgres", func(t *testing.T) {
					exerciseMagicLinkHTTPPostgres(t, ctx, pool, service, consumer, config, crypto, binding, flowKey, lookup, cookiePolicy)
				})
			}
			if mode == "mfa-enabled" {
				proof := captureMagicLinkDelivery(t, ctx, pool, config, crypto, workerHistoryInstalled)
				workerHistoryInstalled = true
				grant, _, _, _, err := service.issuer.ReadMagicLinkOrigin(ctx, pool, proof)
				if err != nil || grant.Payload().Caveats["magiclink.factor-version"] != "1" || grant.Payload().Subject != string(requestTestUser) {
					t.Fatal("MFA primary delivery lost original factor/subject", err)
				}
				lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{104}, 32))
				csrf, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{105}, 32))
				cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-magic", SameSite: http.SameSiteLaxMode})
				native := public.(*RequestService)
				consumer, err := NewConsumeService(native, ConsumeConfig{ConfigurationID: "magic-mfa-v1", PolicyNamespace: "users", Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookiePolicy}, CSRF: csrf, MFA: &MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3}})
				if err != nil {
					t.Fatal(err)
				}
				consumeID, _ := identity.NewCommandID()
				consumeCaller := caller.Clone()
				consumeCaller.Request.Action = "identity.magic-link.consume"
				consumeCaller.CorrelationID = string(consumeID)
				consume := magiclink.ConsumeRequest{TenantID: r.TenantID, CommandID: consumeID, Token: proof, Callback: r.Callback, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: consumeCaller, Origin: r.Origin, Network: r.Network, Device: r.Device}
				foreign := consume
				foreign.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{102}, 32)))
				if denied, e := consumer.Consume(ctx, foreign); e == nil || denied.Challenge.Proof.ValidateBounds(32, 4096) == nil || denied.Session.Token != (session.Token{}) {
					t.Fatal("foreign browser received MFA challenge")
				}
				failed := consume
				failed.CommandID, _ = identity.NewCommandID()
				failed.Caller = consumeCaller.Clone()
				failed.Caller.CorrelationID = string(failed.CommandID)
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.records ADD CONSTRAINT mfa_challenge_reject CHECK(action<>'identity.magic-link.consume' OR outcome<>1) NOT VALID`); e != nil {
					t.Fatal(e)
				}
				denied, denyErr := consumer.Consume(ctx, failed)
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.records DROP CONSTRAINT mfa_challenge_reject`); e != nil {
					t.Fatal(e)
				}
				if denyErr == nil || denied.Challenge.Proof.ValidateBounds(32, 4096) == nil || denied.Session.Token != (session.Token{}) {
					t.Fatal("failed challenge audit disclosed credentials")
				}
				var failedContinuations, failedChildren, failedParentUses int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations WHERE origin_command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2),(SELECT uses FROM capability_identity_one_use WHERE capability_id=$3)`, mustCommandBytes(t, failed.CommandID), string(failed.CommandID), grant.Payload().ID).Scan(&failedContinuations, &failedChildren, &failedParentUses); e != nil || failedContinuations != 0 || failedChildren != 0 || failedParentUses != 0 {
					t.Fatal("failed challenge audit split primary/child transaction", failedContinuations, failedChildren, failedParentUses, e)
				}
				failedQuery := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: failed.CommandID, AnonymousFlowID: string(r.PreAuthID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.consume"}
				var originalFailure identity.UnavailableError
				if recovered, e := consumer.RecoverConsume(ctx, failedQuery, failed.Caller); !errors.As(e, &originalFailure) || recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Challenge.Proof.ValidateBounds(32, 4096) == nil {
					t.Fatal("failed challenge cannot recover without delivery", e)
				}
				// Proven abort retires its reserved parent; never resurrect it for
				// another command. Request a genuine successor on the unchanged flow.
				successor := r
				successor.CommandID, _ = identity.NewCommandID()
				successor.Caller = r.Caller.Clone()
				successor.Caller.CorrelationID = string(successor.CommandID)
				successor.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("mfa-parent-after-audit-failure"))
				if issued, e := public.Request(ctx, successor); e != nil || !issued.Accepted {
					t.Fatal("retired primary could not request successor", e)
				}
				proof = captureMagicLinkDelivery(t, ctx, pool, config, crypto, true)
				grant, _, _, _, err = native.issuer.ReadMagicLinkOrigin(ctx, pool, proof)
				if err != nil {
					t.Fatal(err)
				}
				consume.Token = proof
				result, err := consumer.Consume(ctx, consume)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.State != auth.SignInStateChallengeRequired || result.Challenge.ID == "" || result.Challenge.Method != "totp" || result.Challenge.Proof.ValidateBounds(32, 4096) != nil || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("enrolled primary login did not produce challenge-only commit", err)
				}
				childCrypto, err := capability.NewService(config.Issuer.Crypto)
				if err != nil {
					t.Fatal(err)
				}
				child, err := childCrypto.Verify(ctx, result.Challenge.Proof, "identity.mfa.complete", config.Issuer.Audience)
				if err != nil || child.Payload().ID != string(result.Challenge.ID) || child.Payload().Subject != string(requestTestUser) || child.Payload().Operation != "identity.mfa.complete" {
					t.Fatal("challenge proof lost owned scope", err)
				}
				reader, e := mfapg.NewContinuationReader(pool, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				continuation, e := reader.Read(ctx, child, config.IssuerURL)
				if e != nil {
					t.Fatal("new child cannot read actual continuation", e)
				}
				scope, e := continuation.Bindings()
				originalRemember, _ := remember.Bindings()
				actualRemember, _ := scope.RememberPolicy.Bindings()
				if e != nil || scope.SourcePreAuthID != r.PreAuthID || string(scope.PrimaryProofID) != grant.Payload().ID || scope.PrimaryProofDigest != grant.EnvelopeDigest() || scope.MaxAttempts != 3 || actualRemember != originalRemember || !scope.PrimaryProofExpiresAt.Equal(grant.Payload().ExpiresAt) || scope.ExpiresAt.After(grant.Payload().ExpiresAt) {
					t.Fatal("continuation changed primary/browser/remember/budget", e)
				}
				var continuations, sessions, parentUses, children int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations WHERE origin_command_id=$1),(SELECT count(*) FROM magic_sessions.session_issuances WHERE command_id=$1),(SELECT uses FROM capability_identity_one_use WHERE capability_id=$2),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$3 AND purpose='identity.mfa.complete')`, mustCommandBytes(t, consumeID), grant.Payload().ID, string(consumeID)).Scan(&continuations, &sessions, &parentUses, &children); err != nil || continuations != 1 || sessions != 0 || parentUses != 1 || children != 1 {
					t.Fatal("challenge/primary effects were not atomic without session", continuations, sessions, parentUses, children, err)
				}
				again, err := consumer.Consume(ctx, consume)
				if err != nil || again.Outcome != identity.CommitOutcomeCommitted || again.Challenge.Proof.ValidateBounds(32, 4096) == nil || again.Session.Token != (session.Token{}) {
					t.Fatal("challenge retry redelivered a credential", err)
				}
				query := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: consumeID, AnonymousFlowID: string(r.PreAuthID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.consume"}
				recovered, e := consumer.RecoverConsume(ctx, query, consumeCaller)
				if e != nil || recovered.State != auth.SignInStateChallengeRequired || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Challenge.Proof.ValidateBounds(32, 4096) == nil || recovered.Session.Token != (session.Token{}) {
					t.Fatal("challenge recovery misclassified or redelivered", e)
				}
				t.Run("native HTTP challenge", func(t *testing.T) {
					exerciseMagicLinkHTTPPostgres(t, ctx, pool, native, consumer, config, crypto, binding, flowKey, lookup, cookiePolicy)
				})
			}
			changed := r
			changed.Callback = "https://app.test/login?changed=1"
			if result, e := public.Request(ctx, changed); e == nil || result.Accepted {
				t.Fatal("foreign callback accepted")
			}
		})
	}
	t.Run("prospective-native-preparation", func(t *testing.T) {
		exerciseProspectiveRequestGeneration(t, ctx, pool, config, keys, flowKey, normalization)
	})
}

func mustCommandBytes(t *testing.T, id identity.CommandID) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func captureMagicLinkDelivery(t *testing.T, ctx context.Context, pool *database.Pool, c RequestConfig, crypto *envelope.Service, historyInstalled ...bool) capability.Proof {
	return captureMagicLinkDeliveryFor(t, ctx, pool, c, crypto, "person@example.test", len(historyInstalled) != 0 && historyInstalled[0])
}

func captureMagicLinkDeliveryFor(t *testing.T, ctx context.Context, pool *database.Pool, c RequestConfig, crypto *envelope.Service, address string, historyInstalled bool) capability.Proof {
	t.Helper()
	history, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 20, WorkerVersion: 23, PolicyVersion: 24, KeyedVersion: 25, StateVersion: 26}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 23 && !historyInstalled {
			if _, err = pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("worker forward history", err)
			}
		}
	}
	authz, _ := authorization.NewDecisionService(requestTestWorkerPolicy{})
	policy := delivery.DefaultConfig()
	policy.Production = true
	policy.DedupeTTL = 25 * time.Hour
	templates := []delivery.Template{{ID: "magic-link", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Sign in: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://app.test"}, MaxRenderedBytes: 4096}}
	s, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "magic-mail", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {92}}, ActiveEnvelopeKeyID: "magic-mail", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, Coordinator: c.Coordinator, PolicyID: "login", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{103}, Policies: map[uint64]delivery.Config{1: policy}, StateTracking: true}, crypto, authz, templates)
	if err != nil {
		t.Fatal("worker composition", err)
	}
	var proof capability.Proof
	calls := 0
	worker, err := s.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "magic-worker", Request: authorization.Request{Tenant: requestTestTenant, Action: "identity.delivery.process", Subject: authorization.Subject{ID: "magic-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "magic-worker"}}}, ProviderConfigVersion: 1}, requestTestSender(func(_ context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		if a.Recipient != address || !strings.HasPrefix(string(a.Body), "Sign in: ") {
			return delivery.DeliveryResult{}, delivery.ErrInvalidInput
		}
		link, e := url.Parse(strings.TrimPrefix(string(a.Body), "Sign in: "))
		if e != nil || link.RawQuery != "" || !strings.HasPrefix(link.Fragment, "token=") {
			return delivery.DeliveryResult{}, delivery.ErrInvalidInput
		}
		proof, e = capability.ParseProof(strings.TrimPrefix(link.Fragment, "token="), c.Issuer.Crypto.Limits)
		if e != nil {
			return delivery.DeliveryResult{}, delivery.ErrInvalidInput
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || processed.Completion.State != delivery.StateDelivered || calls != 1 {
		t.Fatal("original committed delivery", err)
	}
	if next, e := worker.ProcessOne(ctx); e != nil || next.Claimed || calls != 1 {
		t.Fatal("delivery repeated after acknowledgement", e)
	}
	return proof
}
