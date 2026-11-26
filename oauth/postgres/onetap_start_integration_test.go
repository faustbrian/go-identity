//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
)

const (
	oneTapStartTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
	oneTapStartActor  = "AAAAAAAAAAAAAAAAAAAAAw"
	oneTapStartPolicy = "AAAAAAAAAAAAAAAAAAAABQ"
	oneTapStartOrigin = "https://identity.example"
)

// The application policy is finite and runs through the actual authorization
// snapshot, engine and decision service. No fixture replaces native admission.
type oneTapStartApplicationPolicy struct{}

func (oneTapStartApplicationPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	deny := authorization.Decision{Outcome: authorization.Deny}
	if err := ctx.Err(); err != nil {
		return deny, err
	}
	if r.Tenant != oneTapStartTenant || r.Subject.Kind != authorization.SubjectServiceAccount || r.Subject.ID != oneTapStartActor {
		return deny, nil
	}
	if r.Action != oneTapStartOperationID && r.Action != oneTapCallbackPurpose {
		return deny, nil
	}
	requestAdmission := r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(r.Action)
	originalFlow := r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != ""
	if requestAdmission || originalFlow {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return deny, nil
}

// This is the documented external velocity-store seam. The real policy,
// coordinator, evaluator, evidence custody and PostgreSQL security audit remain
// in use. The values model an admitted first request, not authentication.
type oneTapStartCounterBoundary struct{ calls int }

func (s *oneTapStartCounterBoundary) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	s.calls++
	b := c.Bindings()
	counters := make([]risk.Counter, 0, len(b.Targets))
	for _, target := range b.Targets {
		counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
	}
	return risk.NewCounterResult(c, risk.CounterCommitted, counters)
}

// No Google request is necessary to initiate a browser flow. Reject accidental
// validation through the provider's external signature seam in this start test.
type oneTapStartRejectingKeySet struct{}

func (oneTapStartRejectingKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return nil, errors.New("start must not validate a Google credential")
}

func oneTapStartIntegrationFixture(t *testing.T) (context.Context, *database.Pool, OneTapStartConfig, *oneTapStartCounterBoundary) {
	t.Helper()
	ctx, db := rpMigrationDatabase(t)
	pool, err := database.Connect(ctx, database.Config{DSN: db.Config().ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = db.Config().Database
		return nil
	}})
	if err != nil {
		t.Fatal("open fixture-owned primary pool", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("close fixture-owned pool", err)
		}
	})
	var databaseName string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil || databaseName != db.Config().Database {
		t.Fatal("primary pool escaped fixture-owned database", err)
	}

	// rpMigrationDatabase already installed immutable kernel versions 1..9.
	var history migrations.Source = kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 10, GlobalAuthorityID: "onetap-deployment", TenantIDs: []identity.TenantID{oneTapStartTenant}}
	history = kernel.RequestKeyMigrationSource{Base: history, Version: 11}
	history = kernel.RequestKeyPreparationMigrationSource{Base: history, Version: 12}
	history = kernel.RequestKeyExpiryMigrationSource{Base: history, Version: 13}
	history = kernel.PreparationMigrationSource{Base: history, Version: 14}
	history = kernel.AdmissionPreparationMigrationSource{Base: history, Version: 15}
	history = kernel.CounterPreparationMigrationSource{Base: history, Version: 16}
	history = kernel.OneTapStartPreparationErasureMigrationSource{Base: history, Version: 17}
	kernelHistory, err := history.Load(ctx)
	if err != nil {
		t.Fatal("load native start kernel history", err)
	}
	for _, m := range kernelHistory {
		if m.Version() > 9 {
			oneTapStartInstallMigration(t, ctx, db, m)
		}
	}
	for _, source := range []migrations.Source{
		sessionpg.MigrationSource{Schema: "onetap_sessions", Version: 30},
		sessionpg.PreAuthMigrationSource{Schema: "onetap_sessions", Version: 31},
		sessionpg.PreAuthReleaseMigrationSource{Schema: "onetap_sessions", Version: 32},
		sessionpg.PreAuthIssueMigrationSource{Schema: "onetap_sessions", Version: 33},
		sessionpg.OneTapStartPreAuthMigrationSource{Schema: "onetap_sessions", Version: 34, ValidationVersion: 35},
		MigrationSource{Schema: "onetap_oauth", Version: 40},
		OneTapCallbackGrantMigrationSource{Schema: "onetap_oauth", Version: 41},
	} {
		items, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load native start owner history", err)
		}
		for _, m := range items {
			oneTapStartInstallMigration(t, ctx, db, m)
		}
	}
	oneTapStartInstallParticipants(t, ctx, db)

	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: oneTapStartPolicy, Revision: 9, Evaluator: oneTapStartApplicationPolicy{}})
	if err != nil {
		t.Fatal("application policy snapshot", err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal("application authorization engine", err)
	}
	authorize, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal("application decision service", err)
	}
	query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {71}}, QueryPolicy: &query, AdmissionPolicy: &query}

	signing := bytes.Repeat([]byte{72}, 32)
	signer, err := capability.NewHMACSHA256Signer("onetap-signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: oneTapStartOrigin, ID: "onetap-signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewGoogleAccountsProvider(oauth.OIDCConfig{
		ID: "google", Version: 7, Issuer: "https://accounts.google.com",
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", TokenEndpoint: "https://oauth2.googleapis.com/token", RedirectURI: oneTapStartOrigin + "/google/callback",
		ClientID: "onetap-original-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"openid", "email", "profile"}, Algorithms: []string{"RS256"}, KeySet: oneTapStartRejectingKeySet{}, Clock: clock.System{}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal("configured Google provider", err)
	}
	t.Cleanup(provider.Close)
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	counter := &oneTapStartCounterBoundary{}
	config := OneTapStartConfig{
		Schema: "onetap_oauth", ConfigurationID: "onetap-start-v1", GlobalAuthorityID: "onetap-deployment", TenantID: oneTapStartTenant, Provider: provider,
		Issuance: session.PreAuthIssuerConfig{ActorID: oneTapStartActor, Action: "identity.oauth.onetap-start", Origin: oneTapStartOrigin, PolicyID: oneTapStartPolicy, PolicyVersion: 9, Clock: clock.System{}, MaximumDuration: 3 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: cookie},
		Session:  sessionpg.Config{Schema: "onetap_sessions", MaximumDuration: time.Second},
		Risk:     oneTapStartIntegrationRisk(t, pool, counter), Coordinator: coordinator,
		Capability:            capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: oneTapStartOrigin, Signer: signer, Resolver: keys, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {74}}, PreparationTimeout: time.Second},
		CapabilityPreparation: capabilitypg.IssuancePreparationConfig{Deployment: "onetap-deployment", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{75}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "onetap-signing", HMAC: signing}}, Clock: time.Now},
		MaximumDuration:       3 * time.Second, AuditRetentionPolicyVersion: 1, IntentKey: [32]byte{76}, CurrentEnvelopeKey: "onetap", EnvelopeKeys: map[string][]byte{"onetap": bytes.Repeat([]byte{77}, 32)},
	}
	return ctx, pool, config, counter
}

func oneTapStartInstallMigration(t *testing.T, ctx context.Context, db *pgx.Conn, m migrations.Migration) {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal("begin owner migration", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, m.UpSQL()); err != nil {
		t.Fatal("install owner migration", m.Name(), err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit owner migration", m.Name(), err)
	}
}

var oneTapParticipantFixture = struct {
	sync.Mutex
	installedAuditRoles bool
}{}

func oneTapStartInstallParticipants(t *testing.T, ctx context.Context, db *pgx.Conn) {
	t.Helper()
	// All One Tap fixtures in this test process use the same disposable
	// loopback cluster, but each owns a separate database. The first real
	// install must reserve the cluster-wide role names without collisions.
	// Later fixture databases reuse only those previously committed roles.
	oneTapParticipantFixture.Lock()
	defer oneTapParticipantFixture.Unlock()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL search_path = public, pg_catalog`); err != nil {
		t.Fatal(err)
	}
	if !oneTapParticipantFixture.installedAuditRoles {
		if _, err := tx.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
			t.Fatal("audit installation preflight", err)
		}
	}
	for _, files := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations(), capabilitypg.Migrations()} {
		entries, err := fs.ReadDir(files, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := fs.ReadFile(files, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, strings.Split(string(data), "-- +migrations Down")[0]); err != nil {
				t.Fatal("install actual participant", entry.Name(), err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit participant histories", err)
	}
	oneTapParticipantFixture.installedAuditRoles = true
}

func oneTapStartIntegrationRisk(t *testing.T, pool *database.Pool, counter *oneTapStartCounterBoundary) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal("actual risk policy", err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{78}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counted, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: counter, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal("actual counted risk coordinator", err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("actual decision audit sink", err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: 2 * time.Second, Counters: &counted,
		Sources: []risk.Source{{Name: "status", Version: "onetap-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: oneTapStartPolicy, Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		}},
	})
	if err != nil {
		t.Fatal("actual audited risk evaluator", err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{79}, 32), bytes.Repeat([]byte{80}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "onetap-risk-v1", Keys: []risk.EvidenceKey{evidence}}
}

func oneTapStartIntegrationRequest(t *testing.T, requestKey string) (onetap.BrowserStartRequestSpec, onetap.BrowserStartRequest) {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignUp, CancelOnTapOutside: false})
	if err != nil {
		t.Fatal(err)
	}
	options, err := onetap.NewBrowserStartOptions(prompt, onetap.OneTapButtonOptions{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte(requestKey))
	if err != nil {
		t.Fatal(err)
	}
	spec := onetap.BrowserStartRequestSpec{TenantID: oneTapStartTenant, Origin: oneTapStartOrigin, Network: "192.0.2.19", Device: "trusted-onetap-browser", Key: key, Options: options, Remember: remember}
	request, err := onetap.NewBrowserStartRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	return spec, request
}

func TestOneTapStartCommitsOriginalBrowserFlowAndTokenlessReplay(t *testing.T) {
	ctx, pool, config, counter := oneTapStartIntegrationFixture(t)
	owner, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal("public native One Tap start construction", err)
	}
	spec, request := oneTapStartIntegrationRequest(t, "native-onetap-original-start")
	options, remember := spec.Options, spec.Remember
	started := time.Now().UTC()
	first, err := owner.Start(ctx, request)
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.Replayed {
		var mapped, reserved, prepared int
		readErr := pool.Raw().QueryRow(ctx, `SELECT
		 (SELECT count(*) FROM identity.request_key_mappings WHERE route_id='identity.oauth.onetap-start'),
		 (SELECT count(*) FROM identity.commands WHERE purpose='identity.oauth.onetap-start'),
		 (SELECT count(*) FROM identity.commands WHERE purpose='identity.oauth.onetap-start' AND preparation_started_generation IS NOT NULL)`).Scan(&mapped, &reserved, &prepared)
		t.Fatalf("fresh public start did not commit: outcome=%v original=%t mappings=%d reserved=%d begun=%d counter_calls=%d diagnostic=%v: %v",
			first.Outcome, first.CommandID != "", mapped, reserved, prepared, counter.calls, readErr, err)
	}
	browser, ok := first.Browser()
	if !ok || browser.FlowID == "" || browser.ClientID != config.Provider.Profile().ClientID || browser.Origin != oneTapStartOrigin || browser.Nonce == "" || !browser.ExpiresAt.After(started) || browser.ExpiresAt.After(time.Now().UTC().Add(5*time.Minute)) {
		t.Fatal("fresh start lost bounded original Google browser result")
	}
	wantOptions, _ := options.Projection()
	gotOptions, err := browser.Options.Projection()
	if err != nil || !reflect.DeepEqual(gotOptions, wantOptions) {
		t.Fatal("start changed exact selected prompt options", err)
	}
	if browser.Cookie.Name != "__Host-identity_flow" || browser.Cookie.Value != "" || browser.Cookie.Path != "/" || browser.Cookie.Domain != "" || !browser.Cookie.Secure || !browser.Cookie.HttpOnly || browser.Cookie.SameSite != http.SameSiteLaxMode || browser.Cookie.MaxAge <= 0 || browser.Cookie.MaxAge > 300 || browser.Cookie.Expires.After(browser.ExpiresAt) {
		t.Fatal("committed browser cookie lost original scope or lifetime")
	}
	token, err := browser.Token.Reveal()
	if err != nil || token == "" {
		t.Fatal("fresh committed start withheld original browser token", err)
	}
	selected := session.PreAuthProviderBinding{ProviderID: "google", ProviderVersion: config.Provider.Profile().Version, ClientID: browser.ClientID, Mode: session.PreAuthProviderCallback}
	flow, err := sessionpg.ReadProviderPreAuth(ctx, pool.Raw(), config.Session, oneTapStartTenant, browser.FlowID, selected)
	if err != nil {
		t.Fatal("actual native flow unavailable", err)
	}
	original, err := flow.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	binding := original.Transaction.Binding
	if binding.Intent.Action != "identity.oauth.onetap-start" || binding.Intent.TenantID != oneTapStartTenant || binding.Intent.Remember != remember || binding.Intent.Origin != spec.Origin || binding.Intent.CallbackURL != "" || binding.Intent.PolicyID != oneTapStartPolicy || binding.Intent.PolicyVersion != 9 || !binding.ExpiresAt.Equal(browser.ExpiresAt) || binding.ExpiresAt.Sub(binding.IssuedAt) != 5*time.Minute || browser.Nonce != base64.RawURLEncoding.EncodeToString(binding.Intent.Nonce[:]) {
		t.Fatal("public start did not retain exact original provider flow intent")
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.ProviderPreAuthDigest(config.Issuance.LookupKey, binding, selected)
	if err != nil || digest != original.Transaction.Cookie || flow.CheckProvider(time.Now().UTC(), binding, selected, digest) != nil {
		t.Fatal("released cookie does not prove original provider-bound browser", err)
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(first.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := base64.RawURLEncoding.Strict().DecodeString(string(browser.FlowID))
	if err != nil {
		t.Fatal(err)
	}
	assertCommitted := func() []byte {
		t.Helper()
		var flows, grants, evidence, capabilities, audits, events, users, sessions int
		var ciphertext []byte
		var erased bool
		err := pool.Raw().QueryRow(ctx, `SELECT
		 (SELECT count(*) FROM onetap_sessions.preauth_transactions),
		 (SELECT count(*) FROM onetap_oauth.onetap_callback_grants),
		 (SELECT count(*) FROM onetap_sessions.preauth_issuances WHERE command_id=$1),
		 (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$2 AND tenant_id=$3 AND purpose='identity.oauth.onetap-callback' AND state='issued' AND uses=0 AND max_uses=1 AND subject_id=$4 AND expires_at=$6),
		 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
		 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
		 (SELECT count(*) FROM identity.users),
		 (SELECT count(*) FROM onetap_sessions.sessions),
		 (SELECT proof_ciphertext FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$3 AND flow_id=$5 AND origin_command_id=$1 AND expires_at=$6),
		 (SELECT state='committed' AND preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL AND preparation_started_generation IS NOT NULL FROM identity.commands WHERE command_id=$1)`, command, string(first.CommandID), oneTapStartTenant, string(browser.FlowID), flowID, browser.ExpiresAt).Scan(&flows, &grants, &evidence, &capabilities, &audits, &events, &users, &sessions, &ciphertext, &erased)
		if err != nil || flows != 1 || grants != 1 || evidence != 1 || capabilities != 1 || audits != 1 || events != 1 || users != 0 || sessions != 0 || len(ciphertext) == 0 || !erased {
			t.Fatal("native start effects or terminal secret custody not conserved", flows, grants, evidence, capabilities, audits, events, users, sessions, erased, err)
		}
		if bytes.Contains(ciphertext, []byte(token)) || bytes.Contains(ciphertext, []byte(browser.Nonce)) {
			t.Fatal("native callback custody retained plaintext browser secrets")
		}
		return ciphertext
	}
	ciphertext := assertCommitted()
	charges := counter.calls
	if charges != 1 {
		t.Fatal("fresh start did not perform exactly one external velocity charge", charges)
	}
	restarted, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.Start(ctx, request)
	if err != nil || replay.CommandID != first.CommandID || replay.Outcome != identity.CommitOutcomeCommitted || !replay.Replayed {
		t.Fatal("same-key restart changed original committed outcome", err)
	}
	if _, ok := replay.Browser(); ok {
		t.Fatal("same-key replay released browser credentials or renewed flow")
	}
	if counter.calls != charges || !bytes.Equal(ciphertext, assertCommitted()) {
		t.Fatal("same-key replay charged or rewrote original custody")
	}
	q := identity.RecoveryQuery{CommandID: first.CommandID, TenantID: oneTapStartTenant, ActorID: oneTapStartActor,
		ActorKind: authorization.SubjectServiceAccount, OperationID: oneTapStartOperationID, RecordID: string(browser.FlowID), AnonymousFlowID: string(browser.FlowID)}
	receipt, err := restarted.recoverOneTap(ctx, q)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Binding.CommandID != first.CommandID ||
		receipt.Feature == nil || receipt.Feature.Operation != kernel.OneTapStartOperation() || receipt.Feature.AfterVersion != 1 {
		t.Fatal("authorized recovery did not retain the exact committed receipt", receipt.Outcome, err)
	}
	q.RecordID, q.AnonymousFlowID = "AAAAAAAAAAAAAAAAAAAAAg", "AAAAAAAAAAAAAAAAAAAAAg"
	if result, err := restarted.recoverOneTap(ctx, q); err == nil || result.Feature != nil {
		t.Fatal("scope-substituted recovery disclosed another flow's outcome")
	}

	for name, change := range map[string]func(*onetap.BrowserStartRequestSpec){
		"options": func(s *onetap.BrowserStartRequestSpec) {
			other, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignIn, CancelOnTapOutside: true})
			if err != nil {
				t.Fatal(err)
			}
			s.Options, err = onetap.NewBrowserStartOptions(other, onetap.OneTapButtonOptions{})
			if err != nil {
				t.Fatal(err)
			}
		},
		"remember": func(s *onetap.BrowserStartRequestSpec) {
			var err error
			s.Remember, err = session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
		},
		"tenant": func(s *onetap.BrowserStartRequestSpec) { s.TenantID = "AAAAAAAAAAAAAAAAAAAAAg" },
		"origin": func(s *onetap.BrowserStartRequestSpec) { s.Origin = "https://other.example" },
	} {
		t.Run("same key rejects substituted "+name, func(t *testing.T) {
			altered := spec
			change(&altered)
			request, err := onetap.NewBrowserStartRequest(altered)
			if err != nil {
				t.Fatal("valid alternate intent construction", err)
			}
			result, err := restarted.Start(ctx, request)
			if err == nil {
				t.Fatal("same key adopted changed original browser intent")
			}
			if _, ok := result.Browser(); ok {
				t.Fatal("denial disclosed browser credentials")
			}
			if counter.calls != charges || !bytes.Equal(ciphertext, assertCommitted()) {
				t.Fatal("denial changed original effects or charged risk")
			}
		})
	}
	t.Run("deferred failure withholds browser", func(t *testing.T) {
		proveOneTapStartDeferredCommitFailure(t, ctx, pool, config, counter)
	})
}

func proveOneTapStartDeferredCommitFailure(t *testing.T, ctx context.Context, pool *database.Pool, config OneTapStartConfig, counter *oneTapStartCounterBoundary) {
	t.Helper()
	chargesBefore := counter.calls
	// Fail the real COMMIT after flow, capability, grant, audit and lifecycle
	// staging. The fixture-owned sequence is not rolled back, so an unrelated
	// early denial cannot satisfy the test.
	if _, err := pool.Raw().Exec(ctx, `
 CREATE SEQUENCE onetap_oauth.commit_failure_observed;
 CREATE FUNCTION onetap_oauth.refuse_callback_custody_commit() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN
 PERFORM nextval('onetap_oauth.commit_failure_observed');
 RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='fixture requested abort';
 END $$;
 CREATE CONSTRAINT TRIGGER refuse_callback_custody_commit AFTER INSERT ON onetap_oauth.onetap_callback_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION onetap_oauth.refuse_callback_custody_commit();`); err != nil {
		t.Fatal("install deferred test fault", err)
	}
	owner, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	_, request := oneTapStartIntegrationRequest(t, "native-onetap-deferred-failure")
	result, err := owner.Start(ctx, request)
	if err == nil || result.CommandID == "" || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed COMMIT was reported as successful", result.Outcome, err)
	}
	if _, ok := result.Browser(); ok {
		t.Fatal("failed COMMIT released browser credentials")
	}
	command, err := base64.RawURLEncoding.DecodeString(string(result.CommandID))
	if err != nil || len(command) != 16 {
		t.Fatal("failure lost the exact original command")
	}
	var effects int
	var fired bool
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called,
  (SELECT count(*) FROM onetap_sessions.preauth_transactions) - 1 +
  (SELECT count(*) FROM onetap_sessions.preauth_issuances WHERE command_id=$1) +
  (SELECT count(*) FROM onetap_oauth.onetap_callback_grants WHERE origin_command_id=$1) +
  (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$2) +
  (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1) +
  (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)
  FROM onetap_oauth.commit_failure_observed`, command, string(result.CommandID)).Scan(&fired, &effects); err != nil || !fired || effects != 0 || counter.calls != chargesBefore+1 {
		t.Fatal("deferred COMMIT did not fail and roll back all Work effects", fired, effects, counter.calls-chargesBefore, err)
	}
}
