//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const otpTenant = "AAAAAAAAAAAAAAAAAAAAAQ"

// This is the explicit test policy seam, not a domain store or production
// policy default. It admits only the selected fixture tenant and two operations.
type otpGraphPolicy struct{}

func (otpGraphPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	outcome := authorization.Deny
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 7 && c.Request.Action == "identity.session.preauth-issue" && c.Request.Subject.ID == "preauth-service" && c.Request.Subject.Kind == authorization.SubjectServiceAccount {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 7}, nil
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && (c.Request.Action == "identity.otp.send" || c.Request.Action == "identity.delivery.process") {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}

type otpGraphSender struct{}

func (otpGraphSender) Send(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
	// Sending is a separate acceptance boundary. Construction/startup/Send must
	// never invoke a provider; the test does not schedule the delivery worker.
	panic("provider invoked before explicit worker scheduling")
}

func otpGraphConfiguration(t *testing.T, c reference.StoreConfiguration) (reference.StoreConfiguration, reference.ReferenceDependencies, deliverypg.WorkerConfig) {
	t.Helper()
	c.Velocity.Tenants = []string{otpTenant}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("otp-reference", [32]byte{0x41}, kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: otpGraphPolicy{}, PolicyVersion: 9})
	if err != nil {
		t.Fatal(err)
	}
	riskKey, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 4 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
	c.OTP = &reference.OTPSendConfiguration{
		BootstrapTenantIDs: []identity.TenantID{otpTenant},
		Store:              otppg.ContributorConfig{Schema: "otp_store", GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x57}, 32)}},
		Codec:              otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"wrap-1": bytes.Repeat([]byte{0x21}, 32)}, CurrentWrappingKey: "wrap-1", AttemptKeys: map[uint32][32]byte{7: {0x31}}, CodeKeys: map[uint32][32]byte{3: {0x41}, 4: {0x42}}, CurrentCodeKeyVersion: 4, MaximumDuration: time.Second},
		Coordinator:        coordinator, RequestKeys: requestKeys, Policy: policy, TemplateID: "otp-code", TemplateVersion: 1, LocaleChain: []string{"en"}, ProviderVersion: 1, PolicyID: "otp-policy", PolicyVersion: 7, PreAuthAction: "identity.otp.signin", IntentKey: [32]byte{0x67}, IdentifierKey: [32]byte{0x68}, Timeout: 3 * time.Second, RiskTimeout: 2 * time.Second, AuditTimeout: time.Second, RiskPolicyID: otpTenant, ConfigurationID: "otp-reference-v1", RiskKeys: []risk.EvidenceKey{riskKey},
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.Production = true
	c.Delivery = &reference.DeliveryConfiguration{Enqueue: deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {0x72}}, ActiveEnvelopeKeyID: "issue-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "test-sender", PolicyVersion: 1}}}, Coordinator: coordinator, PolicyID: "otp-policy", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{0x73}, Policies: map[uint64]delivery.Config{1: deliveryPolicy}, StateTracking: true}, Templates: []delivery.Template{{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "verification", Body: "{{.code}}", ContentType: "text/plain"}}}
	keys, err := keyring.New(map[string][]byte{"issue-envelope": bytes.Repeat([]byte{0x71}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	worker := deliverypg.WorkerConfig{ProviderConfigVersion: 1, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "worker-correlation", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "delivery-worker"}}}}
	return c, reference.ReferenceDependencies{EnvelopeKeys: keys, DeliverySender: otpGraphSender{}}, worker
}

func TestReferenceOTPRequiresProductionDeliveryProfile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	c, deps, _ := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	p := c.Delivery.Enqueue.Policies[1]
	p.Production = false
	c.Delivery.Enqueue.Policies[1] = p
	stores, err := reference.ComposeStores(c, deps)
	if err == nil {
		_ = stores.Close(ctx)
		t.Fatal("production reference accepted development delivery profile")
	}
}

// NATIVE-01/03/04/06: actual public reference graph, real primary/native counter
// owners, real kernel/OTP/encrypted delivery/audit/lifecycle participants. The
// historical-origin fixture proves conditional composition, NOT a fresh warmup.
// This initial partition is pre-auth; authenticated-session parity is separate.
func TestReferencePublicOTPCountsNativeIssuanceSuppressionAndReplay(t *testing.T) {
	testReferencePublicOTP(t, false)
}

func TestReferencePublicOTPSigninAndRecovery(t *testing.T) {
	testReferencePublicOTP(t, true)
}

func testReferencePublicOTP(t *testing.T, signin bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	var codes chan auth.OneTimeCode
	if signin {
		codes = make(chan auth.OneTimeCode, 1)
		configureReferenceSignin(t, &c)
		configureReferencePreAuth(t, &c)
		deps.DeliverySender = otpSigninCapture{codes: codes}
	}
	// A retained older provider must not satisfy the current OTP provider's
	// required worker. Native construction alone cannot enforce graph coverage.
	c.Delivery.Enqueue.Custody.ProviderProfiles[2] = deliverypg.ProviderProfile{Provider: "retained-sender", PolicyVersion: 1}
	deps.PostgreSQL = f.pool
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("owned feature stores", err)
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
	wrongWorker := worker
	wrongWorker.ProviderConfigVersion = 2
	if _, err := reference.ComposeWorkers(stores, providers, wrongWorker); err == nil {
		t.Fatal("retained provider worker satisfied missing OTP provider")
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal("actual delivery worker", err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	service, err := features.OTP()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Send(ctx, otp.SendRequest{}); err == nil {
		t.Fatal("uninitialized graph admitted workflow")
	}
	if signin {
		// Upgrade an already-populated Send-only deployment through the owned
		// source; do not replace or rewrite any original ledger entry.
		legacyConfig := c
		legacyOTP := *c.OTP
		legacyOTP.Signin = nil
		legacyOTP.PreAuth = nil
		legacyConfig.OTP = &legacyOTP
		legacy, err := reference.ComposeStores(legacyConfig, deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := legacy.Close(cleanup); err != nil {
				t.Error(err)
			}
		})
		installOTPGraphFixture(t, ctx, f, legacy)
		db := stdlib.OpenDBFromPool(f.pool.Raw())
		defer db.Close()
		backend, err := migrationdb.New(db)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(stores.MigrationSource(), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("populated Send-only to consuming Signin upgrade", err)
		}
		plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/session/postgres"}})
		if err != nil || len(plan.Plan.Steps) != 1 || plan.Plan.Steps[0].ToVersion != 1420 || plan.Plan.Steps[0].FromVersion != 0 {
			t.Fatal("independent initiation migration plan", err)
		}
		initiationKey, _ := identity.NewIdempotencyKey([]byte("original-initiation-upgrade"))
		applyRequest := reference.ReferenceMigrationApplyRequest{CommandID: "original_initiation_upgrade", Plan: plan.Plan, IdempotencyKey: initiationKey}
		applied, err := stores.ReferenceMigrationApply(ctx, applyRequest)
		if err != nil || applied.Result.State() != reference.MigrationApplied {
			t.Fatal("native initiation migration apply", err)
		}
		if replay, err := stores.ReferenceMigrationApply(ctx, applyRequest); err != nil || replay.Result.State() != reference.MigrationApplied {
			t.Fatal("same-command initiation migration replay", err)
		}
		check, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/otp/postgres", "identity/session/postgres"}})
		if err != nil || len(check.Statuses) != 2 {
			t.Fatal("upgraded ownership discovery", err)
		}
		for _, status := range check.Statuses {
			if status.Compatibility != reference.MigrationCompatible || status.CurrentVersion != status.RequiredVersion {
				t.Fatal("upgraded native owner incompatible", status.Module)
			}
		}
	} else {
		installOTPGraphFixture(t, ctx, f, stores)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("native startup", err)
	}
	if store, err := stores.RecoverVelocity(ctx, otpTenant); err == nil || store != nil {
		t.Fatal("fresh coverage was invented")
	}
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '61 minutes' WHERE tenant_id=$1 AND state='replaying'", otpTenant); err != nil {
		t.Fatal(err)
	}
	// Expire the actual initial five-second lease before explicit recovery.
	wait(ctx, t, 6*time.Second)
	if store, err := stores.RecoverVelocity(ctx, otpTenant); err != nil || store == nil {
		t.Fatal("historical covered activation", err)
	}
	var flow otp.SendFlow
	if signin {
		flow = issueOTPGraphPreAuth(t, ctx, features)
	} else {
		flow = insertOTPGraphPreAuth(t, ctx, f, c)
	}
	destination, _ := otp.NewDestinationInput("recipient@example.invalid")
	key, _ := identity.NewIdempotencyKey([]byte("first"))
	request := otp.SendRequest{TenantID: otpTenant, Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Tenant: otpTenant, Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}}}, Flow: flow, Channel: otp.ChannelEmail, Destination: destination, Purpose: otp.PurposeSignin, TargetID: "login", Network: "192.0.2.8", Device: "reference-device", IdempotencyKey: key}
	first, err := service.Send(ctx, request)
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.CommandID == "" {
		t.Fatal("native-counted public issuance", err)
	}
	if signin {
		assertOTPGraphCounts(t, ctx, f, 1, 1, 1, 3, 2)
	} else {
		assertOTPGraphCounts(t, ctx, f, 1, 1, 1, 2, 1)
	}
	if signin {
		proveReferenceSignin(t, ctx, stores, features, workers, f, request, first, codes)
		return
	}
	before := nativeAttemptFacts(t, ctx, f)
	again, err := service.Send(ctx, request)
	if err != nil || again != first {
		t.Fatal("original receipt replay", err)
	}
	if nativeAttemptFacts(t, ctx, f) != before {
		t.Fatal("replay changed original counter facts")
	}
	assertOTPGraphCounts(t, ctx, f, 1, 1, 1, 2, 1)
	changed := request
	changed.Device = "changed"
	if _, err := service.Send(ctx, changed); err == nil {
		t.Fatal("changed intent adopted original")
	}
	wrong := request
	kind, id, _, _ := flow.Bindings()
	if kind != otp.FlowAuthorizationPreAuthTransaction {
		t.Fatal("wrong fixture variant")
	}
	wrong.Flow, _ = otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(id), auth.NewBearerCredential(strings.Repeat("A", 43)))
	if _, err := service.Send(ctx, wrong); err == nil {
		t.Fatal("wrong possession recovered receipt")
	}
	assertOTPGraphCounts(t, ctx, f, 1, 1, 1, 2, 1)
	missing := request
	missing.Destination, _ = otp.NewDestinationInput("absent@example.invalid")
	missing.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("second"))
	second, err := service.Send(ctx, missing)
	if err != nil || second.Outcome != first.Outcome || second.CommandID == first.CommandID {
		t.Fatal("native-counted suppression shape", err)
	}
	assertOTPGraphCounts(t, ctx, f, 2, 1, 1, 4, 2)
	third := missing
	third.Destination, _ = otp.NewDestinationInput("third@example.invalid")
	third.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("third"))
	denied, err := service.Send(ctx, third)
	if err == nil || denied.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("real N+1 counters did not deny")
	}
	assertOTPGraphCounts(t, ctx, f, 3, 1, 1, 5, 2)
	// A wholly reconstructed public graph has no adopted native activation.
	// It may return an authenticated terminal receipt, but cannot debit or issue
	// for a fresh/unresolved request. This is not cross-process native adoption.
	restartedStores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := restartedStores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	restartedProviders, err := reference.ComposeProviders(restartedStores)
	if err != nil {
		t.Fatal(err)
	}
	restartedWorkers, err := reference.ComposeWorkers(restartedStores, restartedProviders, worker)
	if err != nil {
		t.Fatal(err)
	}
	restartedFeatures, err := reference.ComposeFeatures(restartedStores, restartedProviders, restartedWorkers)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedFeatures.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	restarted, err := restartedFeatures.OTP()
	if err != nil {
		t.Fatal(err)
	}
	before = nativeAttemptFacts(t, ctx, f)
	if replay, err := restarted.Send(ctx, request); err != nil || replay != first {
		t.Fatal("reconstructed graph lost terminal receipt", err)
	}
	if nativeAttemptFacts(t, ctx, f) != before {
		t.Fatal("reconstructed receipt renewed native facts")
	}
	fresh := missing
	fresh.Destination, _ = otp.NewDestinationInput("unactivated@example.invalid")
	fresh.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("unactivated"))
	if result, err := restarted.Send(ctx, fresh); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("unactivated reconstructed graph issued")
	}
	if nativeAttemptFacts(t, ctx, f) != before {
		t.Fatal("unactivated graph fabricated native mutation")
	}
	var protected int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges)+(SELECT count(*) FROM identity.delivery_intents)+(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&protected); err != nil || protected != 4 {
		t.Fatal("unactivated graph produced protected effects", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Send(ctx, request); err == nil {
		t.Fatal("retained feature survived closure")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("borrowed pool closed")
	}
}

func installOTPGraphFixture(t *testing.T, ctx context.Context, f liveStores, stores reference.StoreSet) {
	t.Helper()
	pending := reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/otp/postgres", "audit/postgres", "outbox/postgres/identity"}}
	before, err := stores.ReferenceMigrationCheck(ctx, pending)
	if err != nil || len(before.Statuses) != 3 {
		t.Fatal("pending selected discovery", err)
	}
	for _, status := range before.Statuses {
		if status.CurrentVersion != 0 || status.Compatibility != reference.MigrationRequired {
			t.Fatal("pending selected authority misclassified", status)
		}
	}
	if _, err := f.pool.Raw().Exec(ctx, "CREATE SCHEMA otp_store"); err != nil {
		t.Fatal(err)
	}
	unmanaged, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/otp/postgres"}})
	if err != nil || len(unmanaged.Statuses) != 1 || unmanaged.Statuses[0].Compatibility != reference.MigrationIncompatible {
		t.Fatal("unmanaged optional schema adopted", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "DROP SCHEMA otp_store"); err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(stores.MigrationSource(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("selected native source upgrade", err)
	}
	for _, owner := range []struct {
		namespace string
		files     fs.FS
		preflight string
	}{
		{"audit", auditpg.Migrations(), auditpg.FreshInstallPreflightSQL()},
		{"outbox", outboxpg.Migrations(), ""},
		{"identity_outbox", lifecyclepg.Migrations(), ""},
	} {
		source, err := migrations.NewFSSource(fixtureMigrationFiles{owner.files}, ".")
		if err != nil {
			t.Fatal(err)
		}
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := backend.ForNamespace(owner.namespace)
		if err != nil {
			t.Fatal(err)
		}
		if owner.namespace == "audit" {
			failure, err := migrations.NewMigration(history[len(history)-1].Version()+1, "fixture_late_failure", migrations.TransactionModeDefault, "SELECT 1/0", "")
			if err != nil {
				t.Fatal(err)
			}
			broken := append(append([]migrations.Migration(nil), history...), failure)
			if records, err := owned.InstallFresh(ctx, broken, owner.preflight); err == nil || len(records) != 0 {
				t.Fatal("late audit failure succeeded")
			}
			var rolledBack bool
			if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regclass('audit.records') IS NULL AND to_regclass('public.golib_migrations_audit') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN('audit_writer','audit_reader','audit_retention'))`).Scan(&rolledBack); err != nil || !rolledBack {
				t.Fatal("audit preflight escaped installation transaction", err)
			}
		}
		installHistory := history
		if owner.namespace == "audit" {
			installHistory = history[:1]
		}
		if _, err := owned.InstallFresh(ctx, installHistory, owner.preflight); err != nil {
			t.Fatal("original independent owner installation", err)
		}
		if owner.namespace == "audit" {
			// Roles are cluster-wide, unlike these test-owned databases. Release
			// only the roles this successful fresh installation just created.
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if _, err := f.pool.Raw().Exec(cleanup, "DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
					t.Error("owned audit role cleanup failed", err)
				}
			})
			for _, table := range []string{"records", "retention_events"} {
				if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE audit."+table+" ADD COLUMN accepted_order bigint"); err != nil {
					t.Fatal(err)
				}
				result, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"audit/postgres"}})
				if err != nil || len(result.Statuses) != 1 || result.Statuses[0].Compatibility != reference.MigrationIncompatible {
					t.Fatal("unmanaged independent column adopted", table, result, err)
				}
				if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE audit."+table+" DROP COLUMN accepted_order"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE audit.record_identities(unmanaged boolean)"); err != nil {
				t.Fatal(err)
			}
			result, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"audit/postgres"}})
			if err != nil || len(result.Statuses) != 1 || result.Statuses[0].Compatibility != reference.MigrationIncompatible {
				t.Fatal("unmanaged later independent object adopted", result, err)
			}
			if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE audit.record_identities"); err != nil {
				t.Fatal(err)
			}
			upgrade, err := migrations.NewRunner(source, owned)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := upgrade.Up(ctx); err != nil {
				t.Fatal("native independent owner upgrade", err)
			}
		}
		records, err := owned.ReadLedger(ctx)
		if err != nil || len(records) != len(history) {
			t.Fatal("independent owner history", err)
		}
		for i, step := range history {
			if records[i].Version() != step.Version() || records[i].Name() != step.Name() || records[i].Checksum() != step.Checksum() || records[i].Dirty() {
				t.Fatal("native adoption rewrote original owner identity")
			}
		}
		if _, err := owned.InstallFresh(ctx, history, owner.preflight); err == nil {
			t.Fatal("nonempty owner history was silently reinstalled")
		}
		if owner.namespace == "audit" {
			mixed, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"audit/postgres", "outbox/postgres", "outbox/postgres/identity"}})
			if err != nil || len(mixed.Statuses) != 3 {
				t.Fatal("independent mixed-state discovery", err)
			}
			for _, status := range mixed.Statuses {
				if status.Module == "audit/postgres" {
					if status.Compatibility != reference.MigrationCompatible || status.CurrentVersion != uint64(history[len(history)-1].Version()) {
						t.Fatal("installed audit identity lost")
					}
				} else if status.Compatibility != reference.MigrationRequired || status.CurrentVersion != 0 {
					t.Fatal("audit history satisfied another owner")
				}
			}
		}
	}
	check, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity"}})
	if err != nil || len(check.Statuses) != 9 {
		t.Fatal("native selected compatibility discovery", err)
	}
	for _, status := range check.Statuses {
		if status.Compatibility != reference.MigrationCompatible || status.CurrentVersion != status.RequiredVersion {
			t.Fatal("installed selected owner incompatible", status.Module, status.Compatibility)
		}
	}
	if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',1,1,1,1);
INSERT INTO authorization_subject_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','users','AAAAAAAAAAAAAAAAAAAAAg',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','email','email','recipient@example.invalid',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal("owned identity fixture", err)
	}
}

// The test adapter borrows only immutable upstream embedded files. Native
// FSSource owns parsing and validation; there is no test SQL runner.
type fixtureMigrationFiles struct{ files fs.FS }

func (f fixtureMigrationFiles) ReadDir(ctx context.Context, root string, limits migrations.SourceDirectoryLimits) ([]migrations.SourceEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(f.files, root)
	if err != nil {
		return nil, err
	}
	if len(entries) > limits.MaxEntries {
		return nil, migrations.ErrSourceLimit
	}
	result := make([]migrations.SourceEntry, 0, len(entries))
	total := 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > limits.MaxNameBytes || len(name) > limits.MaxTotalNameBytes-total {
			return nil, migrations.ErrSourceLimit
		}
		total += len(name)
		result = append(result, migrations.SourceEntry{Name: name, Directory: entry.IsDir()})
	}
	return result, ctx.Err()
}

func (f fixtureMigrationFiles) ReadFile(ctx context.Context, name string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := f.files.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > limit {
		return nil, migrations.ErrSourceLimit
	}
	return wire, ctx.Err()
}

type otpFixtureTx struct{ pgx.Tx }

func (q otpFixtureTx) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := q.Tx.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

func insertOTPGraphPreAuth(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration) otp.SendFlow {
	t.Helper()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := session.PreAuthBinding{ID: id, Intent: session.PreAuthIntent{TenantID: otpTenant, Action: c.OTP.PreAuthAction, Origin: "https://identity.example.invalid", Nonce: [32]byte{1}, Remember: remember, PolicyID: c.OTP.PolicyID, PolicyVersion: c.OTP.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	bearer := auth.NewBearerCredential(strings.Repeat("B", 42) + "A")
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(3, bytes.Repeat([]byte{0x57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.PreAuthDigest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := sessionpg.InsertPreAuth(ctx, otpFixtureTx{tx}, c.OTP.Store.PreAuth, record); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewPreAuthSendFlow(id, bearer)
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func assertOTPGraphCounts(t *testing.T, ctx context.Context, f liveStores, attempts, challenges, intents, audits, lifecycle int) {
	t.Helper()
	var a, c, i, u, l int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.velocity_attempts),(SELECT count(*) FROM otp_store.challenges),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM audit.records),(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&a, &c, &i, &u, &l); err != nil {
		t.Fatal(err)
	}
	if a != attempts || c != challenges || i != intents || u != audits || l != lifecycle {
		t.Fatalf("effects attempts=%d challenges=%d intents=%d audits=%d lifecycle=%d", a, c, i, u, l)
	}
}
func nativeAttemptFacts(t *testing.T, ctx context.Context, f liveStores) string {
	t.Helper()
	var facts string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object('attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY sequence) FROM risk_store.velocity_attempts a),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY sequence,dimension) FROM risk_store.velocity_snapshots s))::text`).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	return facts
}
