//go:build integration

package postgres

import (
	"context"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpostgres "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5/stdlib"
)

// All persistence phases are real owned public adapters. This low-level trusted
// composition proves original-command atomicity, not an application endpoint or
// completed email/password workflow authorization.
func TestPublicContributorOriginalCoordinatorComposition(t *testing.T) {
	// Audit roles are cluster-wide, while every child owns an isolated database.
	// Reserve the roles once in this disposable cluster, never in a shared one.
	ctx, rolePool := emptyIntentDatabase(t)
	if _, err := rolePool.Exec(ctx, auditpostgres.FreshInstallPreflightSQL()); err != nil {
		t.Fatal("owned audit preflight failed")
	}
	for _, mode := range []string{"committed", "no-op", "delivery-failure"} {
		t.Run(mode, func(t *testing.T) { testPublicComposition(t, mode) })
	}
}

func testPublicComposition(t *testing.T, mode string) {
	t.Helper()
	ctx, pool := emptyIntentDatabase(t)
	install := beginIntentTestTransaction(t, ctx, pool)
	apply := func(source fs.FS) {
		t.Helper()
		files, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal("owned migration discovery failed")
		}
		for _, file := range files {
			data, err := fs.ReadFile(source, file.Name())
			if err != nil {
				t.Fatal("owned migration load failed")
			}
			if _, err := install.Exec(ctx, strings.Split(string(data), "-- +migrations Down")[0]); err != nil {
				t.Fatal("owned dependency migration failed", file.Name())
			}
		}
	}
	apply(auditpostgres.Migrations())
	apply(outboxpostgres.Migrations())
	apply(identityoutbox.Migrations())
	if install.Commit(ctx) != nil {
		t.Fatal("owned dependency installation failed")
	}
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	t.Cleanup(func() {
		if db.Close() != nil {
			t.Error("migration database cleanup failed")
		}
	})
	backend, err := migrationpostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10}, backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Up(ctx)
	if err != nil || len(result.Records()) != 10 {
		t.Fatal("public migration installation failed")
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("unchanged migration replay failed")
	}
	config := pool.Config().ConnConfig
	// ConnString retains the original fixture database even after pgx's parsed
	// Database field changes. The owned adapter must use this isolated database.
	dsn, err := url.Parse(config.ConnString())
	if err != nil {
		t.Fatal("owned database configuration failed")
	}
	dsn.Path, dsn.RawPath = "/"+config.Database, ""
	owned, err := database.Connect(ctx, database.Config{DSN: dsn.String(), MaxConns: 4})
	if err != nil {
		t.Fatal("owned primary pool failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if owned.Close(cleanup) != nil {
			t.Error("owned pool cleanup failed")
		}
	})
	field := identity.FieldPolicy{Name: "display_name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteAdministrator, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1}
	repo, err := identitypostgres.NewRepository(owned, identitypostgres.Config{MaximumDuration: 2 * time.Second, AttributeSchemas: []identity.AttributeSchema{{ID: "fields", Version: 1, Fields: []identity.FieldPolicy{field}}}, ProfileSchema: identitypostgres.ProfileSchemaRef{ID: "fields", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	auditing, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	// This fixture uses the new public constructor rather than an application
	// implementation of the delivery persistence contract.
	contributor, b, input := compositionPreparation(t)
	input.NoOpEquivalent = mode == "no-op"
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, auditing, lifecycle, contributor})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(owned, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := contributor.Prepare(ctx, b, []IntentInput{input})
	if err != nil {
		t.Fatal(err)
	}
	deliveryPlan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	record := compositionRecord(t, ctx, b, time.Now().UTC().Truncate(time.Microsecond))
	digest, err := identitypostgres.AuditBindingDigest(b, record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareCommandPlan(b, command, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, Delivery: &deliveryPlan})
	if err != nil {
		t.Fatal("public declaration not admitted", err)
	}
	reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal("original reservation failed", err)
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	user, err := repo.ApplyUserCreation(ctx, work, command)
	if err != nil {
		t.Fatal(err)
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record = compositionRecord(t, ctx, b, now)
	if work.StageAudit(0, record) != nil || work.StageLifecycle(0, now) != nil {
		t.Fatal("original audit/lifecycle staging failed")
	}
	foreign, foreignBinding, foreignInput := compositionPreparation(t)
	foreignPrepared, err := foreign.Prepare(ctx, foreignBinding, []IntentInput{foreignInput})
	if err != nil {
		t.Fatal("foreign preparation failed")
	}
	if err := contributor.Stage(ctx, work, foreignPrepared); err == nil {
		t.Fatal("foreign owner preparation staged")
	}
	matchingForeign, err := foreign.Prepare(ctx, b, []IntentInput{input})
	if err != nil {
		t.Fatal("identical configuration preparation failed")
	}
	if err := foreign.Stage(ctx, work, matchingForeign); err == nil {
		t.Fatal("unenlisted identical contributor staged its own custody")
	}
	changedBinding := b
	changedBinding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	changedPrepared, err := contributor.Prepare(ctx, changedBinding, []IntentInput{input})
	if err != nil {
		t.Fatal("changed command preparation failed")
	}
	if err := contributor.Stage(ctx, work, changedPrepared); err != delivery.ErrForbidden {
		t.Fatal("other original command staged")
	}
	if err := contributor.Stage(ctx, work, prepared); err != nil {
		t.Fatal("original delivery staging failed", err)
	}
	var visible int
	if pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&visible) != nil || visible != 0 {
		t.Fatal("delivery visible before original commit")
	}
	if mode == "delivery-failure" {
		if _, err := pool.Exec(ctx, `ALTER TABLE identity.delivery_intents ADD CONSTRAINT test_delivery_deny CHECK (false)`); err != nil {
			t.Fatal("delivery failure setup failed")
		}
	}
	receipt, err := coordinator.Commit(work, identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
	if mode == "delivery-failure" {
		if err == nil || receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("denied delivery became committed")
		}
		var users, intents, effects, audits int
		if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings)`).Scan(&users, &intents, &effects, &audits) != nil || users != 0 || intents != 0 || effects != 0 || audits != 0 {
			t.Fatal("delivery failure retained an original mutation prefix")
		}
		return
	}
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owned original composition did not commit", err)
	}
	var users, intents, effects, audits int
	if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings)`).Scan(&users, &intents, &effects, &audits) != nil || users != 1 || intents != 1 || effects != 2 || audits != 1 {
		t.Fatal("original committed owners disagree", users, intents, effects, audits)
	}
	if mode == "no-op" {
		var erased bool
		if pool.QueryRow(ctx, `SELECT state='cancelled' AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL FROM identity.delivery_intents`).Scan(&erased) != nil || !erased {
			t.Fatal("no-op retained sendable custody")
		}
	}
	_, repeat, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || repeat.Outcome != identity.CommitOutcomeCommitted || repeat.AuditEventID != receipt.AuditEventID {
		t.Fatal("original replay did not return retained receipt")
	}
	if err := contributor.Stage(ctx, work, prepared); err == nil {
		t.Fatal("closed original Work survived")
	}
}

func compositionPreparation(t *testing.T) (*Contributor, identity.CommandBinding, IntentInput) {
	t.Helper()
	codec, bound, p := custodyFixture(t)
	b := bound.Command
	user, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	b.UserID = identity.UserID(user)
	b.PolicyID, b.SchemaID, b.CorrelationID = "policy", "fields", "correlation"
	c, err := NewContributor(ContributorConfig{Deployment: "test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {3}}, ActiveEnvelopeKeyID: "envelope-a", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]ProviderProfile{1: {Provider: "test-provider", PolicyVersion: 1}}}, codec.service)
	if err != nil {
		t.Fatal(err)
	}
	return c, b, IntentInput{Purpose: "verification", SubjectID: string(b.UserID), TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), Recipient: p.Recipient, Rendered: p.Rendered}
}

func compositionRecord(t *testing.T, ctx context.Context, b identity.CommandBinding, now time.Time) audit.Record {
	t.Helper()
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, err := identity.NewSubjectID(); return string(id), err }})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard", "aggregate.type": "user", "aggregate.id": string(b.UserID), "aggregate.before_version": "0", "aggregate.after_version": "1"}})
	if err != nil {
		t.Fatal("owned audit build failed")
	}
	keys := []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: keys})
	if err != nil {
		t.Fatal(err)
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
