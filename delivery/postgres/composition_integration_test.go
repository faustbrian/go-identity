//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
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
	for _, mode := range []string{"committed", "no-op", "delivery-failure", "native-committed", "native-owned", "public-owned", "public-state", "public-cancel", "public-receipt", "native-compatible-custody", "native-no-op", "native-missing", "native-failure", "native-cancel", "native-cancel-noop", "native-receipt"} {
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
	native := strings.HasPrefix(mode, "native-")
	input.NoOpEquivalent = mode == "no-op" || mode == "native-no-op" || mode == "native-cancel-noop"
	participants := []identitypostgres.Contributor{repo}
	var enqueue *EnqueueContributor
	if native {
		op := EnqueueOperation()
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		nativeCustody := contributor
		if mode == "native-compatible-custody" {
			// Native declarations validate retained profiles, not cross-phase
			// pointer identity. Staging still requires the registered owner.
			nativeCustody, _, _ = compositionPreparation(t)
		}
		enqueue, err = NewEnqueueContributor(nativeCustody)
		if err != nil {
			t.Fatal(err)
		}
		participants = append(participants, enqueue)
	}
	participants = append(participants, auditing, lifecycle, contributor)
	registry, err := identitypostgres.NewContributorRegistry(participants)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := identitypostgres.NewCoordinator(owned, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	var prepared PreparedDelivery
	if native {
		prepared, err = contributor.PrepareEnqueue(ctx, b, []IntentInput{input})
	} else {
		prepared, err = contributor.Prepare(ctx, b, []IntentInput{input})
	}
	if err != nil {
		t.Fatal(err)
	}
	if mode == "public-owned" || mode == "public-state" || mode == "public-cancel" || mode == "public-receipt" {
		runner, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal(err)
		}
		op := EnqueueOperation()
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		if _, err := pool.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'public-email','email',$3,true,true,1,2,1,statement_timestamp())`, string(b.TenantID), string(b.UserID), input.Recipient.Address); err != nil {
			t.Fatal(err)
		}
		permit := false
		denyHistorical := false
		policy := enqueueDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			outcome := authorization.Deny
			if permit {
				outcome = authorization.Allow
			}
			if value, ok := dc.Request.Resource.Attributes["identity.command.read-admission"]; ok && denyHistorical {
				if historical, _ := value.Bool(); historical {
					outcome = authorization.Deny
				}
			}
			return authorization.Decision{Outcome: outcome, Revision: dc.PolicyRevision}, nil
		})
		config := EnqueueConfig{Custody: ContributorConfig{Deployment: "test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {3}}, ActiveEnvelopeKeyID: "envelope-a", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]ProviderProfile{1: {Provider: "test-provider", PolicyVersion: 1}}}, Coordinator: identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, PolicyID: "policy", PolicyVersion: 1, AuditRetentionVersion: 1, Timeout: 2 * time.Second, NamespaceKey: [32]byte{7}, Policies: map[uint64]delivery.Config{1: delivery.DefaultConfig()}}
		templates := []delivery.Template{{ID: "verify", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", ContentType: "text/plain", Subject: "Verification", Body: "Code: {{.code}}", MaxRenderedBytes: 1024, RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}}}
		if mode == "public-state" || mode == "public-cancel" || mode == "public-receipt" {
			config.StateTracking = true
			if _, err := NewEnqueueService(ctx, owned, config, contributor.store.codec.service, policy, templates); !errors.Is(err, delivery.ErrUnavailable) {
				t.Fatal("selected tracking admitted absent migration", err)
			}
			tracked, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}, backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tracked.Up(ctx); err != nil {
				t.Fatal("selected state migration", err)
			}
			if mode == "public-cancel" {
				second := delivery.DefaultConfig()
				second.SenderTimeout += time.Second
				config.Policies[2] = second
				config.Custody.ProviderProfiles[2] = ProviderProfile{Provider: "test-provider", PolicyVersion: 2}
				config.Cancellation = true
				if _, err := NewEnqueueService(ctx, owned, config, contributor.store.codec.service, policy, templates); !errors.Is(err, delivery.ErrUnavailable) {
					t.Fatal("selected cancellation admitted absent result migration", err)
				}
				cancelMigration, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14, CancellationVersion: 15}, backend)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cancelMigration.Up(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		if mode == "public-receipt" {
			config.Policies[2] = delivery.DefaultConfig()
			config.Custody.ProviderProfiles[2] = ProviderProfile{Provider: "test-provider", PolicyVersion: 2}
			config.Receipts = &ReceiptAuthenticationConfig{MaxBodyBytes: 16384}
			for _, version := range []uint64{1, 2} {
				config.Receipts.Profiles = append(config.Receipts.Profiles, ReceiptKeyProfile{TenantID: delivery.TenantID(b.TenantID), Provider: "test-provider", ProviderConfigVersion: version, ActorID: "provider-actor", KeyID: "callback-key", Key: [32]byte{9}, NotBefore: time.Now().UTC().Add(-time.Hour), NotAfter: time.Now().UTC().Add(time.Hour)})
			}
			if _, err := NewEnqueueService(ctx, owned, config, contributor.store.codec.service, policy, templates); !errors.Is(err, delivery.ErrUnavailable) {
				t.Fatal("callback feature admitted absent receipt migrations", err)
			}
			receipts, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14, ReceiptVersion: 15, ReceiptCommandVersion: 16}, backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receipts.Up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		public, err := NewEnqueueService(ctx, owned, config, contributor.store.codec.service, policy, templates)
		if err != nil {
			t.Fatal(err)
		}
		request := EnqueueCommandRequest{Binding: b, ActorScope: authorization.DecisionContext{PolicyRevision: 1, CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}, IdentifierID: "public-email", ProviderConfigVersion: 1, Message: delivery.Message{Purpose: "verification", Channel: delivery.ChannelEmail, TemplateID: "verify", TemplateVersion: 1, LocaleChain: []string{"en"}, Variables: []delivery.TemplateVariable{{Name: "code", Kind: "code", CodeValue: "synthetic-code", Sensitive: true}}}, IdempotencyKey: "public-request-key", ExpiresAt: input.ExpiresAt}
		if _, err := public.Enqueue(ctx, request); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("public denied caller admitted", err)
		}
		permit = true
		first, err := public.Enqueue(ctx, request)
		if err != nil || first.State != delivery.CommitCommitted || !first.Queued || first.IntentID == "" {
			t.Fatal("public admission failed", err)
		}
		if config.Cancellation {
			legacyConfig := config
			legacyConfig.Cancellation = false
			legacy, err := NewEnqueueService(ctx, owned, legacyConfig, contributor.store.codec.service, policy, templates)
			if err != nil {
				t.Fatal(err)
			}
			if replay, err := legacy.Enqueue(ctx, request); err != nil || replay != first {
				t.Fatal("cancellation feature changed installed enqueue plan identity", err)
			}
		}
		statusScope := request.ActorScope.Clone()
		statusScope.Request.Action = "identity.delivery.status-get"
		statusRequest := delivery.StatusGetRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: first.IntentID}
		status, err := public.StatusGet(ctx, statusRequest, b.UserID, statusScope)
		if err != nil || status != (delivery.StatusGetResult{State: delivery.StateQueued}) {
			t.Fatal("public status did not observe original queue", err)
		}
		// Cancellation must freeze both fences from one authorized primary
		// snapshot, then retain them on retries rather than infer a new plan.
		if config.StateTracking {
			snapshot, err := public.VersionedStatusGet(ctx, statusRequest, b.UserID, statusScope)
			if err != nil || snapshot.Status != status || snapshot.StatusVersion != 1 {
				t.Fatal("versioned status did not preserve admission snapshot", err, snapshot)
			}
			permit = false
			if got, err := public.VersionedStatusGet(ctx, statusRequest, b.UserID, statusScope); !errors.Is(err, delivery.ErrForbidden) || got != (StatusSnapshot{}) {
				t.Fatal("denied versioned status disclosed metadata", err)
			}
			permit = true
			if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state=state WHERE deployment='test' AND effect_id=$1`, string(first.IntentID)); err != nil {
				t.Fatal(err)
			}
			updated, err := public.VersionedStatusGet(ctx, statusRequest, b.UserID, statusScope)
			if err != nil || updated.Status != status || updated.StatusVersion != 2 || snapshot.StatusVersion != 1 {
				t.Fatal("versioned status renewed prior snapshot or lost transition", err, updated)
			}
		} else if got, err := public.VersionedStatusGet(ctx, statusRequest, b.UserID, statusScope); !errors.Is(err, delivery.ErrInvalidInput) || got != (StatusSnapshot{}) {
			t.Fatal("legacy profile fabricated a status version", err)
		}
		missing := statusRequest
		prefix := "0"
		if string(first.IntentID)[0] == '0' {
			prefix = "1"
		}
		// Exactly one intent exists here; this canonical ID differs from it.
		missing.IntentID = delivery.IntentID(prefix + string(first.IntentID)[1:])
		if _, err := public.StatusGet(ctx, missing, b.UserID, statusScope); !errors.Is(err, delivery.ErrNotFound) {
			t.Fatal("missing status target did not share foreign classification", err)
		}
		if config.StateTracking {
			if got, err := public.VersionedStatusGet(ctx, missing, b.UserID, statusScope); !errors.Is(err, delivery.ErrNotFound) || got != (StatusSnapshot{}) {
				t.Fatal("missing versioned status disclosed metadata", err)
			}
		}
		otherConfig := config
		otherConfig.Custody.Deployment = "other-deployment"
		other, err := NewEnqueueService(ctx, owned, otherConfig, contributor.store.codec.service, policy, templates)
		if err != nil {
			t.Fatal("other deployment construction", err)
		}
		if _, err := other.StatusGet(ctx, statusRequest, b.UserID, statusScope); !errors.Is(err, delivery.ErrNotFound) {
			t.Fatal("status crossed deployment", err)
		}
		permit = false
		if result, err := public.StatusGet(ctx, statusRequest, b.UserID, statusScope); !errors.Is(err, delivery.ErrForbidden) || result != (delivery.StatusGetResult{}) {
			t.Fatal("denied status disclosed metadata", err)
		}
		permit = true
		foreignScope := statusScope.Clone()
		foreignScope.Request.Resource.ID = "foreign-user"
		if result, err := public.StatusGet(ctx, statusRequest, "foreign-user", foreignScope); !errors.Is(err, delivery.ErrNotFound) || result != (delivery.StatusGetResult{}) {
			t.Fatal("status crossed target owner", err)
		}
		if config.StateTracking {
			if got, err := public.VersionedStatusGet(ctx, statusRequest, "foreign-user", foreignScope); !errors.Is(err, delivery.ErrNotFound) || got != (StatusSnapshot{}) {
				t.Fatal("versioned status crossed target owner", err)
			}
		}
		foreignRequest := statusRequest
		foreignRequest.TenantID = "foreign-tenant"
		foreignScope = statusScope.Clone()
		foreignScope.Request.Tenant = "foreign-tenant"
		if _, err := public.StatusGet(ctx, foreignRequest, b.UserID, foreignScope); !errors.Is(err, delivery.ErrNotFound) {
			t.Fatal("status crossed tenant", err)
		}
		if config.StateTracking {
			if got, err := public.VersionedStatusGet(ctx, foreignRequest, b.UserID, foreignScope); !errors.Is(err, delivery.ErrNotFound) || got != (StatusSnapshot{}) {
				t.Fatal("versioned status crossed tenant", err)
			}
		}
		for _, bad := range []delivery.StatusGetRequest{{}, {TenantID: statusRequest.TenantID, IntentID: "not-a-canonical-intent"}, {TenantID: statusRequest.TenantID, IntentID: delivery.IntentID(strings.Repeat("G", 64))}} {
			if _, err := public.StatusGet(ctx, bad, b.UserID, statusScope); !errors.Is(err, delivery.ErrInvalidInput) {
				t.Fatal("malformed status target accepted", err)
			}
		}
		for _, attributes := range []func(*authorization.DecisionContext){
			func(dc *authorization.DecisionContext) {
				dc.Request.Subject.Attributes = authorization.Attributes{"delivery.intent": authorization.StringValue(string(first.IntentID))}
			},
			func(dc *authorization.DecisionContext) {
				dc.Request.Resource.Attributes = authorization.Attributes{"delivery.intent": authorization.StringValue(string(first.IntentID))}
			},
			func(dc *authorization.DecisionContext) {
				dc.Request.Environment.Attributes = authorization.Attributes{"delivery.intent": authorization.StringValue(string(first.IntentID))}
			},
			func(dc *authorization.DecisionContext) {
				dc.Request.Attributes = authorization.Attributes{"delivery.intent": authorization.StringValue(string(first.IntentID))}
			},
		} {
			shadow := statusScope.Clone()
			attributes(&shadow)
			if _, err := public.StatusGet(ctx, statusRequest, b.UserID, shadow); !errors.Is(err, delivery.ErrInvalidInput) {
				t.Fatal("caller shadowed owned status scope", err)
			}
		}
		request.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		second, err := public.Enqueue(ctx, request)
		if err != nil || second != first {
			t.Fatal("public duplicate changed stable result", err)
		}
		changed := request
		changed.Message.Variables = append([]delivery.TemplateVariable(nil), request.Message.Variables...)
		changed.Message.Variables[0].CodeValue = "changed-code"
		if result, err := public.Enqueue(ctx, changed); !errors.Is(err, delivery.ErrConflict) || result.State != delivery.CommitConflict || result.Queued {
			t.Fatal("public changed input reused key", err)
		}
		noop := request
		noop.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		noop.IdempotencyKey = "public-noop-request"
		noop.NoOpEquivalent = true
		noop.IdentifierID = ""
		noResult, err := public.Enqueue(ctx, noop)
		if err != nil || noResult.State != delivery.CommitCommitted || !noResult.Queued || !noResult.NoOpEquivalent {
			t.Fatal("public no-op changed result shape", err)
		}
		noStatus, err := public.StatusGet(ctx, delivery.StatusGetRequest{TenantID: statusRequest.TenantID, IntentID: noResult.IntentID}, b.UserID, statusScope)
		if err != nil || noStatus != status {
			t.Fatal("no-op status disclosed recipient existence", err)
		}
		var intents, outbox, audits, noops int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings),(SELECT count(*) FROM identity.delivery_intents WHERE no_op AND ciphertext IS NULL AND envelope_key_id IS NULL)`).Scan(&intents, &outbox, &audits, &noops); err != nil || intents != 2 || outbox != 4 || audits != 2 || noops != 1 {
			t.Fatal("public composition did not own durable effects", err, intents, outbox, audits, noops)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if _, err := public.Enqueue(cancelled, request); !errors.Is(err, context.Canceled) {
			t.Fatal("public cancelled admission", err)
		}
		if _, err := public.StatusGet(cancelled, statusRequest, b.UserID, statusScope); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled status read", err)
		}
		expiring := request
		expiring.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		expiring.IdempotencyKey = "public-expiring-key"
		expiring.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
		original, err := public.Enqueue(ctx, expiring)
		if err != nil || original.State != delivery.CommitCommitted {
			t.Fatal("expiring admission failed", err)
		}
		expiringNoop := expiring
		expiringNoop.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		expiringNoop.IdempotencyKey = "public-expiring-noop"
		expiringNoop.NoOpEquivalent, expiringNoop.IdentifierID = true, ""
		expiredNoopIntent, err := public.Enqueue(ctx, expiringNoop)
		if err != nil {
			t.Fatal("expiring no-op admission", err)
		}
		// Model interruption after keyed allocation but before reservation. The
		// allocation identifies the original command, never its execution outcome.
		unacknowledged := expiring
		unacknowledged.IdempotencyKey = "public-interrupted-key"
		unacknowledged.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		recipient, _, err := lookupRecipient(ctx, unacknowledged.Binding, unacknowledged.IdentifierID, "verification", public.keyed, public.repository)
		if err != nil {
			t.Fatal(err)
		}
		message := unacknowledged.Message
		message.Recipient = recipient
		rendered, err := public.renderer.Render(ctx, message)
		if err != nil {
			t.Fatal(err)
		}
		interruptedInput := IntentInput{Purpose: message.Purpose, SubjectID: string(b.UserID), TemplateID: message.TemplateID, TemplateVersion: uint32(message.TemplateVersion), ProviderConfigVersion: 1, ExpiresAt: unacknowledged.ExpiresAt, Recipient: recipient, Rendered: rendered}
		checked := unacknowledged.Binding
		checked.RecordID = "enqueue-validation"
		bindings, err := public.executor.custody.validateInputShape(checked, []IntentInput{interruptedInput})
		if err != nil {
			t.Fatal(err)
		}
		logical, err := public.keyed.logical(bindings, []IntentInput{interruptedInput})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := public.keyed.resolveVersion(ctx, unacknowledged.Binding, unacknowledged.IdempotencyKey, logical, 1); err != nil {
			t.Fatal(err)
		}
		deadline := time.NewTimer(time.Until(expiring.ExpiresAt))
		defer deadline.Stop()
		select {
		case <-deadline.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		// Status uses authoritative database time, not the caller's host clock.
		// Wait for that boundary too; VM clock skew must not shape the oracle.
		for {
			var now time.Time
			if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			if !now.Before(expiring.ExpiresAt) {
				break
			}
			ready := time.NewTimer(expiring.ExpiresAt.Sub(now))
			select {
			case <-ready.C:
			case <-ctx.Done():
				ready.Stop()
				t.Fatal(ctx.Err())
			}
			ready.Stop()
		}
		// Also represents a lost acknowledgement: retry observes original durable
		// history, not caller knowledge of whether the first response arrived.
		expiring.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		if replay, err := public.Enqueue(ctx, expiring); err != nil || replay != original {
			t.Fatal("expired committed replay lost original receipt", err, replay.State)
		}
		expiredStatus, err := public.StatusGet(ctx, delivery.StatusGetRequest{TenantID: statusRequest.TenantID, IntentID: original.IntentID}, b.UserID, statusScope)
		if err != nil || expiredStatus != (delivery.StatusGetResult{State: delivery.StateExpired, Terminal: true}) {
			t.Fatal("queued expiry status", err, expiredStatus.State, expiredStatus.AttemptGeneration)
		}
		if noStatus, err := public.StatusGet(ctx, delivery.StatusGetRequest{TenantID: statusRequest.TenantID, IntentID: expiredNoopIntent.IntentID}, b.UserID, statusScope); err != nil || noStatus != expiredStatus {
			t.Fatal("expired no-op status disclosed existence", err)
		}
		denyHistorical = true
		if result, err := public.Enqueue(ctx, expiring); !errors.Is(err, delivery.ErrForbidden) || result.IntentID != "" || result.Queued {
			t.Fatal("denied historical observation leaked admission identity", err)
		}
		denyHistorical = false
		unknown, err := public.Enqueue(ctx, unacknowledged)
		var unknownError delivery.AdmissionUnknownError
		if !errors.As(err, &unknownError) || unknown.State != delivery.CommitUnknown || unknown.Queued || unknownError.CommandID != unacknowledged.Binding.CommandID {
			t.Fatal("expired interrupted admission fabricated noncommit", err)
		}
		changedExpired := expiring
		changedExpired.Message.Variables = append([]delivery.TemplateVariable(nil), expiring.Message.Variables...)
		changedExpired.Message.Variables[0].CodeValue = "expired-changed-code"
		if result, err := public.Enqueue(ctx, changedExpired); !errors.Is(err, delivery.ErrConflict) || result.State != delivery.CommitConflict || result.Queued {
			t.Fatal("expired replay accepted changed content", err)
		}
		freshExpired := expiring
		freshExpired.IdempotencyKey = "public-expired-new-key"
		if result, err := public.Enqueue(ctx, freshExpired); !errors.Is(err, delivery.ErrExpired) || result.State != delivery.CommitNotCommitted || result.Queued {
			t.Fatal("expired new admission was accepted", err)
		}
		var finalIntents, finalKeys int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM identity.delivery_keyed_commands)`).Scan(&finalIntents, &finalKeys); err != nil || finalIntents != 4 || finalKeys != 5 {
			t.Fatal("expired recovery created or renewed durable effects", err, finalIntents, finalKeys)
		}
		worker, err := public.policies.worker(1, public.executor.custody.store.codec)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: statusRequest.TenantID, WorkerID: "status-worker"})
		if err != nil || !claim.Claimed || claim.Attempt.IntentID != first.IntentID {
			t.Fatal("status worker did not claim original intent", err)
		}
		if observed, err := public.StatusGet(ctx, statusRequest, b.UserID, statusScope); err != nil || observed != (delivery.StatusGetResult{State: delivery.StateAttempting, AttemptGeneration: 1}) {
			t.Fatal("live lease did not expose attempting status", err)
		}
		if config.StateTracking {
			var version uint64
			if err := pool.QueryRow(ctx, `SELECT status_version FROM identity.delivery_intents WHERE deployment='test' AND effect_id=$1`, string(first.IntentID)).Scan(&version); err != nil {
				t.Fatal(err)
			}
			got, err := public.VersionedStatusGet(ctx, statusRequest, b.UserID, statusScope)
			if err != nil || got.StatusVersion != version || got.Status != (delivery.StatusGetResult{State: delivery.StateAttempting, AttemptGeneration: 1}) {
				t.Fatal("versioned status lost worker generation", err, got)
			}
		}
		completed, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: statusRequest.TenantID, IntentID: first.IntentID, WorkerID: "status-worker", Generation: 1, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC(), ProviderReference: "synthetic-provider-reference"}})
		if err != nil || completed.State != delivery.StateAccepted {
			t.Fatal("accepted completion failed", err)
		}
		if observed, err := public.StatusGet(ctx, statusRequest, b.UserID, statusScope); err != nil || observed != (delivery.StatusGetResult{State: delivery.StateAccepted, AttemptGeneration: 1, ProviderReferencePresent: true}) {
			t.Fatal("accepted status claimed delivery or exposed reference", err)
		}
		for _, mode := range []string{"delivered", "lost"} {
			fresh := request
			fresh.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			fresh.IdempotencyKey = "public-status-" + mode
			admitted, err := public.Enqueue(ctx, fresh)
			if err != nil {
				t.Fatal("status intent admission", err)
			}
			claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: statusRequest.TenantID, WorkerID: "status-worker"})
			if err != nil || !claim.Claimed || claim.Attempt.IntentID != admitted.IntentID {
				t.Fatal("status intent claim", err)
			}
			want := delivery.StatusGetResult{State: delivery.StateOutcomeUnknown, AttemptGeneration: 1}
			if mode == "delivered" {
				if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: statusRequest.TenantID, IntentID: admitted.IntentID, WorkerID: "status-worker", Generation: 1, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC(), ProviderReference: "synthetic-delivery-reference"}}); err != nil {
					t.Fatal("delivery completion", err)
				}
				want = delivery.StatusGetResult{State: delivery.StateDelivered, AttemptGeneration: 1, Terminal: true, ProviderReferencePresent: true}
			} else {
				// Advance the lease fence, not the immutable original message expiry.
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE deployment='test' AND tenant_id=$1 AND effect_id=$2`, string(b.TenantID), string(admitted.IntentID)); err != nil {
					t.Fatal("expire owned test lease", err)
				}
			}
			observed, err := public.StatusGet(ctx, delivery.StatusGetRequest{TenantID: statusRequest.TenantID, IntentID: admitted.IntentID}, b.UserID, statusScope)
			if err != nil || observed != want {
				t.Fatal("attributable status lost provider or lease semantics", err, mode)
			}
			if mode == "lost" {
				var state string
				var unfinished bool
				if err := pool.QueryRow(ctx, `SELECT i.state,h.outcome IS NULL FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id) WHERE i.deployment='test' AND i.tenant_id=$1 AND i.effect_id=$2`, string(b.TenantID), string(admitted.IntentID)).Scan(&state, &unfinished); err != nil || state != "submitted" || !unfinished {
					t.Fatal("status read mutated an unknown attempt", err)
				}
			}
		}
		if public.stateTracking {
			for _, noop := range []bool{false, true} {
				fresh := request
				fresh.Binding.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				fresh.IdempotencyKey = fmt.Sprintf("public-stop-%t", noop)
				fresh.NoOpEquivalent = noop
				if noop {
					fresh.IdentifierID = ""
				}
				intent, err := public.Enqueue(ctx, fresh)
				if err != nil {
					t.Fatal("state admission", err)
				}
				if _, err := worker.cancelTracked(ctx, delivery.CancelRequest{TenantID: statusRequest.TenantID, IntentID: intent.IntentID, Reason: "workflow-cancel"}, string(b.UserID)); err != nil {
					t.Fatal("state stop", err)
				}
				observed, err := public.StatusGet(ctx, delivery.StatusGetRequest{TenantID: statusRequest.TenantID, IntentID: intent.IntentID}, b.UserID, statusScope)
				if err != nil || observed != (delivery.StatusGetResult{State: delivery.StateCancelled, Terminal: true}) {
					t.Fatal("state stop exposed no-op custody", err, observed)
				}
			}
		}
		if mode == "public-cancel" {
			testAuthenticatedCancellation(t, ctx, pool, public, request, &permit)
			testSubmittedCancellation(t, ctx, pool, public, request)
		}
		if mode == "public-receipt" {
			testAuthenticatedReceipts(t, ctx, pool, public, request, &permit)
		}
		return
	}
	if mode == "native-owned" {
		var permit bool
		var policyMode string
		var policyCalls int
		var requireAdmissionScope bool
		var denyAfter int
		var policyHook func()
		policy := enqueueDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			policyCalls++
			if policyHook != nil {
				policyHook()
			}
			if requireAdmissionScope {
				scopes, ok := dc.Request.Resource.Attributes["delivery.recipient_scopes"].StringSet()
				if !ok || len(scopes) != 1 || scopes[0] != input.Recipient.ScopeDigest {
					t.Fatal("admission did not bind exact recipient scope")
				}
			}
			if _, bounded := ctx.Deadline(); !bounded {
				t.Fatal("enqueue policy lacked bounded context")
			}
			outcome := authorization.Deny
			if permit {
				outcome = authorization.Allow
			}
			if denyAfter != 0 && policyCalls > denyAfter {
				outcome = authorization.Deny
			}
			if policyMode == "panic" {
				panic("synthetic-policy-diagnostic")
			}
			if policyMode == "error" {
				return authorization.Decision{}, errors.New("synthetic-policy-diagnostic")
			}
			if policyMode == "stale" {
				return authorization.Decision{Outcome: outcome, Revision: dc.PolicyRevision + 1}, nil
			}
			return authorization.Decision{Outcome: outcome, Revision: dc.PolicyRevision}, nil
		})
		executor, err := newEnqueueExecutor(coordinator, registry, enqueue, contributor, policy, "policy", 1, 1, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		scope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Action: "identity.delivery.enqueue", Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
		if _, err := pool.Exec(ctx, policySchemaSQL); err != nil {
			t.Fatal("retained policy migration", err)
		}
		policies, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig()}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// A missing encryption service must not hide denied authorization: policy
		// runs first and leaves no claim. Restore it for the real encrypted commit.
		originalService := contributor.store.codec.service
		contributor.store.codec.service = nil
		requireAdmissionScope = true
		if _, err := executor.Admit(ctx, b, scope, []IntentInput{input}, policies); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("denied admission performed encryption", err)
		}
		contributor.store.codec.service = originalService
		requireAdmissionScope = false
		for _, test := range []struct {
			mutate func(*IntentInput)
			want   error
		}{
			{func(v *IntentInput) { v.SubjectID = "other" }, delivery.ErrForbidden},
			{func(v *IntentInput) { v.Rendered.Body = strings.Repeat("x", 262145) }, delivery.ErrInvalidInput},
			{func(v *IntentInput) { v.ProviderConfigVersion = 99 }, delivery.ErrUnavailable},
		} {
			bad := input
			test.mutate(&bad)
			before := policyCalls
			if _, err := executor.Admit(ctx, b, scope, []IntentInput{bad}, policies); !errors.Is(err, test.want) || policyCalls != before {
				t.Fatal("invalid admission reached policy", err)
			}
		}
		if _, err := executor.Execute(ctx, prepared, scope); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("denied enqueue reached persistence", err)
		}
		permit = true
		oversized := scope.Clone()
		members := make([]string, 65)
		for i := range members {
			members[i] = fmt.Sprint(i)
		}
		oversized.Request.Attributes = authorization.Attributes{"custom": authorization.StringSetValue(members)}
		before := policyCalls
		if _, err := executor.Execute(ctx, prepared, oversized); !errors.Is(err, delivery.ErrInvalidInput) || policyCalls != before {
			t.Fatal("oversized enqueue input reached policy", err)
		}
		for _, mutate := range []func(*authorization.DecisionContext){
			func(dc *authorization.DecisionContext) { dc.Request.Tenant = "other" },
			func(dc *authorization.DecisionContext) { dc.Request.Subject.ID = "other" },
			func(dc *authorization.DecisionContext) { dc.Request.Resource.ID = "other" },
			func(dc *authorization.DecisionContext) { dc.Request.Action = "other" },
			func(dc *authorization.DecisionContext) { dc.PolicyRevision++ },
			func(dc *authorization.DecisionContext) { dc.CorrelationID = "other" },
		} {
			changed := scope.Clone()
			mutate(&changed)
			if _, err := executor.Execute(ctx, prepared, changed); !errors.Is(err, delivery.ErrForbidden) {
				t.Fatal("foreign enqueue scope accepted", err)
			}
		}
		for _, policyMode = range []string{"panic", "error", "stale"} {
			want := delivery.ErrUnavailable
			if policyMode == "stale" {
				want = delivery.ErrForbidden
			}
			if _, err := executor.Execute(ctx, prepared, scope); !errors.Is(err, want) {
				t.Fatal("invalid policy output accepted", err)
			}
		}
		policyMode = ""
		// Permission may change during envelope preparation. The second policy
		// read must deny reservation, not trust the pre-encryption decision.
		requireAdmissionScope = true
		denyAfter = policyCalls + 1
		if _, err := executor.Admit(ctx, b, scope, []IntentInput{input}, policies); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("post-encryption policy change reserved a command", err)
		}
		denyAfter = 0
		requireAdmissionScope = false
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := executor.Execute(cancelled, prepared, scope); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled enqueue started admission", err)
		}
		var claimed int
		if pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands`).Scan(&claimed) != nil || claimed != 0 {
			t.Fatal("denied enqueue reserved a command")
		}
		permit = true
		badScope := scope.Clone()
		badScope.Request.Resource.Attributes = authorization.Attributes{"delivery.recipient_scopes": authorization.StringSetValue([]string{"caller-chosen"})}
		if _, err := executor.Admit(ctx, b, badScope, []IntentInput{input}, policies); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("caller overrode owned delivery scope", err)
		}
		missingPolicy := *policies
		missingPolicy.profiles = map[uint64]delivery.Config{2: delivery.DefaultConfig()}
		before = policyCalls
		if _, err := executor.Admit(ctx, b, scope, []IntentInput{input}, &missingPolicy); !errors.Is(err, delivery.ErrUnavailable) || policyCalls != before {
			t.Fatal("unretained admission dispatched policy", err)
		}
		requireAdmissionScope = true
		if _, err := pool.Exec(ctx, keyedSchemaSQL); err != nil {
			t.Fatal("keyed migration", err)
		}
		keyed, err := newKeyedAdmission(ctx, pool, "test", [32]byte{7}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		permit = false
		if _, err := executor.AdmitKeyed(ctx, b, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("denied keyed admission proceeded", err)
		}
		var allocations int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_keyed_commands`).Scan(&allocations); err != nil || allocations != 0 {
			t.Fatal("denied caller allocated original command", err)
		}
		permit = true
		first, err := executor.AdmitKeyed(ctx, b, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key")
		if err != nil || first.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("owned enqueue did not commit", err)
		}
		repeat := b
		repeat.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		second, err := executor.AdmitKeyed(ctx, repeat, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key")
		if err != nil || second.Outcome != identity.CommitOutcomeCommitted || second.AuditEventID != first.AuditEventID || second.Binding != first.Binding {
			t.Fatal("owned enqueue replay did not retain original effects", err)
		}
		// Restart with a new current custody fingerprint key, keeping the old
		// key available. Admission must preserve both the allocated command and
		// its original confidential fingerprint, not reinterpret the request.
		rotated, err := NewContributor(ContributorConfig{Deployment: "test", CurrentDigestKeyVersion: 2, RetainedDigestKeys: map[uint32][32]byte{1: {3}, 2: {4}}, ActiveEnvelopeKeyID: "envelope-a", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]ProviderProfile{1: {Provider: "test-provider", PolicyVersion: 1}}}, originalService)
		if err != nil {
			t.Fatal(err)
		}
		rotatedNative, err := NewEnqueueContributor(rotated)
		if err != nil {
			t.Fatal(err)
		}
		rotatedRegistry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, rotatedNative, auditing, lifecycle, rotated})
		if err != nil {
			t.Fatal(err)
		}
		rotatedCoordinator, err := identitypostgres.NewCoordinator(owned, rotatedRegistry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if err != nil {
			t.Fatal(err)
		}
		rotatedExecutor, err := newEnqueueExecutor(rotatedCoordinator, rotatedRegistry, rotatedNative, rotated, policy, "policy", 1, 1, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		rotatedResult, err := rotatedExecutor.AdmitKeyed(ctx, repeat, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key")
		if err != nil || rotatedResult.Outcome != identity.CommitOutcomeCommitted || rotatedResult.Binding != first.Binding || rotatedResult.AuditEventID != first.AuditEventID {
			t.Fatal("custody rotation broke original keyed replay", err)
		}
		retainedKey := rotated.store.codec.keys[1]
		delete(rotated.store.codec.keys, 1)
		if _, err := rotatedExecutor.AdmitKeyed(ctx, repeat, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key"); !errors.Is(err, delivery.ErrUnavailable) {
			t.Fatal("missing original custody key reinterpreted replay", err)
		}
		rotated.store.codec.keys[1] = retainedKey
		changed := input
		changed.Rendered.Body += "-changed"
		if _, err := rotatedExecutor.AdmitKeyed(ctx, repeat, scope, []IntentInput{changed}, policies, keyed, "synthetic-request-key"); !errors.Is(err, delivery.ErrConflict) {
			t.Fatal("same key changed confidential queued content", err)
		}
		permit = false
		if _, err := executor.AdmitKeyed(ctx, repeat, scope, []IntentInput{input}, policies, keyed, "synthetic-request-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("replay bypassed current authorization", err)
		}
		var intents, effects, audits int
		if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings)`).Scan(&intents, &effects, &audits) != nil || intents != 1 || effects != 2 || audits != 1 {
			t.Fatal("owned enqueue replay duplicated effects", intents, effects, audits)
		}
		permit = true
		requireAdmissionScope = false
		if _, err := pool.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'recipient-email','email',$3,true,true,1,2,1,statement_timestamp())`, string(b.TenantID), string(b.UserID), input.Recipient.Address); err != nil {
			t.Fatal(err)
		}
		directoryBinding := b
		directoryBinding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		permit = false
		if _, err := executor.AdmitIdentifier(ctx, directoryBinding, scope, input, repo, "recipient-email", policies, keyed, "directory-request-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("denied directory discovery", err)
		}
		permit = true
		if _, err := executor.AdmitIdentifier(ctx, directoryBinding, scope, input, repo, "missing", policies, keyed, "directory-request-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("missing identifier leaked or guessed recipient", err)
		}
		claimedRecipient := input
		claimedRecipient.Recipient.Address = "untrusted@example.test"
		if _, err := executor.AdmitIdentifier(ctx, directoryBinding, scope, claimedRecipient, repo, "recipient-email", policies, keyed, "directory-request-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("caller address bypassed primary discovery", err)
		}
		directoryResult, err := executor.AdmitIdentifier(ctx, directoryBinding, scope, input, repo, "recipient-email", policies, keyed, "directory-request-key")
		if err != nil || directoryResult.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("authoritative recipient did not enqueue", err)
		}
		var directoryAAD []byte
		var directoryEnvelope identitypostgres.DeliveryEnvelope
		if err := pool.QueryRow(ctx, `SELECT binding_aad,envelope_key_id,ciphertext FROM identity.delivery_intents WHERE tenant_id=$1 AND effect_id=$2`, string(directoryResult.Binding.TenantID), directoryResult.Binding.RecordID).Scan(&directoryAAD, &directoryEnvelope.KeyID, &directoryEnvelope.Ciphertext); err != nil {
			t.Fatal(err)
		}
		directoryBound, err := decodeBinding(directoryAAD)
		if err != nil {
			t.Fatal(err)
		}
		directoryEnvelope.EffectIndex = directoryBound.Intent.EffectIndex
		directoryPayload, err := contributor.store.codec.open(ctx, directoryBound, directoryEnvelope)
		if err != nil || directoryPayload.Recipient.Address != input.Recipient.Address || directoryPayload.Recipient.ScopeDigest == input.Recipient.ScopeDigest {
			t.Fatal("caller recipient claim replaced primary discovery", err)
		}
		stale := b
		stale.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		mutateAt := policyCalls + 3 // before discovery, before encryption, before reservation
		policyHook = func() {
			if policyCalls == mutateAt {
				if _, err := pool.Exec(ctx, `UPDATE identity.identifiers SET canonical_value='changed@example.test',version=2 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='recipient-email'`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			}
		}
		var recipientConflict identity.ConflictError
		if _, err := executor.AdmitIdentifier(ctx, stale, scope, input, repo, "recipient-email", policies, keyed, "directory-stale-key"); !errors.As(err, &recipientConflict) {
			t.Fatal("changed recipient committed stale discovery", err)
		}
		policyHook = nil
		if pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&intents) != nil || intents != 2 {
			t.Fatal("stale recipient persisted a delivery", intents)
		}
		// Pending addresses are not general notification destinations. Only
		// the closed verification purposes can prepare them, never revoked ones.
		if _, err := pool.Exec(ctx, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='recipient-email'`, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
		pending := b
		pending.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		notification := input
		notification.Recipient.Address = "changed@example.test"
		notification.Purpose = "security-notification"
		if _, err := executor.AdmitIdentifier(ctx, pending, scope, notification, repo, "recipient-email", policies, keyed, "directory-pending-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("pending address received general notification", err)
		}
		pendingInput := input
		pendingInput.Recipient.Address = "changed@example.test"
		if _, err := executor.AdmitIdentifier(ctx, pending, scope, pendingInput, repo, "recipient-email", policies, keyed, "directory-pending-key"); err != nil {
			t.Fatal("pending address verification denied", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
		if _, err := executor.AdmitIdentifier(ctx, pending, scope, input, repo, "recipient-email", policies, keyed, "directory-blocked-key"); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("blocked owner admitted recipient", err)
		}
		return
	}
	deliveryPlan, err := prepared.Plan()
	if err != nil {
		t.Fatal(err)
	}
	var command identity.Command
	if native {
		command, err = prepared.EnqueueCommand()
		spec, _ := command.Feature()
		b = spec.Binding
	} else {
		command, err = identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive})
	}
	if err != nil {
		t.Fatal(err)
	}
	record := compositionRecord(t, ctx, b, time.Now().UTC().Truncate(time.Microsecond))
	var digest [32]byte
	if native {
		record = compositionEnqueueRecord(t, b)
		digest, err = identitypostgres.FeatureAuditBindingDigest(b, EnqueueOperation(), "delivery_intent", record)
	} else {
		digest, err = identitypostgres.AuditBindingDigest(b, record)
	}
	if err != nil {
		t.Fatal(err)
	}
	declaration := identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, Delivery: &deliveryPlan}
	if native {
		declaration.SubjectType = "delivery_intent"
		declaration.Feature = &identitypostgres.FeatureRegistration{Contributor: enqueue.Descriptor(), Operation: EnqueueOperation()}
		declaration.Audits[0].RetentionClass = "protected"
		declaration.Lifecycle.EventType = "delivery.enqueued.v1"
		changed := declaration
		changedPlan := deliveryPlan
		changedPlan.Intents = append([]identitypostgres.DeliveryIntentPlan(nil), deliveryPlan.Intents...)
		changedPlan.Intents[0].TemplateVersion++
		changed.Delivery = &changedPlan
		if _, err := coordinator.PrepareCommandPlan(b, command, changed); err == nil {
			t.Fatal("native command admitted changed frozen rendering declaration")
		}
	}
	plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
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
	var provisional identity.CommandResult
	if native {
		if _, err := enqueue.ApplyFeature(ctx, work, command); err == nil {
			t.Fatal("native contributor entered outside exact coordinator invocation")
		}
		provisional, err = coordinator.ApplyFeature(ctx, work, command)
		if err != nil {
			t.Fatal("native enqueue apply failed", err)
		}
	} else {
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
		provisional = identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()}
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
	if mode != "native-missing" {
		if err := contributor.Stage(ctx, work, prepared); err != nil {
			t.Fatal("original delivery staging failed", err)
		}
	}
	var visible int
	if pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&visible) != nil || visible != 0 {
		t.Fatal("delivery visible before original commit")
	}
	if mode == "delivery-failure" || mode == "native-failure" {
		if _, err := pool.Exec(ctx, `ALTER TABLE identity.delivery_intents ADD CONSTRAINT test_delivery_deny CHECK (false)`); err != nil {
			t.Fatal("delivery failure setup failed")
		}
	}
	receipt, err := coordinator.Commit(work, provisional)
	if mode == "delivery-failure" || mode == "native-failure" || mode == "native-missing" {
		if err == nil || receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("denied delivery became committed")
		}
		var users, intents, effects, audits int
		wantAudits := 0
		if native {
			// Native execution prebuilds classified failure evidence. Abort first
			// rolls back domain effects, then durably records that failure only.
			wantAudits = 1
			if receipt.Outcome != identity.CommitOutcomeNotCommitted || receipt.Validate() != nil {
				t.Fatal("native rollback did not retain a valid failure receipt")
			}
		}
		queryErr := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings)`).Scan(&users, &intents, &effects, &audits)
		if queryErr != nil || users != 0 || intents != 0 || effects != 0 || audits != wantAudits {
			t.Fatal("delivery failure retained an original mutation prefix", queryErr, users, intents, effects, audits)
		}
		if native {
			var outcome int
			auditErr := pool.QueryRow(ctx, `SELECT r.outcome FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.tenant_id=$1 AND rtrim(translate(encode(b.command_id,'base64'),'+/','-_'),'=')=$2`, string(b.TenantID), string(b.CommandID)).Scan(&outcome)
			if auditErr != nil || outcome != int(audit.OutcomeFailed) {
				t.Fatal("native rollback retained success rather than failure evidence", auditErr, outcome)
			}
		}
		return
	}
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owned original composition did not commit", err)
	}
	var users, intents, effects, audits int
	wantUsers := 1
	if native {
		wantUsers = 0
	}
	if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM outbox_messages),(SELECT count(*) FROM audit.identity_command_bindings)`).Scan(&users, &intents, &effects, &audits) != nil || users != wantUsers || intents != 1 || effects != 2 || audits != 1 {
		t.Fatal("original committed owners disagree", users, intents, effects, audits)
	}
	if mode == "no-op" || mode == "native-no-op" {
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
	if mode == "native-receipt" {
		receiptRunner, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14, ReceiptVersion: 15, ReceiptCommandVersion: 16}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiptRunner.Up(ctx); err != nil {
			t.Fatal("populated native receipt migration", err)
		}
		testNativeReceipt(t, ctx, pool, owned, repo, auditing, lifecycle, contributor, receipt.Binding)
	}
	if strings.HasPrefix(mode, "native-cancel") {
		cancelRunner, err := migrations.NewRunner(MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14, CancellationVersion: 15}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cancelRunner.Up(ctx); err != nil {
			t.Fatal("populated cancellation migration", err)
		}
		testNativeCancellation(t, ctx, pool, owned, repo, auditing, lifecycle, contributor, receipt.Binding)
	}
}

type enqueueDecisionFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f enqueueDecisionFunc) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, dc)
}

func compositionEnqueueRecord(t *testing.T, b identity.CommandBinding) audit.Record {
	t.Helper()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.delivery.enqueue", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "delivery_intent", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "delivery_intent", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	return record
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
