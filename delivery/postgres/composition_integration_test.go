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
	for _, mode := range []string{"committed", "no-op", "delivery-failure", "native-committed", "native-owned", "native-compatible-custody", "native-no-op", "native-missing", "native-failure"} {
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
	input.NoOpEquivalent = mode == "no-op" || mode == "native-no-op"
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
	if mode == "native-owned" {
		var permit bool
		var policyMode string
		var policyCalls int
		var requireAdmissionScope bool
		var denyAfter int
		policy := enqueueDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			policyCalls++
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
