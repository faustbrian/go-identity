//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed audit roles are cluster-scoped, whereas fixtures own isolated databases.
// Share only exact safe roles created in this disposable test cluster; never
// adopt partial or privileged role-name collisions as a successful preflight.
func reserveIntentAuditRoles(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var count, unsafe int
	if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&count, &unsafe); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		if _, err := pool.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
			t.Fatal("owned audit preflight failed", err)
		}
	} else if count != 3 || unsafe != 0 {
		t.Fatal("unsafe audit role fixture collision")
	}
}

// Policy is the deliberate seam. Namespace selection, retained binding and
// durable effects use the real owners and an isolated PostgreSQL database.
func TestAnonymousDeliveryUserManagementIsolation(t *testing.T) {
	ctx, pool := intentDatabase(t)
	for _, sql := range []string{attemptSchemaSQL, stateSchemaSQL, receiptSchemaSQL} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	codec, binding, message := custodyFixture(t)
	binding.Command.UserID, binding.Command.AnonymousFlowID = "", "user-a"
	binding.Command.OperationID = "identity.otp.send"
	binding.Intent.SubjectID = "user-a"
	binding.Intent.EffectID = deliveryEffectID(binding.Deployment, binding.Command, 0)
	frozen, envelope, err := codec.seal(ctx, binding, message, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	store, err := newIntentStore("test", codec, map[uint64]providerProfile{1: {name: "test-provider", policyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := store.prepare(binding.Command, kernel.DeliveryPlan{Contributor: store.Descriptor(), Intents: []kernel.DeliveryIntentPlan{frozen.Intent}}, []kernel.DeliveryEnvelope{envelope})
	if err != nil {
		t.Fatal(err)
	}
	seedIntentCommand(t, ctx, pool, prepared[0])
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, store, prepared, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	service := &EnqueueService{
		executor: &enqueueExecutor{policyID: "policy-a", policyVersion: 1, timeout: time.Second, authorize: enqueueDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
		})},
		keyed: &keyedAdmission{pool: pool, deployment: "test"}, stateTracking: true,
		reconciliation: &reconciliationExecutor{coordinator: &kernel.Coordinator{}},
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "correlation-a", Request: authorization.Request{Subject: authorization.Subject{ID: "actor-a", Kind: authorization.SubjectServiceAccount}, Tenant: "tenant-a", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}}
	user := identity.UserID("user-a")
	intent := delivery.IntentID(frozen.Intent.EffectID)
	for _, versioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "status", true: "versioned-status"}[versioned], func(t *testing.T) {
			caller := caller.Clone()
			caller.Request.Action = "identity.delivery.status-get"
			q := delivery.StatusGetRequest{TenantID: "tenant-a", IntentID: intent}
			if versioned {
				out, err := service.VersionedStatusGet(ctx, q, user, caller)
				if !errors.Is(err, delivery.ErrNotFound) || out != (StatusSnapshot{}) {
					t.Fatal("user observed anonymous flow", err)
				}
			} else {
				out, err := service.StatusGet(ctx, q, user, caller)
				if !errors.Is(err, delivery.ErrNotFound) || out != (delivery.StatusGetResult{}) {
					t.Fatal("user observed anonymous flow", err)
				}
			}
		})
	}
	receipts := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	q := delivery.ReceiptRecordRequest{TenantID: "tenant-a", IntentID: intent, Generation: 1, Provider: "test-provider", ProviderEventID: "synthetic-event", Status: delivery.StateDelivered, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), IdempotencyKey: "synthetic-receipt"}
	t.Run("receipt-discovery", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		profile := receiptAuthProfile{Tenant: "tenant-a", Provider: "test-provider", Version: 1, Actor: "actor-a", KeyID: "callback-key", Key: [32]byte{9}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		successor := profile
		successor.Version = 2
		auth, err := newReceiptAuthenticator("test", []receiptAuthProfile{profile, successor}, 16384)
		if err != nil {
			t.Fatal(err)
		}
		service.receipts = &receiptExecutor{auth: auth, clock: receiptClockFunc(func() time.Time { return now })}
		op := ReceiptOperation()
		b := binding.Command
		b.UserID, b.AnonymousFlowID = user, ""
		b.ActorKind = authorization.SubjectServiceAccount
		b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(intent)
		caller := caller.Clone()
		caller.Request.Action = authorization.Action(op.OperationID)
		body, err := json.Marshal(map[string]any{"tenant_id": "tenant-a", "provider": "test-provider", "event_id": "synthetic-public-event", "intent_id": string(intent), "generation": 1, "status": uint8(delivery.StateDelivered), "observed_at": now.Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		var before, after int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, version := range []uint64{1, 2} {
			callback := SignedReceiptCallback{TenantID: "tenant-a", Provider: "test-provider", ProviderConfigVersion: version, KeyID: "callback-key", SignedAt: now, Body: body}
			callback.Signature = receiptAuthOracle(t, "test", [32]byte{9}, receiptSignedInput{Tenant: "tenant-a", Provider: callback.Provider, Version: version, KeyID: callback.KeyID, SignedAt: now, Body: body})
			out, err := service.RecordReceipt(ctx, ReceiptCommandRequest{Binding: b, ActorScope: caller, ExpectedStatusVersion: 1, Callback: callback})
			if !errors.Is(err, delivery.ErrNotFound) || out != (delivery.ReceiptRecordResult{}) {
				t.Fatal("user discovered anonymous receipt provider scope", err)
			}
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands`).Scan(&after); err != nil || after != before {
			t.Fatal("anonymous receipt admitted user command", err)
		}
	})
	for _, reconcile := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "reconcile-effect"}[reconcile], func(t *testing.T) {
			tx := beginIntentTestTransaction(t, ctx, pool)
			defer tx.Rollback(context.Background())
			var err error
			if reconcile {
				_, err = receipts.reconcileIn(ctx, receiptTestSQL(tx), q, "user-a", 0, [32]byte{}, [32]byte{})
			} else {
				_, err = receipts.recordIn(ctx, receiptTestSQL(tx), q, "user-a")
			}
			if !errors.Is(err, delivery.ErrNotFound) {
				t.Fatal("user selected anonymous effect", err)
			}
		})
	}
	t.Run("reconcile-discovery", func(t *testing.T) {
		op := ReconcileOperation()
		b := binding.Command
		b.UserID = user
		b.AnonymousFlowID = ""
		b.ActorKind = authorization.SubjectServiceAccount
		b.OperationID = op.OperationID
		b.SchemaID = op.SchemaID
		b.SchemaVersion = op.SchemaVersion
		b.RecordID = string(intent)
		caller := caller.Clone()
		caller.Request.Action = authorization.Action(op.OperationID)
		_, err := service.Reconcile(ctx, ReconcileCommandRequest{Binding: b, ActorScope: caller, ExpectedStatusVersion: 1, Generation: 1})
		if !errors.Is(err, delivery.ErrNotFound) {
			t.Fatal("user discovered anonymous provider scope", err)
		}
	})
	t.Run("reconcile-recovery", func(t *testing.T) {
		op := ReconcileOperation()
		caller := caller.Clone()
		caller.Request.Action = authorization.Action(op.OperationID)
		q := identity.RecoveryQuery{CommandID: binding.Command.CommandID, TenantID: "tenant-a", UserID: user, ActorID: "actor-a", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(intent)}
		out, err := service.RecoverReconciliation(ctx, q, caller)
		if !errors.Is(err, delivery.ErrNotFound) || out != (kernel.CommandRecord{}) {
			t.Fatal("user recovered anonymous provider scope", err)
		}
	})
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT state='planned' AND ciphertext=$1 AND binding_aad=$2 AND (SELECT count(*) FROM identity.delivery_receipts)=0 FROM identity.delivery_intents`, envelope.Ciphertext, prepared[0].aad).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("user management changed anonymous custody", err)
	}

	// A fresh envelope service/codec and the owned public Worker must consume
	// the retained anonymous profile without needing a fabricated user. Apply
	// real worker audit and retained-policy migrations before construction.
	files, err := fs.ReadDir(auditpg.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	reserveIntentAuditRoles(t, ctx, pool)
	for _, file := range files {
		wire, err := fs.ReadFile(auditpg.Migrations(), file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, policySchemaSQL); err != nil {
		t.Fatal(err)
	}
	policies, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	restartedCodec, _, _ := custodyFixture(t)
	restartedStore, err := newIntentStore("test", restartedCodec, map[uint64]providerProfile{1: {name: "test-provider", policyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	service.executor.custody = &Contributor{store: restartedStore, current: 1, envelopeKey: "envelope-a"}
	service.policies = policies
	workerScope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "worker-correlation", Request: authorization.Request{Subject: authorization.Subject{ID: "worker-actor", Kind: authorization.SubjectServiceAccount}, Tenant: "tenant-a", Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "worker-a"}}}
	sends := 0
	sender := attemptTestSender(func(call context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		sends++
		if pool.Stat().AcquiredConns() != 0 {
			t.Fatal("sender retained adapter transaction")
		}
		lock := beginIntentTestTransaction(t, call, pool)
		if _, err := lock.Exec(call, `SELECT effect_id FROM identity.delivery_intents FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("sender entered under lease locks", err)
		}
		if err := lock.Rollback(call); err != nil {
			t.Fatal(err)
		}
		if a.IntentID != intent || a.Body != message.Rendered.Body || a.Recipient != message.Recipient.Address || !a.ValidUntil.Equal(binding.Intent.ExpiresAt) {
			t.Fatal("restart changed original anonymous payload")
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	})
	worker, err := service.NewWorker(WorkerConfig{Scope: workerScope, ProviderConfigVersion: 1}, sender)
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(ctx)
	if err != nil || !result.Claimed || result.Completion.State != delivery.StateDelivered || result.Completion.Commit != delivery.CommitCommitted || sends != 1 {
		t.Fatal("anonymous worker failed", err)
	}
	if result, err := worker.ProcessOne(ctx); err != nil || result.Claimed || sends != 1 {
		t.Fatal("completed anonymous effect sent again", err)
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL FROM identity.delivery_intents`).Scan(&erased); err != nil || !erased {
		t.Fatal("anonymous worker did not erase terminal custody", err)
	}
}
