//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicLeaseOwner interface {
	RenewLease(context.Context, delivery.IntentID, uint32) (time.Time, error)
	ReleaseLease(context.Context, delivery.IntentID, uint32) (delivery.CompleteResult, error)
}

// QA: both concrete public surfaces, current authority and same-policy provider
// isolation over the owned coordinator/envelope/primary, not a fake Queue.
func testPublicLeaseMaintenance(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner *EnqueueService, admission EnqueueCommandRequest, first delivery.EnqueueResult, permit *bool, fullQueue bool) {
	t.Helper()
	scope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "lease-correlation", Request: authorization.Request{Tenant: authorization.TenantID(admission.Binding.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "worker-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "lease-worker"}}}
	calls := 0
	worker, err := owner.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		return delivery.DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var maintenance publicLeaseOwner = worker
	if fullQueue {
		queue, err := owner.NewQueue(WorkerConfig{Scope: scope, ProviderConfigVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		maintenance = queue
	}
	claim, err := worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != first.IntentID {
		t.Fatal("public lease claim", err)
	}
	id, generation := claim.Attempt.IntentID, claim.Attempt.Generation
	snapshot := func() string {
		t.Helper()
		var digest string
		if err := pool.QueryRow(ctx, `SELECT md5(row_to_json(i)::text || row_to_json(p)::text || row_to_json(h)::text) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id,generation) WHERE i.effect_id=$1`, string(id)).Scan(&digest); err != nil {
			t.Fatal("durable lease snapshot", err)
		}
		return digest
	}
	before := snapshot()
	*permit = false
	if until, err := maintenance.RenewLease(ctx, id, generation); !errors.Is(err, delivery.ErrForbidden) || !until.IsZero() {
		t.Fatal("denied public renewal granted ownership", err)
	}
	if out, err := maintenance.ReleaseLease(ctx, id, generation); !errors.Is(err, delivery.ErrForbidden) || out != (delivery.CompleteResult{}) {
		t.Fatal("denied public release disclosed outcome", err)
	}
	*permit = true
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := maintenance.RenewLease(cancelled, id, generation); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled renewal continued", err)
	}
	if _, err := maintenance.ReleaseLease(cancelled, id, generation); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled release continued", err)
	}
	if before != snapshot() {
		t.Fatal("denied/cancelled lease maintenance changed state")
	}
	// Both providers deliberately share policy version and digest. A policy-only
	// check cannot distinguish this foreign heartbeat from the genuine owner.
	for _, variant := range []string{"provider", "tenant", "worker", "generation"} {
		c := WorkerConfig{Scope: scope.Clone(), ProviderConfigVersion: 1}
		g := generation
		switch variant {
		case "provider":
			c.ProviderConfigVersion = 2
		case "tenant":
			c.Scope.Request.Tenant = "foreign-tenant"
		case "worker":
			c.Scope.Request.Resource.ID = "foreign-worker"
		case "generation":
			g++
		}
		other, err := owner.NewWorker(c, workerSenderFunc(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
			return delivery.DeliveryResult{}, nil
		}))
		if err != nil {
			t.Fatal("foreign variant composition", err)
		}
		if until, err := other.RenewLease(ctx, id, g); !errors.Is(err, delivery.ErrConflict) || !until.IsZero() {
			t.Fatal("foreign "+variant+" renewed lease", err)
		}
		if out, err := other.ReleaseLease(ctx, id, g); !errors.Is(err, delivery.ErrConflict) || out != (delivery.CompleteResult{}) {
			t.Fatal("foreign "+variant+" released lease", err)
		}
		if before != snapshot() {
			t.Fatal("foreign maintenance changed original lease")
		}
	}
	var start time.Time
	if err := pool.QueryRow(ctx, `SELECT started_at FROM identity.delivery_attempt_history WHERE effect_id=$1`, string(id)).Scan(&start); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		until, err := maintenance.RenewLease(ctx, id, generation)
		if err != nil || until.Before(claim.LeaseUntil) || until.After(start.Add(time.Minute)) || until.After(claim.Attempt.ValidUntil) {
			t.Fatal("public heartbeat reset original lifetime", err)
		}
		var retained bool
		if err := pool.QueryRow(ctx, `SELECT i.status_version=2 AND i.state='submitted' AND i.ciphertext IS NOT NULL AND p.generation=1 AND p.attempt_number=1 AND p.lease_until=$2 AND h.lease_until=$2 AND h.started_at=$3 AND h.outcome IS NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id,generation) WHERE i.effect_id=$1`, string(id), until, start).Scan(&retained); err != nil || !retained {
			t.Fatal("renewal changed status/attempt or lost durable deadline", err)
		}
	}
	before = snapshot()
	if _, err := pool.Exec(ctx, `CREATE FUNCTION audit.fail_lease_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.delivery.mark_unknown' THEN RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_lease_test BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION audit.fail_lease_test()`); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.ReleaseLease(ctx, id, generation); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("public release omitted required audit", err)
	}
	if before != snapshot() {
		t.Fatal("release audit rollback lost live lease")
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER fail_lease_test ON audit.records; DROP FUNCTION audit.fail_lease_test()`); err != nil {
		t.Fatal(err)
	}
	result, err := maintenance.ReleaseLease(ctx, id, generation)
	if err != nil || result.Commit != delivery.CommitCommitted || result.State != delivery.StateOutcomeUnknown {
		t.Fatal("public release fabricated provider failure", err)
	}
	event := assertWorkerAudit(t, ctx, pool, id, "identity.delivery.mark_unknown", 2, 3)
	before = snapshot()
	for range 2 {
		if out, err := maintenance.ReleaseLease(ctx, id, generation); err != nil || out != result {
			t.Fatal("public release replay lost original result", err)
		}
	}
	if before != snapshot() || event != assertWorkerAudit(t, ctx, pool, id, "identity.delivery.mark_unknown", 2, 3) {
		t.Fatal("release replay mutated state or audit")
	}
	if _, err := maintenance.RenewLease(ctx, id, generation); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("released public lease resurrected", err)
	}
	if claim, err := worker.Claim(ctx); err != nil || claim.Claimed || calls != 0 {
		t.Fatal("public release granted resend or invoked Sender", err)
	}
	var uncertain bool
	if err := pool.QueryRow(ctx, `SELECT i.state='outcome-unknown' AND i.ciphertext IS NOT NULL AND p.lease_owner IS NULL AND p.lease_until IS NULL AND p.next_attempt_at IS NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) WHERE effect_id=$1`, string(id)).Scan(&uncertain); err != nil || !uncertain {
		t.Fatal("released uncertainty lost recovery custody", err)
	}
	// Concurrent renewal and completion cannot resurrect a definitive outcome.
	r := admission
	r.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r.IdempotencyKey = "public-lease-race-key"
	queued, err := owner.Enqueue(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	claim, err = worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != queued.IntentID {
		t.Fatal("race claim", err)
	}
	begin := make(chan struct{})
	var group sync.WaitGroup
	var renewal, completion error
	var completed delivery.CompleteResult
	group.Go(func() { <-begin; _, renewal = maintenance.RenewLease(ctx, queued.IntentID, claim.Attempt.Generation) })
	group.Go(func() {
		<-begin
		completed, completion = worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, WorkerID: "lease-worker", IntentID: queued.IntentID, Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}})
	})
	close(begin)
	group.Wait()
	if completion != nil || completed.State != delivery.StateDelivered || renewal != nil && !errors.Is(renewal, delivery.ErrConflict) {
		t.Fatal("public renewal/completion race lost outcome", renewal, completion)
	}
	if _, err := maintenance.RenewLease(ctx, queued.IntentID, claim.Attempt.Generation); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("terminal renewal resurrected lease", err)
	}
	if _, err := maintenance.ReleaseLease(ctx, queued.IntentID, claim.Attempt.Generation); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("release overwrote terminal completion", err)
	}
	// A heartbeat that begins before expiry must still fail after its database
	// lock wait crosses expiry. Only this test-owned primary is time-advanced.
	r.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r.IdempotencyKey = "public-lease-lockwait-key"
	queued, err = owner.Enqueue(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	claim, err = worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != queued.IntentID {
		t.Fatal("lock-wait claim", err)
	}
	tx := beginIntentTestTransaction(t, ctx, pool)
	if _, err := tx.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()+INTERVAL '100 milliseconds' WHERE effect_id=$1`, string(queued.IntentID)); err != nil {
		t.Fatal(err)
	}
	var waited time.Time
	var waitErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		waited, waitErr = maintenance.RenewLease(ctx, queued.IntentID, claim.Attempt.Generation)
	}()
	defer func() {
		rollbackAttempt(tx)
		<-done
	}()
	// Prove a real blocked heartbeat, not merely scheduling it after expiry.
	blocked := false
	for limit := time.Now().Add(time.Second); time.Now().Before(limit); {
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT lease_until,clock_timestamp(),policy_digest%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if !blocked || !waited.IsZero() || !errors.Is(waitErr, delivery.ErrConflict) {
		t.Fatal("lock-wait heartbeat resurrected expired ownership", waitErr)
	}
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT i.status_version=2 AND h.lease_until=$2 AND h.outcome IS NULL FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id) WHERE effect_id=$1`, string(queued.IntentID), claim.LeaseUntil).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("denied lock-wait renewal changed historical deadline", err)
	}
}
