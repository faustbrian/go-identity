//go:build integration

package postgres

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

// QA3/QA5: public owned processing, not a test-written Queue or worker engine.
func testPublicWorker(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, config EnqueueConfig, admission EnqueueCommandRequest, first delivery.EnqueueResult, permit *bool) {
	t.Helper()
	scope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "worker-correlation", Request: authorization.Request{Tenant: authorization.TenantID(admission.Binding.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "worker-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "worker-a"}}}
	workerConfig := WorkerConfig{Scope: scope, ProviderConfigVersion: 1}
	var calls atomic.Int32
	sender := attemptTestSender(func(call context.Context, attempt delivery.Attempt) (delivery.DeliveryResult, error) {
		calls.Add(1)
		assertWorkerAudit(t, call, pool, attempt.IntentID, "identity.delivery.attempt", 1, 2)
		if attempt.IntentID != first.IntentID || attempt.IdempotencyKey != string(first.IntentID) || attempt.TenantID != delivery.TenantID(admission.Binding.TenantID) || attempt.Body != "Code: synthetic-code" || attempt.Subject != "Verification" || !attempt.ValidUntil.Equal(admission.ExpiresAt) || attempt.Generation != 1 {
			t.Error("public worker changed frozen effect or provider key")
		}
		check := beginIntentTestTransaction(t, call, pool)
		if _, err := check.Exec(call, `SELECT i.effect_id FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) FOR UPDATE OF i,p NOWAIT`); err != nil {
			t.Error("Sender ran under SQL ownership", err)
		}
		var attempts int
		if err := check.QueryRow(call, `SELECT count(*) FROM identity.delivery_attempt_history`).Scan(&attempts); err != nil || attempts != 1 {
			t.Error("Sender ran before durable attempt", err)
		}
		if err := check.Rollback(call); err != nil {
			t.Error(err)
		}
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	})
	worker, err := service.NewWorker(workerConfig, sender)
	if err != nil {
		t.Fatal("owned public worker construction", err)
	}
	if _, err := service.NewWorker(workerConfig, nil); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("production worker admitted nil Sender", err)
	}
	if _, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 3}, sender); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("unretained provider defaulted", err)
	}
	otherProvider, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 2}, sender)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := otherProvider.ProcessOne(ctx); err != nil || out.Claimed {
		t.Fatal("public provider selected another profile sharing retry policy", err)
	}
	*permit = false
	if _, err := worker.ProcessOne(ctx); !errors.Is(err, delivery.ErrForbidden) || calls.Load() != 0 {
		t.Fatal("denied worker leased or sent", err)
	}
	var history int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_attempt_history`).Scan(&history); err != nil || history != 0 {
		t.Fatal("denial created attempt", err)
	}
	*permit = true
	// Construction owns its snapshot; mutating caller attributes cannot retarget.
	workerConfig.Scope.Request.Resource.ID = "other-worker"
	start := make(chan struct{})
	var wg sync.WaitGroup
	var claimed atomic.Int32
	for range 4 {
		wg.Go(func() {
			<-start
			out, err := worker.ProcessOne(ctx)
			if err != nil {
				t.Error("public processing", err)
				return
			}
			if out.Claimed {
				claimed.Add(1)
				if out.Completion.State != delivery.StateAccepted || out.Completion.Commit != delivery.CommitCommitted {
					t.Error("acceptance claimed delivery or lost commit")
				}
			}
		})
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || claimed.Load() != 1 {
		t.Fatal("concurrent public workers duplicated effect")
	}
	assertWorkerAudit(t, ctx, pool, first.IntentID, "identity.delivery.attempt", 2, 3)
	// Unknown invocation must never be made available for automatic resend.
	request := admission
	request.Binding.CommandID = "AgICAgICAgICAgICAgICAg"
	request.IdempotencyKey = "public-worker-unknown-key"
	second, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		return delivery.DeliveryResult{}, errors.New("synthetic-private-provider-error")
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := unknown.ProcessOne(ctx)
	if !errors.Is(err, delivery.ErrOutcomeUnknown) || out.IntentID != second.IntentID || out.Completion.Commit != delivery.CommitCommitted || out.Completion.State != delivery.StateOutcomeUnknown {
		t.Fatal("ambiguous public worker lost durable uncertainty", err)
	}
	if out, err := unknown.ProcessOne(ctx); err != nil || out.Claimed {
		t.Fatal("unknown public send was retried", err)
	}
	// QA4: authoritative transient no-success evidence schedules a retry,
	// preserving the original message/key and respecting a provider throttle.
	request.Binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	request.IdempotencyKey = "public-worker-retry-key"
	third, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	retrying, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		return delivery.DeliveryResult{State: delivery.StateTransientFailure, ObservedAt: time.Now().UTC(), RetryAfter: 2 * time.Second}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := retrying.ProcessOne(ctx); err != nil || out.Completion.State != delivery.StateRetryWait {
		t.Fatal("public worker lost authoritative retry", err)
	}
	if out, err := retrying.ProcessOne(ctx); err != nil || out.Claimed {
		t.Fatal("retry ignored throttle", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=clock_timestamp()-interval '1 microsecond' WHERE effect_id=$1`, string(third.IntentID)); err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != third.IntentID || claim.Attempt.Generation != 2 || claim.Attempt.IdempotencyKey != string(third.IntentID) || claim.Attempt.Body != "Code: synthetic-code" || !claim.Attempt.ValidUntil.Equal(admission.ExpiresAt) {
		t.Fatal("public direct claim lost retry identity", err)
	}
	completion := delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, WorkerID: "worker-a", IntentID: claim.Attempt.IntentID, Generation: 2, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}}
	wrong := completion
	wrong.WorkerID = "another-worker"
	if _, err := worker.Complete(ctx, wrong); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("public wrong worker completed lease", err)
	}
	if _, err := otherProvider.Complete(ctx, completion); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("public wrong provider completed lease", err)
	}
	result, err := worker.Complete(ctx, completion)
	if err != nil || result.State != delivery.StateDelivered || result.Commit != delivery.CommitCommitted {
		t.Fatal("public direct completion", err)
	}
	event := assertWorkerAudit(t, ctx, pool, third.IntentID, "identity.delivery.confirm", 4, 5)
	if replay, err := worker.Complete(ctx, completion); err != nil || replay != result {
		t.Fatal("public completion replay changed", err)
	}
	if replayEvent := assertWorkerAudit(t, ctx, pool, third.IntentID, "identity.delivery.confirm", 4, 5); replayEvent != event {
		t.Fatal("worker replay emitted another success audit")
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT ciphertext IS NULL AND envelope_key_id IS NULL FROM identity.delivery_intents WHERE effect_id=$1`, string(third.IntentID)).Scan(&erased); err != nil || !erased {
		t.Fatal("public terminal completion retained payload", err)
	}
	testPublicWorkerRevocation(t, ctx, pool, service, admission, scope, permit)
	testPublicWorkerAuditRollbackAndSweeps(t, ctx, pool, service, admission, scope)
}

func testPublicWorkerAuditRollbackAndSweeps(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, admission EnqueueCommandRequest, scope authorization.DecisionContext) {
	t.Helper()
	request := admission
	request.Binding.CommandID = "DQ0NDQ0NDQ0NDQ0NDQ0NDQ"
	request.IdempotencyKey = "worker-audit-rollback-key"
	intent, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	worker, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION audit.fail_worker_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('identity.delivery.attempt','identity.delivery.confirm','identity.delivery.mark_unknown') THEN RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_worker_test BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION audit.fail_worker_test()`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.ProcessOne(ctx); !errors.Is(err, delivery.ErrUnavailable) || calls != 0 {
		t.Fatal("audit failure did not prevent provider invocation", err)
	}
	var intact bool
	if err := pool.QueryRow(ctx, `SELECT state='planned' AND ciphertext IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity.delivery_attempt_history h WHERE h.effect_id=i.effect_id) FROM identity.delivery_intents i WHERE effect_id=$1`, string(intent.IntentID)).Scan(&intact); err != nil || !intact {
		t.Fatal("failed audit committed lease/history", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE audit.records DISABLE TRIGGER fail_worker_test`); err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != intent.IntentID {
		t.Fatal("audit rollback lost retryable claim", err)
	}
	completion := delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: intent.IntentID, WorkerID: "worker-a", Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}}
	if _, err := pool.Exec(ctx, `ALTER TABLE audit.records ENABLE TRIGGER fail_worker_test`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Complete(ctx, completion); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing terminal audit accepted completion", err)
	}
	if err := pool.QueryRow(ctx, `SELECT i.state='submitted' AND i.ciphertext IS NOT NULL AND h.completion_digest IS NULL AND p.lease_owner='worker-a' FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id) WHERE i.effect_id=$1`, string(intent.IntentID)).Scan(&intact); err != nil || !intact {
		t.Fatal("audit failure split terminal transition/erasure/history", err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER fail_worker_test ON audit.records; DROP FUNCTION audit.fail_worker_test()`); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Complete(ctx, completion); err != nil {
		t.Fatal(err)
	}
	assertWorkerAudit(t, ctx, pool, intent.IntentID, "identity.delivery.confirm", 2, 3)

	// Exhaustion is local retry-policy evidence. Neither invoked nor uninvoked
	// completion may manufacture a provider observation from that classification.
	for index, invoked := range []bool{false, true} {
		request.Binding.CommandID = identity.CommandID([]string{"EREREREREREREREREREREQ", "EhISEhISEhISEhISEhISEg"}[index])
		request.IdempotencyKey = []string{"worker-audit-uninvoked-exhaustion", "worker-audit-invoked-exhaustion"}[index]
		last, err := service.Enqueue(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		limit := int(service.policies.profiles[1].Attempts)
		for attempt := 1; attempt <= limit; attempt++ {
			claim, err := worker.Claim(ctx)
			if err != nil || !claim.Claimed || claim.Attempt.IntentID != last.IntentID {
				t.Fatal("exhaustion claim", err)
			}
			completion := delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: last.IntentID, WorkerID: "worker-a", Generation: claim.Attempt.Generation, Invoked: invoked}
			if invoked {
				completion.Result = delivery.DeliveryResult{State: delivery.StateTransientFailure, ObservedAt: time.Now().UTC()}
			}
			out, err := worker.Complete(ctx, completion)
			if err != nil {
				t.Fatal(err)
			}
			if attempt < limit {
				if out.State != delivery.StateRetryWait {
					t.Fatal("retry exhausted early")
				}
				// Advance only the task fixture's retry clock; all leases, histories
				// and completions still pass through the public worker.
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=clock_timestamp() WHERE effect_id=$1`, string(last.IntentID)); err != nil {
					t.Fatal(err)
				}
			} else if out.State != delivery.StateExhausted {
				t.Fatal("final attempt did not exhaust")
			}
		}
		if err := pool.QueryRow(ctx, `SELECT state='exhausted' AND ciphertext IS NULL FROM identity.delivery_intents WHERE effect_id=$1`, string(last.IntentID)).Scan(&intact); err != nil || !intact {
			t.Fatal("exhaustion retained custody", err)
		}
		event := assertWorkerAudit(t, ctx, pool, last.IntentID, "identity.delivery.attempt", uint64(2*limit), uint64(2*limit+1))
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT canonical_record FROM audit.records WHERE record_id=$1`, event).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		record, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
		if err != nil || record.Attributes()["provider.result"] != "" || record.Context().CausationID() != string(request.Binding.CommandID) {
			t.Fatal("local exhaustion invented provider evidence or changed original command", err)
		}
	}

	// A lost invocation lease is uncertainty, not rejection or resend.
	request.Binding.CommandID = "Dg4ODg4ODg4ODg4ODg4ODg"
	request.IdempotencyKey = "worker-audit-lost-lease-key"
	lost, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	claim, err = worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != lost.IntentID {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE effect_id=$1`, string(lost.IntentID)); err != nil {
		t.Fatal(err)
	}
	if out, err := worker.Claim(ctx); err != nil || out.Claimed {
		t.Fatal("lost lease became resendable", err)
	}
	lostEvent := assertWorkerAudit(t, ctx, pool, lost.IntentID, "identity.delivery.mark_unknown", 2, 3)
	var lostRaw []byte
	if err := pool.QueryRow(ctx, `SELECT canonical_record FROM audit.records WHERE record_id=$1`, lostEvent).Scan(&lostRaw); err != nil {
		t.Fatal(err)
	}
	lostRecord, err := audit.ParseCanonicalJSON(lostRaw, audit.DefaultLimits())
	if err != nil || lostRecord.Attributes()["provider.result"] != "" || lostRecord.Context().CausationID() != string(request.Binding.CommandID) {
		t.Fatal("lease loss invented provider observation", err)
	}

	// Cleanup may only mutate this selected provider's effects.
	request.Binding.CommandID = "Dw8PDw8PDw8PDw8PDw8PDw"
	request.IdempotencyKey = "worker-audit-expiry-key"
	request.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
	expired, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Binding.CommandID = "EBAQEBAQEBAQEBAQEBAQEA"
	request.IdempotencyKey = "worker-audit-foreign-expiry-key"
	request.ProviderConfigVersion = 2
	foreign, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if out, err := worker.Claim(ctx); err != nil || out.Claimed {
		t.Fatal(err)
	}
	assertWorkerAudit(t, ctx, pool, expired.IntentID, "identity.delivery.attempt", 1, 2)
	if err := pool.QueryRow(ctx, `SELECT state='planned' AND ciphertext IS NOT NULL FROM identity.delivery_intents WHERE effect_id=$1`, string(foreign.IntentID)).Scan(&intact); err != nil || !intact {
		t.Fatal("worker cleanup crossed provider authority", err)
	}
	other, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 2}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		t.Fatal("expired provider invoked")
		return delivery.DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := other.Claim(ctx); err != nil || out.Claimed {
		t.Fatal(err)
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state='expired' AND ciphertext IS NULL FROM identity.delivery_intents WHERE effect_id=$1`, string(foreign.IntentID)).Scan(&erased); err != nil || !erased {
		t.Fatal("selected provider did not erase expired custody", err)
	}
}

func assertWorkerAudit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, intent delivery.IntentID, action string, before, after uint64) string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT canonical_record FROM audit.records WHERE action=$1 AND subject_id=$2`, action, string(intent))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var match string
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		record, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
		if err != nil {
			t.Fatal("worker audit not canonical", err)
		}
		attrs := record.Attributes()
		if attrs["aggregate.before_version"] != strconv.FormatUint(before, 10) || attrs["aggregate.after_version"] != strconv.FormatUint(after, 10) {
			continue
		}
		if match != "" || record.Actor().Kind() != audit.ActorSystem || record.Actor().ID() != "worker-service" || record.Outcome() != audit.OutcomeSucceeded || attrs["retention.class"] != "protected" || attrs["identity.profile"] != "identity.security.v1" || attrs["provider.version"] != "1" || record.Policy().Version != "1" || record.Context().CausationID() != attrs["command.id"] || !record.Changes().Redacted() {
			t.Fatal("worker audit missing or duplicated protected attribution")
		}
		match = record.ID()
	}
	if rows.Err() != nil || match == "" {
		t.Fatal("worker transition committed without protected audit", rows.Err())
	}
	return match
}

// QA3/QA9: policy can be revoked across IO even after pre-claim permission.
// Exercise the real public worker, not a direct call to its policy helper.
func testPublicWorkerRevocation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, admission EnqueueCommandRequest, scope authorization.DecisionContext, permit *bool) {
	t.Helper()
	request := admission
	request.Binding.CommandID = "BAQEBAQEBAQEBAQEBAQEBA"
	request.IdempotencyKey = "public-worker-postclaim-key"
	first, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	original := service.executor.authorize
	t.Cleanup(func() { service.executor.authorize = original; *permit = true })
	checks, calls := 0, 0
	service.executor.authorize = workerPolicyFunc(func(call context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if dc.Request.Action == "identity.delivery.process" {
			checks++
			if checks == 2 {
				return authorization.Decision{Outcome: authorization.Deny, Revision: dc.PolicyRevision}, nil
			}
		}
		return original.Decide(call, dc)
	})
	worker, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.ProcessOne(ctx); !errors.Is(err, delivery.ErrForbidden) || calls != 0 || checks != 2 {
		t.Fatal("post-custody revocation allowed Sender", err)
	}
	var noInvocation bool
	if err := pool.QueryRow(ctx, `SELECT completion_digest IS NOT NULL AND outcome=9 FROM identity.delivery_attempt_history WHERE effect_id=$1 AND generation=1`, string(first.IntentID)).Scan(&noInvocation); err != nil || !noInvocation {
		t.Fatal("denied committed lease lost no-invocation cleanup", err)
	}
	service.executor.authorize = original
	// Keep that cleanup retry out of the next independent revocation scenario.
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=clock_timestamp()+interval '1 minute' WHERE effect_id=$1`, string(first.IntentID)); err != nil {
		t.Fatal(err)
	}
	request.Binding.CommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
	request.IdempotencyKey = "public-worker-complete-denial-key"
	second, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx)
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != second.IntentID {
		t.Fatal("direct revocation claim", err)
	}
	completion := delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, WorkerID: "worker-a", IntentID: claim.Attempt.IntentID, Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}}
	*permit = false
	if _, err := worker.Complete(ctx, completion); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("revoked direct completion committed success", err)
	}
	assertPending := func(intent delivery.IntentID) {
		t.Helper()
		var pending bool
		if err := pool.QueryRow(ctx, `SELECT i.state='submitted' AND h.completion_digest IS NULL AND p.lease_owner='worker-a' FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id) JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) WHERE i.effect_id=$1`, string(intent)).Scan(&pending); err != nil || !pending {
			t.Fatal("revoked completion mutated durable evidence", err)
		}
	}
	assertPending(second.IntentID)
	*permit = true
	request.Binding.CommandID = "BgYGBgYGBgYGBgYGBgYGBg"
	request.IdempotencyKey = "public-worker-sender-revocation-key"
	third, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	invoked := 0
	revoked, err := service.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
		invoked++
		*permit = false
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := revoked.ProcessOne(ctx)
	if !errors.Is(err, delivery.ErrOutcomeUnknown) || out.IntentID != third.IntentID || out.Completion.Commit != delivery.CommitUnknown || invoked != 1 {
		t.Fatal("revoked Sender completion lost recovery identity", err)
	}
	assertPending(third.IntentID)
	*permit = true
	if out, err := revoked.ProcessOne(ctx); err != nil || out.Claimed || invoked != 1 {
		t.Fatal("revoked uncertain completion was resubmitted", err)
	}
}
