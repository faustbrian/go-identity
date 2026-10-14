//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestUserCancellationCannotSelectAnonymousFlowWithSameText(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal(err)
	}
	codec, binding, payload := custodyFixture(t)
	binding.Command.UserID = ""
	binding.Command.AnonymousFlowID = "user-a"
	binding.Command.OperationID = "identity.otp.send"
	binding.Intent.SubjectID = "user-a"
	binding.Intent.EffectID = deliveryEffectID(binding.Deployment, binding.Command, 0)
	frozen, envelope, err := codec.seal(ctx, binding, payload, "envelope-a")
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
	worker, err := newAttemptStore(pool, "test", codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.cancel(ctx, delivery.CancelRequest{TenantID: "tenant-a", IntentID: delivery.IntentID(frozen.Intent.EffectID), Reason: "user-cancel"}, "user-a")
	if !errors.Is(err, delivery.ErrNotFound) {
		t.Fatal("user selected anonymous namespace by equal ID text", err)
	}
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT state='planned' AND ciphertext IS NOT NULL FROM identity.delivery_intents`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("anonymous effect changed through user cancellation", err)
	}
}

func TestDurableCancellationPreventsUnsentWorkAndErasesCustody(t *testing.T) {
	for _, noop := range []bool{false, true} {
		t.Run(map[bool]string{false: "sendable", true: "noop"}[noop], func(t *testing.T) {
			ctx, pool := intentDatabase(t)
			if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
				t.Fatal(err)
			}
			s, p := preparedFixture(t, noop)
			seedIntentCommand(t, ctx, pool, p)
			tx := beginIntentTestTransaction(t, ctx, pool)
			if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			worker, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			request := delivery.CancelRequest{TenantID: "tenant-a", IntentID: delivery.IntentID(p.binding.Intent.EffectID), Reason: "workflow-cancel"}
			want := delivery.CancelResult{State: delivery.StateCancelled, LocalCancelled: true}
			for range 2 {
				got, err := worker.cancel(ctx, request, "user-a")
				if err != nil || got != want {
					t.Fatal("unsent cancellation did not prevent work", err, got)
				}
			}
			if got, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "replacement"}); err != nil || got.Claimed {
				t.Fatal("cancelled work was leased", err)
			}
			var erased bool
			var attempts int
			if err := pool.QueryRow(ctx, `SELECT state='cancelled' AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL,(SELECT count(*) FROM identity.delivery_attempt_history) FROM identity.delivery_intents`).Scan(&erased, &attempts); err != nil || !erased || attempts != 0 {
				t.Fatal("cancellation did not atomically erase unsent custody", err)
			}
		})
	}
}

// A protected cancellation must share its owner's transaction: a later audit
// or lifecycle failure must restore custody, scheduling and status together.
func TestCancellationBorrowedTransactionRollsBackEveryEffect(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsent", true: "submitted"}[submitted], func(t *testing.T) {
			ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
			if _, err := pool.Exec(ctx, stateSchemaSQL); err != nil {
				t.Fatal(err)
			}
			if !submitted {
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state='retry-wait'; UPDATE identity.delivery_processing SET next_attempt_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL`); err != nil {
					t.Fatal(err)
				}
			}
			q := delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: fence.Generation, Reason: "workflow-cancel"}
			var beforeState, beforeVersion string
			if err := pool.QueryRow(ctx, `SELECT state,status_version::text FROM identity.delivery_intents`).Scan(&beforeState, &beforeVersion); err != nil {
				t.Fatal(err)
			}
			for _, commit := range []bool{false, true} {
				tx := beginIntentTestTransaction(t, ctx, pool)
				got, err := worker.cancelIn(ctx, cancellationSQL{
					scan: func(ctx context.Context, sql string, args []any, dest ...any) error {
						return tx.QueryRow(ctx, sql, args...).Scan(dest...)
					},
					exec: func(ctx context.Context, sql string, args ...any) error {
						_, err := tx.Exec(ctx, sql, args...)
						return err
					},
				}, q, "user-a", true)
				want := delivery.StateCancelled
				if submitted {
					want = delivery.StateOutcomeUnknown
				}
				if err != nil || got.State != want || !got.LocalCancelled {
					t.Fatal("borrowed cancellation failed", err)
				}
				var applied bool
				if err := tx.QueryRow(ctx, `SELECT p.cancel_requested AND p.next_attempt_at IS NULL AND (i.state='outcome-unknown' OR (i.state='cancelled' AND i.ciphertext IS NULL)) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&applied); err != nil || !applied {
					t.Fatal("effects not staged in owner transaction", err)
				}
				if commit {
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					var state, version string
					var restored bool
					if err := pool.QueryRow(ctx, `SELECT i.state,i.status_version::text,i.ciphertext IS NOT NULL AND NOT p.cancel_requested AND (p.next_attempt_at IS NOT NULL OR p.lease_owner IS NOT NULL) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&state, &version, &restored); err != nil || state != beforeState || version != beforeVersion || !restored {
						t.Fatal("owner rollback lost custody or schedule", err)
					}
				}
			}
			if claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || claim.Claimed {
				t.Fatal("committed stop allowed resubmission", err)
			}
		})
	}
}

func TestDurableCancellationPendingPreservesAttributableCompletion(t *testing.T) {
	for _, evidence := range []delivery.DeliveryState{delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateTransientFailure, delivery.StateOutcomeUnknown} {
		t.Run(fmt.Sprint(evidence), func(t *testing.T) {
			ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
			request := delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: fence.Generation, Reason: "workflow-cancel"}
			want := delivery.CancelResult{State: delivery.StateOutcomeUnknown, LocalCancelled: true}
			for range 2 {
				got, err := worker.cancel(ctx, request, "user-a")
				if err != nil || got != want {
					t.Fatal("pending cancellation fabricated remote outcome", err, got)
				}
			}
			if _, err := worker.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
				t.Fatal("pending cancellation renewed invocation", err)
			}
			if got, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || got.Claimed {
				t.Fatal("pending cancellation allowed resend", err)
			}
			var pending, retained, live bool
			if err := pool.QueryRow(ctx, `SELECT i.state='outcome-unknown' AND p.cancel_requested AND p.next_attempt_at IS NULL,i.ciphertext IS NOT NULL,p.lease_owner IS NOT NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&pending, &retained, &live); err != nil || !pending || !retained || !live {
				t.Fatal("pending cancellation destroyed original invocation evidence", err)
			}
			completion := fence.completion()
			completion.Invoked = true
			completion.Result = delivery.DeliveryResult{State: evidence, ObservedAt: time.Now().UTC()}
			wantState := evidence
			if evidence == delivery.StateTransientFailure {
				wantState = delivery.StateCancelled
			}
			got, err := worker.Complete(ctx, completion)
			if err != nil || got.State != wantState || got.Commit != delivery.CommitCommitted {
				t.Fatal("cancellation lost live provider evidence", err, got)
			}
			if replay, err := worker.Complete(ctx, completion); err != nil || replay != got {
				t.Fatal("cancelled invocation completion did not replay", err)
			}
		})
	}
}

func TestDurableCancellationRejectsForeignAndStaleFences(t *testing.T) {
	ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
	q := delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: 1, Reason: "workflow-cancel"}
	for _, bad := range []delivery.CancelRequest{{}, {TenantID: q.TenantID, IntentID: "invalid", Reason: q.Reason}, {TenantID: q.TenantID, IntentID: delivery.IntentID(strings.Repeat("A", 64)), Reason: q.Reason}, {TenantID: q.TenantID, IntentID: q.IntentID, Reason: ""}, {TenantID: q.TenantID, IntentID: q.IntentID, Reason: strings.Repeat("x", 257)}, {TenantID: q.TenantID, IntentID: q.IntentID, Reason: string([]byte{255})}} {
		if result, err := worker.cancel(ctx, bad, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) || result != (delivery.CancelResult{}) {
			t.Fatal("invalid cancellation input accepted", err)
		}
	}
	for _, invalid := range []*attemptStore{nil, {}} {
		if _, err := invalid.cancel(ctx, q, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("invalid cancellation store accepted", err)
		}
	}
	if _, err := worker.cancel(nil, q, "user-a"); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil cancellation context accepted", err)
	}
	for _, subject := range []string{"foreign-user", ""} {
		_, err := worker.cancel(ctx, q, subject)
		if subject == "" && !errors.Is(err, delivery.ErrInvalidInput) || subject != "" && !errors.Is(err, delivery.ErrNotFound) {
			t.Fatal("foreign cancellation accepted", err)
		}
	}
	for _, generation := range []uint32{0, 2} {
		bad := q
		bad.ExpectedGeneration = generation
		if _, err := worker.cancel(ctx, bad, "user-a"); !errors.Is(err, delivery.ErrConflict) {
			t.Fatal("stale cancellation accepted", err)
		}
	}
	bad := q
	bad.TenantID = "foreign-tenant"
	if _, err := worker.cancel(ctx, bad, "user-a"); !errors.Is(err, delivery.ErrNotFound) {
		t.Fatal("cross-tenant cancellation accepted", err)
	}
	other := *worker
	other.deployment = "foreign-deployment"
	if _, err := other.cancel(ctx, q, "user-a"); !errors.Is(err, delivery.ErrNotFound) {
		t.Fatal("cross-deployment cancellation accepted", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := worker.cancel(cancelled, q, "user-a"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller changed intent", err)
	}
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT i.state='submitted' AND NOT p.cancel_requested FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("denied cancellation changed durable state", err)
	}
}

func TestDurableCancellationRetryStopsScheduleAndPendingAcceptanceStaysUnknown(t *testing.T) {
	for _, prior := range []delivery.DeliveryState{delivery.StateTransientFailure, delivery.StateAccepted, delivery.StateOutcomeUnknown} {
		t.Run(fmt.Sprint(prior), func(t *testing.T) {
			ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
			complete := fence.completion()
			complete.Invoked = true
			complete.Result = delivery.DeliveryResult{State: prior, ObservedAt: time.Now().UTC()}
			if _, err := worker.Complete(ctx, complete); err != nil {
				t.Fatal("prior completion", err)
			}
			request := delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: 1, Reason: "workflow-cancel"}
			want := delivery.CancelResult{State: delivery.StateOutcomeUnknown, LocalCancelled: true}
			if prior == delivery.StateTransientFailure {
				want.State = delivery.StateCancelled
			}
			for range 2 {
				if got, err := worker.cancel(ctx, request, "user-a"); err != nil || got != want {
					t.Fatal("prior outcome was misclassified", err, got)
				}
			}
			if got, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || got.Claimed {
				t.Fatal("cancelled retry/pending was claimed", err)
			}
			var stopped, erased bool
			var attempts int
			if err := pool.QueryRow(ctx, `SELECT p.cancel_requested AND p.next_attempt_at IS NULL AND p.lease_owner IS NULL,i.ciphertext IS NULL,(SELECT count(*) FROM identity.delivery_attempt_history) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&stopped, &erased, &attempts); err != nil || !stopped || erased != (prior == delivery.StateTransientFailure) || attempts != 1 {
				t.Fatal("cancellation damaged prior evidence or schedule", err)
			}
			// Acknowledged completion replay remains exact history, not authority
			// to invoke again or replace the later cancellation checkpoint.
			if _, err := worker.Complete(ctx, complete); err != nil {
				t.Fatal("prior completion replay lost", err)
			}
		})
	}
}

func TestDurableCancellationLostInvocationNeverCreatesAProviderOutcome(t *testing.T) {
	ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	q := delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: 1, Reason: "workflow-cancel"}
	if got, err := worker.cancel(ctx, q, "user-a"); err != nil || got != (delivery.CancelResult{State: delivery.StateOutcomeUnknown, LocalCancelled: true}) {
		t.Fatal("lost invocation was locally confirmed", err)
	}
	complete := fence.completion()
	complete.Invoked = true
	complete.Result = delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}
	if _, err := worker.Complete(ctx, complete); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("expired worker bypassed cancellation fence", err)
	}
	if got, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || got.Claimed {
		t.Fatal("lost cancelled invocation resent", err)
	}
	var unknown bool
	if err := pool.QueryRow(ctx, `SELECT i.state='outcome-unknown' AND i.ciphertext IS NOT NULL AND h.outcome IS NULL FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id)`).Scan(&unknown); err != nil || !unknown {
		t.Fatal("cancellation fabricated outcome evidence", err)
	}
}

func TestDurableCancellationRacesSuccessfulCompletion(t *testing.T) {
	ctx, pool, worker, _, fence := claimedLeaseFixture(t, time.Hour)
	start := make(chan struct{})
	var group sync.WaitGroup
	var cancelled delivery.CancelResult
	var cancelError, completeError error
	var completed delivery.CompleteResult
	group.Go(func() {
		<-start
		cancelled, cancelError = worker.cancel(ctx, delivery.CancelRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, ExpectedGeneration: 1, Reason: "workflow-cancel"}, "user-a")
	})
	group.Go(func() {
		<-start
		q := fence.completion()
		q.Invoked = true
		q.Result = delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}
		completed, completeError = worker.Complete(ctx, q)
	})
	close(start)
	group.Wait()
	if cancelError != nil || completeError != nil || completed.State != delivery.StateDelivered || cancelled.RemoteCancellationConfirmed || cancelled.State != delivery.StateDelivered && cancelled.State != delivery.StateOutcomeUnknown {
		t.Fatal("cancellation race lost confirmed outcome", cancelError, completeError)
	}
	var confirmed bool
	if err := pool.QueryRow(ctx, `SELECT i.state='confirmed' AND i.ciphertext IS NULL AND p.lease_owner IS NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&confirmed); err != nil || !confirmed {
		t.Fatal("cancellation overwrote provider success", err)
	}
}
