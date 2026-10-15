//go:build integration

package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/delivery"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testMissingStartupSchema(t *testing.T, ctx context.Context, pool *database.Pool, config EnqueueConfig, crypto *envelope.Service, authorize authorization.Service, templates []delivery.Template) {
	t.Helper()
	counts := func() [2]int {
		t.Helper()
		var values [2]int
		if pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_policy_profiles`).Scan(&values[0]) != nil || pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_admission_namespaces`).Scan(&values[1]) != nil {
			t.Fatal("startup registration observation failed")
		}
		return values
	}
	before := counts()
	s, err := NewUninitializedEnqueueService(pool, config, crypto, authorize, templates)
	if err != nil {
		t.Fatal("pure selected-schema composition failed", err)
	}
	if err := s.Initialize(ctx); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing selected schema did not deny startup", err)
	}
	if after := counts(); after != before {
		t.Fatal("missing selected schema installed registration state")
	}
	if result, err := s.Enqueue(ctx, EnqueueCommandRequest{}); !errors.Is(err, delivery.ErrUnavailable) || result.Queued {
		t.Fatal("missing selected schema enabled the graph", err)
	}
}

func holdStartupPool(t *testing.T, ctx context.Context, pool *database.Pool) []*pgxpool.Conn {
	t.Helper()
	held := make([]*pgxpool.Conn, 0, pool.Raw().Config().MaxConns)
	for range pool.Raw().Config().MaxConns {
		connection, err := pool.Raw().Acquire(ctx)
		if err != nil {
			for _, previous := range held {
				previous.Release()
			}
			t.Fatal("task pool acquisition failed")
		}
		held = append(held, connection)
	}
	return held
}

func testDeferredStartup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, s *EnqueueService, config EnqueueConfig, templates []delivery.Template, request EnqueueCommandRequest) {
	t.Helper()
	var worker *Worker
	if config.StateTracking {
		scope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "startup-worker", Request: authorization.Request{Tenant: authorization.TenantID(request.Binding.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "startup-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "startup-worker"}}}
		var err error
		worker, err = s.NewWorker(WorkerConfig{Scope: scope, ProviderConfigVersion: 1}, attemptTestSender(func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
			t.Fatal("empty startup invoked sender")
			return delivery.DeliveryResult{}, delivery.ErrUnavailable
		}))
		if err != nil {
			t.Fatal("pure startup worker construction failed", err)
		}
		if result, err := worker.ProcessOne(ctx); !errors.Is(err, delivery.ErrUnavailable) || result.Claimed {
			t.Fatal("pre-start worker acquired authority", err)
		}
		if config.Cancellation && config.Receipts != nil && config.Reconciliation != nil {
			queue, err := s.NewQueue(WorkerConfig{Scope: scope, ProviderConfigVersion: 1})
			if err != nil {
				t.Fatal("pure Queue construction failed", err)
			}
			if result, err := queue.Claim(ctx, queue.worker.request); !errors.Is(err, delivery.ErrUnavailable) || result.Claimed {
				t.Fatal("pre-start Queue acquired a lease", err)
			}
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Initialize(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("startup lost cancellation", err)
	}
	// Observe a genuine blocked registration, not a synthetic ready flag.
	lock := beginIntentTestTransaction(t, ctx, pool)
	if _, err := lock.Exec(ctx, `LOCK TABLE identity.delivery_policy_profiles IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("startup contention fixture failed")
	}
	bounded, stop := context.WithTimeout(ctx, 40*time.Millisecond)
	err := s.Initialize(bounded)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("startup did not respect earlier caller deadline", err)
	}
	if result, err := s.Enqueue(ctx, request); !errors.Is(err, delivery.ErrUnavailable) || result.Queued {
		t.Fatal("failed startup enabled admission", err)
	}
	active, cancelActive := context.WithCancel(ctx)
	finished := make(chan error, 1)
	joined := false
	go func() { finished <- s.Initialize(active) }()
	t.Cleanup(func() {
		cancelActive()
		if !joined {
			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				t.Error("startup goroutine did not join after cancellation")
			}
		}
	})
	deadline := time.NewTimer(time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO identity.delivery_policy_profiles%')`).Scan(&waiting); err != nil {
			cancelActive()
			<-finished
			joined = true
			t.Fatal("startup contention observation failed")
		}
		if waiting {
			break
		}
		select {
		case <-deadline.C:
			cancelActive()
			<-finished
			joined = true
			t.Fatal("startup registration did not become blocked")
		case <-tick.C:
		}
	}
	copy := *s
	if err := copy.Initialize(ctx); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("concurrent startup queued or fabricated success", err)
	}
	if result, err := copy.Enqueue(ctx, request); !errors.Is(err, delivery.ErrUnavailable) || result.Queued {
		t.Fatal("concurrent startup published partial owners", err)
	}
	cancelActive()
	err = <-finished
	joined = true
	if !errors.Is(err, context.Canceled) {
		t.Fatal("blocked startup lost cancellation", err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal("startup contention cleanup failed")
	}

	// Mutating startup input cannot reinterpret its retained policy, key,
	// renderer, receipt or future reconciliation-coordinator configuration.
	original := config.Policies[1]
	original.BackoffCeilings = slices.Clone(original.BackoffCeilings)
	expected := attemptPolicyDigest(original, config.Timeout)
	changed := config.Policies[1]
	changed.SenderConcurrency++
	changed.BackoffCeilings[0] += time.Second
	config.Policies[1] = changed
	provider := config.Custody.ProviderProfiles[1]
	config.Custody.ProviderProfiles[1] = ProviderProfile{Provider: "changed-provider", PolicyVersion: 1}
	template := templates[0]
	templates[0].Body = "changed-body"
	key := config.Coordinator.RetainedFingerprintKeys[1]
	config.Coordinator.RetainedFingerprintKeys[1] = [32]byte{88}
	if err := s.Initialize(ctx); err != nil {
		t.Fatal("exact startup retry failed", err)
	}
	var installed []byte
	if pool.QueryRow(ctx, `SELECT config_digest FROM identity.delivery_policy_profiles WHERE deployment=$1 AND policy_version=1`, config.Custody.Deployment).Scan(&installed) != nil || !hmac.Equal(installed, expected[:]) {
		t.Fatal("startup reread mutated caller policy")
	}
	config.Policies[1], config.Custody.ProviderProfiles[1], templates[0], config.Coordinator.RetainedFingerprintKeys[1] = original, provider, template, key

	if worker != nil {
		// The exact pre-start handle observes successful publication; no new
		// worker or capacity owner is constructed to make this check pass.
		result, err := worker.ProcessOne(ctx)
		if err != nil || result.Claimed {
			t.Fatal("empty initialized worker fabricated a claim", err)
		}
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("startup closed the borrowed pool")
	}
}
