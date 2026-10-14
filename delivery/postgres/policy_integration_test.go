//go:build integration

package postgres

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestRetainedDeliveryPolicyRestartRotationAndConflict(t *testing.T) {
	ctx, pool := intentDatabase(t)
	history, err := (MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history[len(history)-2:] {
		if _, err := pool.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("policy migration", err)
		}
	}
	s, prepared := preparedFixture(t, false)
	config := delivery.DefaultConfig()
	policies, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: config, 10: delivery.DefaultConfig()}, time.Second)
	if err != nil {
		t.Fatal("first policy registration", err)
	}
	// Caller mutation cannot change a retained policy or its future decisions.
	config.BackoffCeilings[1] = 2 * time.Second
	original, err := policies.worker(1, s.codec)
	if err != nil || original.policyDigest != attemptPolicyDigest(delivery.DefaultConfig(), time.Second) {
		t.Fatal("retained config was not snapshotted", err)
	}
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{prepared}, tx); err != nil || tx.Commit(ctx) != nil {
		t.Fatal("intent admission", err)
	}
	// QA4: two provider versions may share a retry policy. A worker's transport
	// profile must still not acquire another provider's frozen effect.
	otherProvider, err := policies.worker(1, s.codec)
	if err != nil {
		t.Fatal(err)
	}
	otherProvider.providerVersion = 2
	if claim, err := otherProvider.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker"}); err != nil || claim.Claimed {
		t.Fatal("other provider sharing policy acquired effect", err)
	}
	claim, err := original.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker"})
	if err != nil || !claim.Claimed {
		t.Fatal("original worker claim", err)
	}
	if _, err := otherProvider.Complete(ctx, delivery.CompleteRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, WorkerID: "worker", Generation: 1}); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("other provider sharing policy completed effect", err)
	}
	changed := delivery.DefaultConfig()
	changed.Attempts = 1
	changed.BackoffCeilings = []time.Duration{0}
	if _, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig(), 2: changed, 10: changed}, time.Second); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed installed policy accepted", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_policy_profiles`).Scan(&count); err != nil || count != 2 {
		t.Fatal("conflict retained a partial configuration", err, count)
	}
	restarted, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig(), 2: changed}, time.Second)
	if err != nil {
		t.Fatal("retained policy rotation", err)
	}
	old, err := restarted.worker(1, s.codec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := old.Complete(ctx, delivery.CompleteRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, WorkerID: "worker", Generation: 1})
	if err != nil || result.State != delivery.StateRetryWait {
		t.Fatal("rotation reinterpreted original retry policy", err, result.State)
	}
	current, err := restarted.worker(2, s.codec)
	if err != nil || current.attempts != 1 || old.attempts != 5 {
		t.Fatal("policy selection lost version", err)
	}
	if _, err := current.Complete(ctx, delivery.CompleteRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, WorkerID: "worker", Generation: 1}); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("wrong retained policy replayed completion", err)
	}
	if _, err := restarted.worker(3, s.codec); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing retained policy selected a default", err)
	}
	for _, sql := range []string{
		`UPDATE identity.delivery_policy_profiles SET config_digest=decode(repeat('aa',32),'hex')`,
		`DELETE FROM identity.delivery_policy_profiles`,
		`TRUNCATE identity.delivery_policy_profiles`,
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatal("retained policy history changed")
		}
	}
	// Deployment namespaces retain independent versions rather than overwriting.
	if _, err := newRetainedPolicies(ctx, pool, "other", map[uint64]delivery.Config{1: changed}, time.Second); err != nil {
		t.Fatal("independent deployment denied", err)
	}
}

func TestRetainedDeliveryPolicyConcurrentRegistrationAndClaimIsolation(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL+policySchemaSQL); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			if _, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig(), 2: delivery.DefaultConfig()}, time.Second); err != nil {
				t.Error("concurrent identical registration", err)
			}
		})
	}
	close(start)
	wg.Wait()
	s, prepared := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{prepared}, tx); err != nil || tx.Commit(ctx) != nil {
		t.Fatal("intent admission", err)
	}
	profiles, err := newRetainedPolicies(ctx, pool, "test", map[uint64]delivery.Config{1: delivery.DefaultConfig(), 2: delivery.DefaultConfig()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other, err := profiles.worker(2, s.codec)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := other.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "other"}); err != nil || result.Claimed {
		t.Fatal("wrong policy head must not block an independent worker", err)
	}
	original, err := profiles.worker(1, s.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := original.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker"})
	if err != nil || !claim.Claimed {
		t.Fatal("wrong-version selection changed original claim", err)
	}
	fence := leaseFence{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, WorkerID: "worker", Generation: 1}
	if _, err := other.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("wrong version renewed original lease", err)
	}
	if _, err := original.Renew(ctx, fence); err != nil {
		t.Fatal("original version could not renew", err)
	}
}
