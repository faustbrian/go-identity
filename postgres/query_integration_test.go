//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// Reuse actual production domain commit/abort fixtures, not manually fabricated
// terminal receipts. Query never invokes either contributor or reservation.
func testCommandQuery(t *testing.T, ctx context.Context, owner *Coordinator, binding identity.CommandBinding, expected identity.CommandResult) *Coordinator {
	t.Helper()
	var decisions, reads int
	allow := true
	policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		outcome := authorization.Deny
		if allow {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: dc.PolicyRevision}, nil
	})}
	c, err := NewCoordinator(owner.pool, owner.registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicyVersion = 99
	query, caller := queryInputs(binding)
	originalRead := c.commandRead
	c.commandRead = func(ctx context.Context, id identity.CommandID) (commandObservation, error) {
		reads++
		return originalRead(ctx, id)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
	snapshot := func() string {
		var json string
		if err := owner.pool.Raw().QueryRow(ctx, `SELECT json_build_array(row_to_json(j),row_to_json(c))::text FROM identity.commands j JOIN identity.identity_command_id_claims c USING(command_id) WHERE j.command_id=$1`, id).Scan(&json); err != nil {
			t.Fatal(err)
		}
		return json
	}
	before := snapshot()
	if expected.Outcome == identity.CommitOutcomeCommitted {
		if _, err := owner.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(binding.TenantID), string(binding.UserID)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		got, err := c.QueryCommand(ctx, query, caller)
		if expected.Outcome == identity.CommitOutcomeInProgress {
			if err != nil || got.Outcome != expected.Outcome || got.Binding != binding || got.RetryAfter <= 0 || got.Validate() != nil {
				t.Fatal("pending lease inferred terminal outcome", err)
			}
		} else if got != (CommandRecord{Binding: expected.Binding, Outcome: expected.Outcome}) {
			t.Fatal("query changed historical receipt", err)
		}
	}
	// Corrupt the primary observation at the read seam, not immutable storage
	// through a disabled trigger. Valid fixtures above exercise real SQL bytes.
	c.commandRead = func(ctx context.Context, id identity.CommandID) (commandObservation, error) {
		o, err := originalRead(ctx, id)
		o.plan = []byte{1}
		return o, err
	}
	corrupt, corruptErr := c.QueryCommand(ctx, query, caller)
	var unavailable identity.UnavailableError
	if !errors.As(corruptErr, &unavailable) || corrupt != (CommandRecord{}) {
		t.Fatal("corrupt primary plan disclosed historical outcome")
	}
	c.commandRead = func(ctx context.Context, id identity.CommandID) (commandObservation, error) {
		reads++
		return originalRead(ctx, id)
	}
	for _, change := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.CommandID, _ = identity.NewCommandID() },
		func(q *identity.RecoveryQuery) { q.TenantID = "wrong-tenant" },
		func(q *identity.RecoveryQuery) { q.UserID = "wrong-user" },
		func(q *identity.RecoveryQuery) { q.ActorID = "wrong-actor" },
		func(q *identity.RecoveryQuery) { q.ActorKind = authorization.SubjectAPIKey },
		func(q *identity.RecoveryQuery) { q.OperationID = "identity.user.suspend" },
		func(q *identity.RecoveryQuery) { q.RecordID = "wrong-record" },
		func(q *identity.RecoveryQuery) { q.LinkMode = identity.AccountLinkExplicit },
	} {
		changed := query
		change(&changed)
		oldReads, oldDecisions := reads, decisions
		got, err := c.QueryCommand(ctx, changed, callerForQuery(caller, changed))
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got != (CommandRecord{}) || reads != oldReads+1 || decisions != oldDecisions+1 {
			t.Fatal("missing/wrong-scope disclosed state or changed work shape")
		}
	}
	allow = false
	oldReads, oldDecisions := reads, decisions
	got, err := c.QueryCommand(ctx, query, caller)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || got != (CommandRecord{}) || reads != oldReads+1 || decisions != oldDecisions+1 {
		t.Fatal("denial disclosed result or bypassed primary work")
	}
	if snapshot() != before {
		t.Fatal("query changed durable state/ownership")
	}
	// Use an immutable, concurrent-safe policy rather than the instrumentation
	// closure for concurrent calls through the actual primary read implementation.
	c.commandRead = originalRead
	c.queryPolicy.Authorization = queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
	})
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			got, err := c.QueryCommand(ctx, query, caller)
			if got.Binding != binding || got.Outcome != expected.Outcome || got.Validate() != nil {
				failures <- errors.New("concurrent query lost coherent snapshot")
			} else if expected.Outcome == identity.CommitOutcomeCommitted && err != nil {
				failures <- err
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if snapshot() != before {
		t.Fatal("concurrent query mutated ownership")
	}
	// Earlier caller cancellation never becomes absence or rollback proof.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	got, err = c.QueryCommand(cancelled, query, caller)
	if !errors.Is(err, context.Canceled) || got != (CommandRecord{}) {
		t.Fatal("cancelled query fabricated a receipt")
	}
	return c
}
