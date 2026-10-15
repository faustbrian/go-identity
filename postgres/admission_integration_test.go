//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func testCommandAdmissionPrimary(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	fixture, _, plan := featurePlanFixture(t)
	allowed := true
	policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Deny
		if allowed {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	c, err := NewCoordinator(pool, fixture.registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, AdmissionPolicy: policy, QueryPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicyVersion++ // The constructor must own its copied policy revision.
	spec := featureCodecSpec()
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	q, caller := queryInputs(spec.Binding)
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	snapshot := func() string {
		var value string
		if err := pool.Raw().QueryRow(ctx, `SELECT coalesce((SELECT json_build_array(row_to_json(c),row_to_json(j))::text FROM identity.identity_command_id_claims c LEFT JOIN identity.commands j USING(command_id) WHERE c.command_id=$1),'absent')`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if before != "absent" {
		t.Fatal("new command fixture already present")
	}
	for _, admissionOnly := range []bool{false, true} {
		p := *c.admissionPolicy
		config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
		if admissionOnly {
			config.AdmissionPolicy = &p
		} else {
			config.QueryPolicy = &p
		}
		isolated, err := NewCoordinator(pool, fixture.registry, config)
		if err != nil {
			t.Fatal("isolated observation constructor", err)
		}
		admission, admissionErr := isolated.ObserveCommandAdmission(ctx, q, caller)
		record, queryErr := isolated.QueryCommand(ctx, q, caller)
		if admissionOnly {
			if admissionErr != nil || !admission.Absent || queryErr == nil || record != (CommandRecord{}) {
				t.Fatal("admission-only constructor enabled query or disabled admission")
			}
		} else {
			var forbidden identity.ForbiddenError
			if admissionErr == nil || admission != (CommandAdmission{}) || !errors.As(queryErr, &forbidden) || record != (CommandRecord{}) {
				t.Fatal("query-only constructor enabled admission or disabled query")
			}
		}
		if snapshot() != before {
			t.Fatal("isolated observation composition mutated state")
		}
	}
	got, err := c.ObserveCommandAdmission(ctx, q, caller)
	if err != nil || !got.Absent || got.Validate() != nil || snapshot() != before {
		t.Fatal("primary absence unavailable or mutated state", err)
	}
	var forbidden identity.ForbiddenError
	if record, err := c.QueryCommand(ctx, q, caller); !errors.As(err, &forbidden) || record != (CommandRecord{}) {
		t.Fatal("ordinary query disclosed absence")
	}
	allowed = false
	if got, err := c.ObserveCommandAdmission(ctx, q, caller); !errors.As(err, &forbidden) || got != (CommandAdmission{}) || snapshot() != before {
		t.Fatal("denied primary absence disclosed or mutated")
	}
	allowed = true

	// A durable global claim without its journal is not an absent command. The
	// fixture deliberately constructs corrupt history; production never commits
	// this prefix. Admission must remain fail closed, without repairing it.
	command := featureCodecCommand(t, spec)
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if d, err := lockCommandClaim(ctx, tx, claim, c.keys); err != nil || d != claimNew {
		t.Fatal("claim fixture", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	var unavailable identity.UnavailableError
	if got, err := c.ObserveCommandAdmission(ctx, q, caller); !errors.As(err, &unavailable) || got != (CommandAdmission{}) || snapshot() != before {
		t.Fatal("orphan primary claim became absence/history", err)
	}

	tx, err = pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	journal, err := reserveJournal(ctx, tx, claim, claimNew, [16]byte{1}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeFeaturePlan(spec.Binding, claimFingerprint([32]byte{1}, claim.canonical), plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, id, wire); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	got, err = c.ObserveCommandAdmission(ctx, q, caller)
	if err != nil || got.Absent || got.Record.Outcome != identity.CommitOutcomeInProgress || got.Record.Validate() != nil || snapshot() != before {
		t.Fatal("pending primary history lost or mutated", err)
	}
	wrong := q
	wrong.TenantID = "foreign"
	if got, err := c.ObserveCommandAdmission(ctx, wrong, callerForQuery(caller, wrong)); !errors.As(err, &forbidden) || got != (CommandAdmission{}) || snapshot() != before {
		t.Fatal("wrong-scope primary history disclosed")
	}

	tx, err = pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	receipt := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: spec.Operation, AfterVersion: 1}}
	if err = terminalizeJournal(ctx, tx, claim, journal, [16]byte{1}, receipt, "committed"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	// Primary metadata observation is independent of present registry and keys;
	// this is not complete native command-intent or bearer replay verification.
	c.registry = nil
	c.keys = claimKeys{current: 2, retained: map[uint32][32]byte{2: {2}}}
	c.admissionPolicy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			got, err := c.ObserveCommandAdmission(ctx, q, caller)
			if err != nil || got.Absent || got.Record.Outcome != identity.CommitOutcomeCommitted || got.Record.Binding != spec.Binding || got.Record.Feature == nil || *got.Record.Feature != spec.Operation || got.Validate() != nil {
				failures <- errors.New("primary concurrent metadata lost")
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if snapshot() != before {
		t.Fatal("primary admission mutated terminal history")
	}
}
