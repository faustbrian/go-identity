//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This is an old/new-binary historical receipt fixture, not a fake session
// issuer. It proves the real primary journal/query boundary; execution stays
// disabled until native feature phases are implemented.
func testFeatureObservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	c, _, _ := featurePlanFixture(t)
	var decisions int
	policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	reader, err := NewCoordinator(pool, c.registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "committed", "aborted", "mismatched lifecycle"} {
		t.Run(state, func(t *testing.T) {
			_, _, p := featurePlanFixture(t)
			spec := featureCodecSpec()
			spec.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			command := featureCodecCommand(t, spec)
			q, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encodeFeaturePlan(spec.Binding, claimFingerprint([32]byte{1}, q.canonical), p)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			d, err := lockCommandClaim(ctx, tx, q, c.keys)
			if err != nil || d != claimNew {
				t.Fatal("fixture claim", err)
			}
			owner := [16]byte{1}
			journal, err := reserveJournal(ctx, tx, q, d, owner, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
			if _, err = tx.Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, id, wire); err != nil {
				t.Fatal(err)
			}
			want := identity.CommitOutcomeInProgress
			if state != "pending" {
				want = identity.CommitOutcomeCommitted
				class := "committed"
				receipt := identity.CommandResult{Binding: spec.Binding, Outcome: want, AuditEventID: "historical-audit", Feature: &identity.FeatureReceipt{Operation: spec.Operation, AfterVersion: 1}}
				if state == "mismatched lifecycle" {
					receipt.Feature.BeforeVersion, receipt.Feature.AfterVersion = 1, 2
				}
				if state == "aborted" {
					want, class = identity.CommitOutcomeNotCommitted, "denied"
					receipt.Outcome, receipt.AuditEventID, receipt.Feature.AfterVersion = want, "", 0
				}
				if err = terminalizeJournal(ctx, tx, q, journal, owner, receipt, class); err != nil {
					t.Fatal(err)
				}
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			query, caller := queryInputs(spec.Binding)
			record, err := reader.QueryCommand(ctx, query, caller)
			var forbidden identity.ForbiddenError
			if state == "mismatched lifecycle" {
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) || record != (CommandRecord{}) {
					t.Fatal("inconsistent primary transition disclosed", err)
				}
			} else if state == "aborted" && !errors.As(err, &forbidden) || state != "aborted" && err != nil || record.Outcome != want || record.Feature == nil || *record.Feature != spec.Operation || record.Validate() != nil {
				t.Fatal("real feature receipt", err)
			}
			if state == "pending" {
				if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				recovered, err := reader.RecoverCommand(ctx, query, caller)
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) || recovered.Outcome != identity.CommitOutcomeInProgress || recovered.Feature == nil {
					t.Fatal("unsupported recovery fabricated terminal result", err)
				}
				var generation string
				if err = pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&generation); err != nil || generation != "1" {
					t.Fatal("observation took recovery ownership", err)
				}
			}
			wrong := query
			wrong.TenantID = "foreign"
			before := decisions
			record, err = reader.QueryCommand(ctx, wrong, callerForQuery(caller, wrong))
			if !errors.As(err, &forbidden) || record != (CommandRecord{}) || decisions != before+1 {
				t.Fatal("cross-tenant historical disclosure", err)
			}
		})
	}
}
