//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// A real fenced transaction exercises Abort before domain admission is enabled.
// The SQL participant proves coordinator atomicity, not native risk authenticity
// or a complete phone workflow.
func testRiskOwnerAbort(t *testing.T, ctx context.Context, pool *database.Pool, setup func(*testing.T, Contributor) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan), expire func(*testing.T, identity.CommandBinding)) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS identity.risk_recovery_audits(command_id text PRIMARY KEY,event_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.risk_abort_domain(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"release", "takeover", "expired-evidence", "no-audit", "missing-phase", "wrong-generation", "wrong-fingerprint", "terminal", "missing", "audit-failure", "release-error", "release-panic", "release-rows", "release-poison", "expired-owner"} {
		t.Run(mode, func(t *testing.T) {
			participant := &sqlRiskRelease{failure: mode}
			participant.registered = participant
			var registered Contributor = participant
			if mode == "missing-phase" {
				registered = &sqlRiskReservation{}
			}
			c, b, command, plan := setup(t, registered)
			entries := []Contributor{}
			for _, entry := range c.registry.state.entries {
				if entry.descriptor.Owner == "audit/postgres" {
					entries = append(entries, &riskRecoveryAudit{fail: mode == "audit-failure"})
				} else {
					entries = append(entries, entry.contributor)
				}
			}
			var err error
			c.registry, err = NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired-evidence" {
				plan.RiskEvidence.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(200 * time.Millisecond)
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.risk_reservation_fixture SET expiry=$2 WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:], plan.RiskEvidence.ExpiresAt); err != nil {
					t.Fatal(err)
				}
				plan, err = c.PrepareCommandPlan(b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
			}
			r, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			generation := "1"
			if mode == "takeover" {
				expire(t, b)
				r, _, err = c.ReserveCommand(ctx, b, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				generation = "2"
			}
			mutations := map[string]string{
				"wrong-generation":  `UPDATE identity.risk_reservation_fixture SET generation=7 WHERE digest=$1`,
				"wrong-fingerprint": `UPDATE identity.risk_reservation_fixture SET fingerprint='\x01'::bytea WHERE digest=$1`,
				"terminal":          `UPDATE identity.risk_reservation_fixture SET state='finalized' WHERE digest=$1`,
				"missing":           `DELETE FROM identity.risk_reservation_fixture WHERE digest=$1`,
			}
			if sql := mutations[mode]; sql != "" {
				if _, err := pool.Raw().Exec(ctx, sql, plan.RiskEvidence.EvidenceDigest[:]); err != nil {
					t.Fatal(err)
				}
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			snapshot := func() string {
				var value string
				if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text||COALESCE((SELECT row_to_json(e)::text FROM identity.risk_reservation_fixture e WHERE digest=$2),'missing') FROM identity.commands c WHERE command_id=$1`, id, plan.RiskEvidence.EvidenceDigest[:]).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			tx, err := pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			fence, err := beginJournal(bounded, tx, r.state.request, c.keys, r.state.journal, r.state.owner)
			if err != nil {
				t.Fatal(err)
			}
			w, err := newWork(bounded, tx, b, r.state.request, fence)
			if err != nil {
				t.Fatal(err)
			}
			w.state.registry = c.registry.state
			w.state.execution = &domainExecution{coordinator: c, reservation: r.state, ctx: bounded, cancel: cancel}
			if err := r.state.plan.bindWork(w); err != nil {
				t.Fatal(err)
			}
			if err := configureKernelWork(bounded, w); err != nil {
				t.Fatal(err)
			}
			now, err := w.DatabaseTime(bounded)
			if err != nil {
				t.Fatal(err)
			}
			records, err := featureMutationAudits(bounded, r.state.plan, now, "dependency-failure")
			if err != nil {
				t.Fatal(err)
			}
			if mode != "no-audit" {
				w.state.execution.featureAbortAudits = map[string][]audit.Record{"dependency-failure": records}
			}
			if _, err := w.Exec(bounded, `INSERT INTO identity.risk_abort_domain(command_id) VALUES($1)`, string(b.CommandID)); err != nil {
				t.Fatal(err)
			}
			if mode == "expired-owner" {
				_, _ = w.Exec(bounded, `SELECT pg_sleep(1.05)`)
			} else if mode == "expired-evidence" {
				_, _ = w.Exec(bounded, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.01)`, plan.RiskEvidence.ExpiresAt)
			}
			result, _ := c.Abort(w, identity.UnavailableError{})
			var state, riskState, riskGeneration string
			var audits, domains int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM identity.risk_recovery_audits WHERE command_id=$2),(SELECT count(*) FROM identity.risk_abort_domain WHERE command_id=$2),COALESCE((SELECT state FROM identity.risk_reservation_fixture WHERE digest=$3),'missing'),COALESCE((SELECT generation::text FROM identity.risk_reservation_fixture WHERE digest=$3),'missing') FROM identity.commands WHERE command_id=$1`, id, string(b.CommandID), plan.RiskEvidence.EvidenceDigest[:]).Scan(&state, &audits, &domains, &riskState, &riskGeneration); err != nil {
				t.Fatal(err)
			}
			if domains != 0 {
				t.Fatal("domain prefix survived rollback")
			}
			if mode == "release" || mode == "takeover" || mode == "expired-evidence" {
				if result.Outcome != identity.CommitOutcomeNotCommitted || state != "aborted" || audits != 1 || riskState != "released" || riskGeneration != generation {
					t.Fatal("proved rollback did not atomically release live custody", result.Outcome, state, audits, riskState, riskGeneration)
				}
				if participant.retainedRelease.state == nil || participant.retainedRelease.state.work.state.generation != r.state.journal.generation {
					t.Fatal("release invented ownership")
				}
				if _, err := participant.retainedRelease.Binding(participant); err == nil {
					t.Fatal("retained release authority")
				}
				return
			}
			if result.Outcome != identity.CommitOutcomeUnknown || state != "pending" || audits != 0 || riskState == "released" || snapshot() != before {
				t.Fatal("failed terminal release left durable prefix", result.Outcome, state, audits, riskState)
			}
		})
	}
}
