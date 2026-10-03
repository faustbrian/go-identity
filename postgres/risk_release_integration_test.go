//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// A SQL seam proves coordinator release ownership, not native risk authenticity
// or phone domain completion. The official adapter remains a separate consumer.
type sqlRiskRelease struct {
	sqlRiskReservation
	status           RecoveryStatus
	failure          string
	retainedRelease  RiskReleaseWork
	retainedRecovery RecoveryWork
}

type riskRecoveryPhone struct {
	phoneReservationProbe
	status RecoveryStatus
}

func (p *riskRecoveryPhone) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return p.status, nil
}

type riskRecoveryPassive struct {
	riskPassiveProbe
	status RecoveryStatus
}

func (p *riskRecoveryPassive) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return p.status, nil
}

func (p *sqlRiskRelease) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	p.retainedRecovery = w
	b, err := w.RiskBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.risk_reservation_fixture WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7 AND intent=$8 AND proof=$9)`, b.Plan.Tenant, b.Plan.Purpose, b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), b.Plan.ExpiresAt, b.Plan.IntentDigest[:], b.Plan.ProofDigest[:])
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exact bool
	if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if !exact {
		return RecoveryUnknown, nil
	}
	return p.status, nil
}
func (p *sqlRiskRelease) ReleaseRiskEvidence(ctx context.Context, w RiskReleaseWork) error {
	p.retainedRelease = w
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&sqlRiskRelease{}); err == nil {
		return invalidWork()
	}
	if _, err := w.DatabaseTime(ctx); err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.risk_reservation_fixture SET state='released',generation=$7::numeric WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric`, b.Plan.Tenant, b.Plan.Purpose, b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	switch p.failure {
	case "release-error":
		return identity.UnavailableError{}
	case "release-panic":
		panic("private risk release")
	case "release-rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "release-poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
		return nil
	}
	return nil
}

type riskRecoveryAudit struct{ fail bool }

func (*riskRecoveryAudit) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "audit/postgres", ContractID: "audit.records", Version: 1}
}
func (p *riskRecoveryAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err = w.Exec(ctx, `INSERT INTO identity.risk_recovery_audits(command_id,event_id) VALUES($1,$2)`, string(b.CommandID), r.Record.ID()); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*riskRecoveryAudit) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.risk_recovery_audits")
}

func testRiskRelease(t *testing.T, ctx context.Context, pool *database.Pool, setup func(*testing.T, Contributor) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan), expire func(*testing.T, identity.CommandBinding)) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.risk_recovery_audits(command_id text PRIMARY KEY,event_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"release", "expired-release", "expired-unknown", "live", "unknown", "committed", "phone-unknown", "outbox-committed", "audit-committed", "wrong-generation", "wrong-fingerprint", "terminal", "missing", "audit-failure", "release-error", "release-panic", "release-rows", "release-poison"} {
		t.Run(mode, func(t *testing.T) {
			p := &sqlRiskRelease{status: RecoveryNotCommitted, failure: mode}
			p.registered = p
			c, b, command, plan := setup(t, p)
			a := &riskRecoveryAudit{fail: mode == "audit-failure"}
			entries := []Contributor{}
			for _, entry := range c.registry.state.entries {
				if entry.descriptor.Owner == "audit/postgres" {
					entries = append(entries, a)
				} else if mode == "phone-unknown" && entry.descriptor.Owner == "identity/phone/postgres" {
					entries = append(entries, &riskRecoveryPhone{status: RecoveryUnknown})
				} else if mode == "outbox-committed" && entry.descriptor.Owner == "outbox/postgres" {
					entries = append(entries, &riskRecoveryPassive{riskPassiveProbe: riskPassiveProbe{registryContributor{entry.descriptor}}, status: RecoveryCommitted})
				} else {
					entries = append(entries, entry.contributor)
				}
			}
			registry, err := NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			c.registry = registry
			if mode == "expired-release" || mode == "expired-unknown" {
				// Retain an authentic original interval in the frozen plan and row.
				// Waiting below observes real primary expiry, not altered custody.
				plan.RiskEvidence.ExpiresAt = plan.RiskEvidence.IssuedAt.Add(2 * time.Second)
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.risk_reservation_fixture SET expiry=$2 WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:], plan.RiskEvidence.ExpiresAt); e != nil {
					t.Fatal(e)
				}
			}
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = c.ReserveCommand(ctx, b, command, plan); err != nil {
				t.Fatal(err)
			}
			if mode != "live" {
				expire(t, b)
			}
			mutate := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "unknown", "expired-unknown":
				p.status = RecoveryUnknown
			case "audit-committed":
				mutate(`INSERT INTO identity.risk_recovery_audits(command_id,event_id) VALUES($1,'prior')`, string(b.CommandID))
			case "committed":
				p.status = RecoveryCommitted
			case "wrong-generation":
				mutate(`UPDATE identity.risk_reservation_fixture SET generation=7 WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:])
			case "wrong-fingerprint":
				mutate(`UPDATE identity.risk_reservation_fixture SET fingerprint=$2 WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:], []byte{1})
			case "terminal":
				mutate(`UPDATE identity.risk_reservation_fixture SET state='finalized' WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:])
			case "missing":
				mutate(`DELETE FROM identity.risk_reservation_fixture WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:])
			}
			if mode == "expired-release" || mode == "expired-unknown" {
				mutate(`SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, plan.RiskEvidence.ExpiresAt)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var before, after string
			snapshot := func() string {
				var row string
				if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, raw).Scan(&row); err != nil {
					t.Fatal(err)
				}
				return row
			}
			before = snapshot()
			nativeSnapshot := func() string {
				var row string
				if e := pool.Raw().QueryRow(ctx, `SELECT COALESCE((SELECT row_to_json(r)::text FROM identity.risk_reservation_fixture r WHERE digest=$1),'missing')`, plan.RiskEvidence.EvidenceDigest[:]).Scan(&row); e != nil {
					t.Fatal(e)
				}
				return row
			}
			nativeBefore := nativeSnapshot()
			q, caller := queryInputs(b)
			result, err := c.RecoverCommand(ctx, q, caller)
			after = snapshot()
			var auditCount int
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.risk_recovery_audits WHERE command_id=$1`, string(b.CommandID)).Scan(&auditCount); e != nil {
				t.Fatal(e)
			}
			if mode == "release" || mode == "expired-release" {
				if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted || auditCount != 1 {
					t.Fatal("proved noncommit did not release atomically", err, result.Outcome, auditCount)
				}
				var state, gen string
				if e := pool.Raw().QueryRow(ctx, `SELECT state,generation::text FROM identity.risk_reservation_fixture WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:]).Scan(&state, &gen); e != nil || state != "released" || gen != "2" {
					t.Fatal("native release absent", e, state, gen)
				}
				replay, e := c.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				if !errors.As(e, &unavailable) || !reflect.DeepEqual(replay, result) || snapshot() != after {
					t.Fatal("terminal recovery replay changed", e)
				}
			} else {
				wantAudits := 0
				if mode == "audit-committed" {
					wantAudits = 1
				}
				if before != after || nativeBefore != nativeSnapshot() || auditCount != wantAudits || result.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("unproved recovery changed authority", err, result.Outcome)
				}
				if mode == "live" && err != nil {
					t.Fatal("live observation failed", err)
				}
			}
			if _, err := p.retainedRelease.Binding(p); err == nil {
				t.Fatal("retained release authority")
			}
			if _, err := p.retainedRecovery.RiskBinding(p); err == nil {
				t.Fatal("retained recovery authority")
			}
		})
	}
}
