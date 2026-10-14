//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This SQL owner proves coordinator atomicity, not production risk policy or
// phone recovery. The production adapter must authenticate native inputs too.
type sqlRiskExecution struct {
	sqlRiskReservation
	mode              string
	checks, finalizes int
	retainedApply     RiskApplyWork
	retainedFinalize  RiskFinalizeWork
}

func (p *sqlRiskExecution) ReleaseRiskEvidence(ctx context.Context, w RiskReleaseWork) error {
	b, e := w.Binding(p)
	if e != nil {
		return e
	}
	n, e := w.Exec(ctx, `UPDATE identity.risk_reservation_fixture SET state='released',generation=$7::numeric WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric`, b.Plan.Tenant, b.Plan.Purpose, b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *sqlRiskExecution) ValidateRiskEvidenceCommand(c identity.Command, plan RiskEvidencePlan) error {
	s, ok := c.Feature()
	if !ok || string(s.Binding.CommandID) != plan.ConsumerCommandID || s.Binding.OperationID != plan.RecoveryOperation {
		return invalidPlan()
	}
	return nil
}

func (p *sqlRiskExecution) CheckRiskEvidence(ctx context.Context, w RiskApplyWork) error {
	p.checks++
	p.retainedApply = w
	b, e := w.Binding(p)
	if e != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, e := w.Binding(&sqlRiskExecution{}); e == nil {
		return invalidWork()
	}
	c, e := w.NativeCommand(p)
	if e != nil || p.ValidateRiskEvidenceCommand(c, b.Plan) != nil {
		return invalidWork()
	}
	rows, e := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.risk_reservation_fixture WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7 AND intent=$8 AND proof=$9 AND expiry>clock_timestamp())`, b.Plan.Tenant, b.Plan.Purpose, b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt, b.Plan.IntentDigest[:], b.Plan.ProofDigest[:])
	if e != nil {
		return e
	}
	var exact bool
	matched := rows.Next() && rows.Scan(&exact) == nil && exact
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched {
		return identity.ForbiddenError{}
	}
	switch p.mode {
	case "deny-apply":
		return identity.ForbiddenError{}
	case "deny-final":
		if p.checks == 2 {
			return identity.ForbiddenError{}
		}
	case "panic":
		panic("private risk diagnostic")
	case "rows":
		_, e = w.Query(ctx, "SELECT 1")
		return e
	case "poison":
		_, _ = w.Query(ctx, "SELECT 1/0")
	}
	_, e = w.DatabaseTime(ctx)
	return e
}

func (p *sqlRiskExecution) FinalizeRiskEvidence(ctx context.Context, w RiskFinalizeWork) error {
	p.finalizes++
	p.retainedFinalize = w
	b, e := w.Binding(p)
	if e != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, e := p.retainedApply.Binding(p); e == nil {
		return invalidWork()
	}
	if _, e := w.Binding(&sqlRiskExecution{}); e == nil {
		return invalidWork()
	}
	c, e := w.NativeCommand(p)
	if e != nil || p.ValidateRiskEvidenceCommand(c, b.Plan) != nil {
		return invalidWork()
	}
	if _, e := w.DatabaseTime(ctx); e != nil {
		return e
	}
	n, e := w.Exec(ctx, `UPDATE identity.risk_reservation_fixture SET state='finalized' WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7 AND expiry>clock_timestamp()`, b.Plan.Tenant, b.Plan.Purpose, b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	switch p.mode {
	case "finalize-error":
		return identity.UnavailableError{}
	case "finalize-panic":
		panic("private finalize diagnostic")
	case "finalize-rows":
		_, e = w.Query(ctx, "SELECT 1")
		return e
	case "finalize-poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	}
	return nil
}

type riskDomainPhone struct {
	phoneReservationProbe
	delay bool
	calls int
}

func (p *riskDomainPhone) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	_, f, _, e := w.FeatureScope(p)
	if e != nil {
		return identity.FeatureReceipt{}, e
	}
	s, _ := command.Feature()
	if _, e = w.Exec(ctx, `INSERT INTO identity.risk_domain_fixture(command_id) VALUES($1)`, string(s.Binding.CommandID)); e != nil {
		return identity.FeatureReceipt{}, e
	}
	if p.delay {
		p.calls++
		if _, e = w.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, w.state.execution.reservation.plan.risk.ExpiresAt); e != nil {
			return identity.FeatureReceipt{}, e
		}
	}
	return identity.FeatureReceipt{Operation: f.Operation, AfterVersion: 1}, nil
}

type riskDomainAudit struct{ featureExecutionAuditPhase }

func (*riskDomainAudit) PersistAudits(ctx context.Context, w Work) error {
	records, e := w.StagedAudits()
	if e != nil {
		return e
	}
	for _, record := range records {
		if record.Feature != (&phoneReservationProbe{}).FeatureOperations()[0] || record.SubjectType != "phone" {
			return invalidAudit()
		}
		if _, e := w.Exec(ctx, `INSERT INTO identity.risk_domain_audits(event_id,command_id,event_index,retention_class) VALUES($1,$2,$3,$4)`, record.Record.ID(), string(w.state.binding.CommandID), int64(record.Plan.EventIndex), record.Record.Attributes()["retention.class"]); e != nil {
			return e
		}
	}
	return nil
}
func (*riskDomainAudit) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, e := w.AuditPlans(); e != nil {
		return RecoveryUnknown, e
	}
	return recoveryTestEvidence(ctx, w, "identity.risk_domain_audits")
}

type riskDomainLifecycle struct{ recoveryLifecyclePhase }

func (*riskDomainLifecycle) PersistLifecycle(ctx context.Context, w Work) error {
	records, e := w.StagedLifecycle()
	if e != nil {
		return e
	}
	for _, record := range records {
		if _, e := w.Exec(ctx, `INSERT INTO identity.risk_domain_outbox(event_id,command_id) VALUES($1,$2)`, record.ID, string(record.CommandID)); e != nil {
			return e
		}
	}
	return nil
}
func (*riskDomainLifecycle) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, e := w.LifecyclePlan(); e != nil {
		return RecoveryUnknown, e
	}
	return recoveryTestEvidence(ctx, w, "identity.risk_domain_outbox")
}

func testRiskDomain(t *testing.T, ctx context.Context, pool *database.Pool, setup func(*testing.T, Contributor) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan), expire func(*testing.T, identity.CommandBinding)) {
	if _, e := pool.Raw().Exec(ctx, `CREATE TABLE identity.risk_domain_fixture(command_id text PRIMARY KEY); CREATE TABLE identity.risk_domain_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index)); CREATE TABLE identity.risk_domain_outbox(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"allow", "takeover", "deny-apply", "deny-final", "expiry", "panic", "rows", "poison", "finalize-error", "finalize-panic", "finalize-rows", "finalize-poison"} {
		t.Run(mode, func(t *testing.T) {
			p := &sqlRiskExecution{mode: mode}
			p.registered = p
			c, b, command, plan := setup(t, p)
			phone := &riskDomainPhone{delay: mode == "expiry"}
			var entries []Contributor
			for _, entry := range c.registry.state.entries {
				switch entry.descriptor.Owner {
				case "identity/phone/postgres":
					entries = append(entries, phone)
				case "audit/postgres":
					entries = append(entries, &riskDomainAudit{})
				case "outbox/postgres":
					entries = append(entries, &riskDomainLifecycle{})
				default:
					entries = append(entries, entry.contributor)
				}
			}
			var e error
			c.registry, e = NewContributorRegistry(entries)
			if e != nil {
				t.Fatal(e)
			}
			plan.Contributors = c.registry.Descriptors()
			if mode == "expiry" {
				plan.RiskEvidence.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(500 * time.Millisecond)
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.risk_reservation_fixture SET expiry=$2 WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:], plan.RiskEvidence.ExpiresAt); e != nil {
					t.Fatal(e)
				}
			}
			plan, e = c.PrepareCommandPlan(b, command, plan)
			if e != nil {
				t.Fatal(e)
			}
			r, _, e := c.ReserveCommand(ctx, b, command, plan)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "takeover" {
				expire(t, b)
				r, _, e = c.ReserveCommand(ctx, b, command, plan)
				if e != nil || r.state.journal.generation != 2 {
					t.Fatal("takeover", e)
				}
			}
			w, e := c.Begin(ctx, r)
			if e != nil {
				t.Fatal("complete native risk phases cannot enter domain", e)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, e := c.ApplyFeature(ctx, w, command)
			if e == nil {
				result, e = c.Commit(w, result)
			} else {
				result, e = c.Abort(w, e)
			}
			var state, commandState string
			var domain, audits, outbox int
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if e2 := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT state FROM identity.commands WHERE command_id=$2),(SELECT count(*) FROM identity.risk_domain_fixture WHERE command_id=$3),(SELECT count(*) FROM identity.risk_domain_audits WHERE command_id=$3),(SELECT count(*) FROM identity.risk_domain_outbox WHERE command_id=$3) FROM identity.risk_reservation_fixture WHERE digest=$1`, plan.RiskEvidence.EvidenceDigest[:], raw, string(b.CommandID)).Scan(&state, &commandState, &domain, &audits, &outbox); e2 != nil {
				t.Fatal(e2)
			}
			if mode == "allow" || mode == "takeover" {
				if e != nil || result.Outcome != identity.CommitOutcomeCommitted || state != "finalized" || commandState != "committed" || domain != 1 || outbox != 1 || p.checks != 2 || p.finalizes != 1 {
					t.Fatal("one-use commit incomplete", e, state, commandState, domain, outbox, p.checks, p.finalizes)
				}
				if replay, replayed, e := c.ReserveCommand(ctx, b, command, plan); e != nil || replay.state != nil || replayed.Outcome != identity.CommitOutcomeCommitted || p.checks != 2 || p.finalizes != 1 {
					t.Fatal("replay executed again", e)
				}
			} else {
				if e == nil || result.Outcome != identity.CommitOutcomeNotCommitted || state != "released" || commandState != "aborted" || domain != 0 || outbox != 0 {
					t.Fatal("failure retained prefix", e, result.Outcome, state, commandState, domain, outbox)
				}
			}
			if audits != 1 {
				t.Fatal("incorrect audit", audits)
			}
			if mode == "expiry" && (phone.calls != 1 || p.checks != 2 || p.finalizes != 0) {
				t.Fatal("expiry did not follow provisional mutation", phone.calls, p.checks, p.finalizes)
			}
			if _, e := p.retainedApply.Binding(p); e == nil {
				t.Fatal("retained apply authority")
			}
			if _, e := p.retainedFinalize.Binding(p); e == nil {
				t.Fatal("retained finalize authority")
			}
		})
	}
}
