//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This independent SQL participant proves coordinator ownership and atomicity;
// it is not the production risk adapter or a CAPTCHA cryptographic oracle.
type sqlCaptchaUseReservation struct {
	captchaUseReservationProbe
	mode           string
	calls, rebinds int
	retained       CaptchaUseReservationWork
	counterDenied  bool
	counterCalls   int
}

func (*sqlCaptchaUseReservation) ValidateCommandCounters(identity.Command, CommandCounterPlan) error {
	return nil
}
func (p *sqlCaptchaUseReservation) ReserveCommandCounters(ctx context.Context, w CommandCounterWork) (CommandCounterDisposition, error) {
	p.counterCalls++
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_counter_fixture(command_id) VALUES($1)`, string(b.Command.CommandID)); err != nil {
		return 0, err
	}
	if p.counterDenied {
		return CommandCounterDenied, nil
	}
	return CommandCounterAllowed, nil
}

type captchaUseCounterAudit struct{ riskPassiveProbe }

func (p *captchaUseCounterAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_counter_audit(command_id,event_id,outcome) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), r.Record.ID(), string(r.Record.Outcome())); err != nil {
			return err
		}
	}
	return nil
}

func (p *sqlCaptchaUseReservation) ReserveCaptchaEvidence(ctx context.Context, w CaptchaUseReservationWork) error {
	p.calls++
	return p.reserve(ctx, w, false)
}
func (p *sqlCaptchaUseReservation) RebindCaptchaEvidence(ctx context.Context, w CaptchaUseReservationWork) error {
	p.rebinds++
	return p.reserve(ctx, w, true)
}
func (p *sqlCaptchaUseReservation) reserve(ctx context.Context, w CaptchaUseReservationWork, rebind bool) error {
	p.retained = w
	b, err := w.Binding(p)
	if err != nil || (b.PreviousGeneration != 0) != rebind {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlCaptchaUseReservation{}); err == nil {
		return invalidWork()
	}
	command, err := w.NativeCommand(p)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b.Command {
		return invalidWork()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || now.Before(b.Plan.CheckedAt) {
		return invalidWork()
	}
	var n int64
	if rebind {
		n, err = w.Exec(ctx, `UPDATE identity.captcha_use_fixture SET generation=$5::numeric WHERE tenant_id=$1 AND digest=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND generation=$6::numeric AND expiry=$7 AND expiry>clock_timestamp()`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10), b.Plan.ExpiresAt)
	} else {
		n, err = w.Exec(ctx, `UPDATE identity.captcha_use_fixture SET state='reserved',command_id=$3,fingerprint=$4,generation=$5::numeric WHERE tenant_id=$1 AND digest=$2 AND state='issued' AND expiry=$6 AND expiry>clock_timestamp()`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	switch p.mode {
	case "error":
		return errors.New("private captcha diagnostic")
	case "panic":
		panic("private captcha diagnostic")
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	}
	return nil
}

func testCaptchaUseReservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.captcha_use_fixture(tenant_id text NOT NULL,digest bytea NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric,expiry timestamptz NOT NULL,PRIMARY KEY(tenant_id,digest))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.captcha_counter_fixture(command_id text PRIMARY KEY); CREATE TABLE identity.captcha_counter_audit(command_id text NOT NULL,event_id text PRIMARY KEY,outcome text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	setup := func(t *testing.T, owner *sqlCaptchaUseReservation) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan) {
		t.Helper()
		c, command, plan := featurePlanFixture(t)
		s, _ := command.Feature()
		s.Binding.CommandID, _ = identity.NewCommandID()
		s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-private-value"}}}
		command = featureCodecCommand(t, s)
		feature := &featureExecutionPhase{}
		registry, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{plan.Contributors[0]}}, &captchaUseCounterAudit{riskPassiveProbe{registryContributor{plan.Contributors[1]}}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, feature, owner})
		if err != nil {
			t.Fatal(err)
		}
		c, err = NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if err != nil {
			t.Fatal(err)
		}
		plan.Contributors = registry.Descriptors()
		plan.SubjectType = "session"
		plan.Audits[0].RetentionClass = "protected"
		plan.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, "session", s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
		_, custody := captchaUsePlanFixture(t)
		plan.CaptchaEvidence = custody.CaptchaEvidence
		now := time.Now().UTC().Truncate(time.Microsecond)
		plan.CaptchaEvidence.IssuedAt, plan.CaptchaEvidence.CheckedAt, plan.CaptchaEvidence.ExpiresAt = now.Add(-time.Second), now, now.Add(time.Minute)
		plan.CaptchaEvidence.EvidenceDigest = sha256.Sum256([]byte(s.Binding.CommandID))
		plan, err = c.PrepareCommandPlan(s.Binding, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.captcha_use_fixture(tenant_id,digest,state,expiry) VALUES($1,$2,'issued',$3)`, string(s.Binding.TenantID), plan.CaptchaEvidence.EvidenceDigest[:], plan.CaptchaEvidence.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return c, s.Binding, command, plan
	}
	t.Run("combined counter denial", func(t *testing.T) {
		p := &sqlCaptchaUseReservation{counterDenied: true}
		c, b, command, plan := setup(t, p)
		plan.CommandCounters = &CommandCounterPlan{PolicyVersion: plan.CaptchaEvidence.PolicyVersion, Fingerprint: [32]byte{1}}
		plan, err := c.PrepareCommandPlan(b, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		r, result, err := c.ReserveCommand(ctx, b, command, plan)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || r.state != nil || result.Outcome != identity.CommitOutcomeNotCommitted || p.calls != 0 {
			t.Fatal("combined denial did not preserve terminal result", err, result.Outcome, p.calls)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var commandState, evidenceState string
		var charges, audits int
		if err := pool.Raw().QueryRow(ctx, `SELECT c.state,e.state,(SELECT count(*) FROM identity.captcha_counter_fixture WHERE command_id=$3),(SELECT count(*) FROM identity.captcha_counter_audit WHERE command_id=$3 AND outcome=$4) FROM identity.commands c CROSS JOIN identity.captcha_use_fixture e WHERE c.command_id=$1 AND e.digest=$2`, raw, plan.CaptchaEvidence.EvidenceDigest[:], string(b.CommandID), string(audit.OutcomeDenied)).Scan(&commandState, &evidenceState, &charges, &audits); err != nil || commandState != "aborted" || evidenceState != "issued" || charges != 1 || audits != 1 {
			t.Fatal("denial charge/audit/receipt not durable", err, commandState, evidenceState, charges, audits)
		}
		r, replay, err := c.ReserveCommand(ctx, b, command, plan)
		if err != nil || r.state != nil || replay.Outcome != identity.CommitOutcomeNotCommitted || p.counterCalls != 1 || p.calls != 0 {
			t.Fatal("terminal denial replay recharged or reserved evidence", err, p.counterCalls, p.calls)
		}
	})
	for _, mode := range []string{"allow", "error", "panic", "rows", "poison"} {
		t.Run(mode, func(t *testing.T) {
			p := &sqlCaptchaUseReservation{mode: mode}
			c, b, command, plan := setup(t, p)
			r, result, err := c.ReserveCommand(ctx, b, command, plan)
			var state, generation string
			var count int
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if e := pool.Raw().QueryRow(ctx, `SELECT state,COALESCE(generation::text,''),(SELECT count(*) FROM identity.commands WHERE command_id=$3) FROM identity.captcha_use_fixture WHERE tenant_id=$1 AND digest=$2`, string(b.TenantID), plan.CaptchaEvidence.EvidenceDigest[:], raw).Scan(&state, &generation, &count); e != nil {
				t.Fatal(e)
			}
			if mode != "allow" {
				if err == nil || r.state != nil || result != (identity.CommandResult{}) || state != "issued" || count != 0 || strings.Contains(err.Error(), "private") {
					t.Fatal("failed native prefix escaped rollback", err, state, count)
				}
				return
			}
			if err != nil || r.state == nil || result.Outcome != identity.CommitOutcomeInProgress || state != "reserved" || generation != "1" || count != 1 {
				t.Fatal("command/evidence not atomically reserved", err, state, generation, count)
			}
			if _, err := p.retained.Binding(p); err == nil {
				t.Fatal("returned handle revived")
			}
			if _, err := p.retained.NativeCommand(p); err == nil {
				t.Fatal("returned handle disclosed native input")
			}
			if _, err := p.retained.Exec(ctx, "SELECT 1"); err == nil {
				t.Fatal("returned handle executed SQL")
			}
			if _, err := c.Begin(ctx, r); err == nil || r.state.started.Load() {
				t.Fatal("reservation enabled unfinished consumption")
			}
			r2, observed, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil || r2.state != nil || observed.Outcome != identity.CommitOutcomeInProgress || p.calls != 1 {
				t.Fatal("live replay repeated reservation", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			r2, _, err = c.ReserveCommand(ctx, b, command, plan)
			if err != nil || r2.state == nil || r2.state.journal.generation != 2 || p.rebinds != 1 {
				t.Fatal("exact takeover failed", err)
			}
			var commandGeneration string
			if err := pool.Raw().QueryRow(ctx, `SELECT e.generation::text,c.generation::text FROM identity.captcha_use_fixture e JOIN identity.commands c ON c.command_id=$3 WHERE e.tenant_id=$1 AND e.digest=$2`, string(b.TenantID), plan.CaptchaEvidence.EvidenceDigest[:], raw).Scan(&generation, &commandGeneration); err != nil || generation != "2" || commandGeneration != "2" {
				t.Fatal("partial ownership takeover", err, generation, commandGeneration)
			}
			// A third takeover cannot replace a divergent participant generation.
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.captcha_use_fixture SET generation=1 WHERE digest=$1`, plan.CaptchaEvidence.EvidenceDigest[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			r3, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err == nil || r3.state != nil {
				t.Fatal("mismatched predecessor transferred")
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&commandGeneration); err != nil || commandGeneration != "2" {
				t.Fatal("failed takeover advanced command prefix", err)
			}
			_, err = c.recoverCommandReceipt(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, OperationID: b.OperationID})
			if err == nil {
				t.Fatal("unfinished release protocol terminalized ownership")
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT state,generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&state, &commandGeneration); err != nil || state != "pending" || commandGeneration != "2" {
				t.Fatal("recovery changed unresolved custody", err, state, commandGeneration)
			}
		})
	}
}
