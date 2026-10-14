//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Independent SQL owner proves coordinator phases/atomicity, not provider truth
// or the production store's signed native checks.
type sqlCaptchaDomain struct {
	sqlCaptchaUseReservation
	behavior string
	checks   int
	apply    CaptchaApplyWork
	finalize CaptchaFinalizeWork
	release  CaptchaReleaseWork
}

func (p *sqlCaptchaDomain) CheckCaptchaEvidence(ctx context.Context, w CaptchaApplyWork) error {
	p.checks++
	p.apply = w
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlCaptchaDomain{}); err == nil {
		return invalidWork()
	}
	command, err := w.NativeCommand(p)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b.Command {
		return invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.captcha_use_fixture WHERE tenant_id=$1 AND digest=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND generation=$5::numeric AND expiry=$6 AND expiry>clock_timestamp())`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
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
	switch p.behavior {
	case "deny-apply":
		return identity.ForbiddenError{}
	case "release-error", "release-panic", "release-rows":
		return identity.ForbiddenError{}
	case "deny-final":
		if p.checks == 2 {
			return identity.ForbiddenError{}
		}
	case "panic":
		panic("private captcha check")
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Query(ctx, "SELECT 1/0")
	}
	_, err = w.DatabaseTime(ctx)
	return err
}

func (p *sqlCaptchaDomain) FinalizeCaptchaEvidence(ctx context.Context, w CaptchaFinalizeWork) error {
	p.finalize = w
	if _, err := p.apply.Binding(p); err == nil {
		return invalidWork()
	}
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlCaptchaDomain{}); err == nil {
		return invalidWork()
	}
	if _, err := w.NativeCommand(p); err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.captcha_use_fixture SET state='finalized' WHERE tenant_id=$1 AND digest=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND generation=$5::numeric AND expiry=$6 AND expiry>clock_timestamp()`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	switch p.behavior {
	case "finalize-error":
		return identity.UnavailableError{}
	case "finalize-panic":
		panic("private captcha finalize")
	case "finalize-rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "finalize-poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	}
	return nil
}

func (p *sqlCaptchaDomain) ReleaseCaptchaEvidence(ctx context.Context, w CaptchaReleaseWork) error {
	p.release = w
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&sqlCaptchaDomain{}); err == nil {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE identity.captcha_use_fixture SET state='released',generation=$6::numeric WHERE tenant_id=$1 AND digest=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND generation=$5::numeric`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	switch p.behavior {
	case "release-error":
		return identity.UnavailableError{}
	case "release-panic":
		panic("private captcha release")
	case "release-rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	}
	return nil
}

func (p *sqlCaptchaDomain) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if p.behavior == "unknown" {
		return RecoveryUnknown, nil
	}
	b, err := w.CaptchaBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	if _, err := w.CaptchaBinding(&sqlCaptchaDomain{}); err == nil {
		return RecoveryUnknown, invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT state FROM identity.captcha_use_fixture WHERE tenant_id=$1 AND digest=$2 AND command_id=$3 AND fingerprint=$4 AND generation=$5::numeric`, string(b.Command.TenantID), b.Plan.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10))
	if err != nil {
		return RecoveryUnknown, err
	}
	var state string
	matched := rows.Next() && rows.Scan(&state) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched || state != "reserved" {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

type captchaDomainFeature struct {
	featureExecutionPhase
	delay bool
}

func (p *captchaDomainFeature) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_use_domain_fixture(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.delay {
		if _, err := w.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp()))+0.02))`, w.state.execution.reservation.plan.captchaUse.ExpiresAt); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (*captchaDomainFeature) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.captcha_use_domain_fixture")
}

type captchaDomainAudit struct{ featureExecutionAuditPhase }

func (*captchaDomainAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_domain_audit(command_id,event_id,outcome) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), r.Record.ID(), string(r.Record.Outcome())); err != nil {
			return err
		}
	}
	return nil
}
func (*captchaDomainAudit) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.captcha_domain_audit")
}

type captchaDomainOutbox struct{ recoveryLifecyclePhase }

func (*captchaDomainOutbox) PersistLifecycle(ctx context.Context, w Work) error {
	events, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, e := range events {
		if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_domain_outbox(command_id,event_id) VALUES($1,$2)`, string(e.CommandID), e.ID); err != nil {
			return err
		}
	}
	return nil
}
func (*captchaDomainOutbox) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.captcha_domain_outbox")
}

func testCaptchaDomain(t *testing.T, ctx context.Context, pool *database.Pool, setup func(*testing.T, Contributor) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan)) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.captcha_use_domain_fixture(command_id text PRIMARY KEY); CREATE TABLE identity.captcha_domain_audit(command_id text NOT NULL,event_id text PRIMARY KEY,outcome text NOT NULL); CREATE TABLE identity.captcha_domain_outbox(command_id text PRIMARY KEY,event_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"allow", "deny-apply", "deny-final", "expiry", "panic", "rows", "poison", "finalize-error", "finalize-panic", "finalize-rows", "finalize-poison", "release-error", "release-panic", "release-rows", "recover", "unknown", "divergent-recovery"} {
		t.Run(mode, func(t *testing.T) {
			p := &sqlCaptchaDomain{behavior: mode}
			p.registered = p
			c, b, command, plan := setup(t, p)
			var entries []Contributor
			for _, entry := range c.registry.state.entries {
				switch entry.descriptor.Owner {
				case "identity/session/postgres":
					entries = append(entries, &captchaDomainFeature{delay: mode == "expiry"})
				case "audit/postgres":
					entries = append(entries, &captchaDomainAudit{})
				case "outbox/postgres":
					entries = append(entries, &captchaDomainOutbox{})
				default:
					entries = append(entries, entry.contributor)
				}
			}
			var err error
			c.registry, err = NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = c.registry.Descriptors()
			if mode == "expiry" {
				var now time.Time
				if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				plan.CaptchaEvidence.ExpiresAt = now.Add(500 * time.Millisecond).UTC()
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.captcha_use_fixture SET expiry=$2 WHERE digest=$1`, plan.CaptchaEvidence.EvidenceDigest[:], plan.CaptchaEvidence.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			}
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if mode == "recover" || mode == "unknown" || mode == "divergent-recovery" {
				if mode == "divergent-recovery" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.captcha_use_fixture SET generation=2 WHERE digest=$1`, plan.CaptchaEvidence.EvidenceDigest[:]); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
				result, err := c.recoverCommandReceipt(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, OperationID: b.OperationID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, RecordID: b.RecordID})
				var unavailable identity.UnavailableError
				if mode == "recover" && (!errors.As(err, &unavailable) || result.Outcome != identity.CommitOutcomeNotCommitted) {
					t.Fatal("proved noncommit did not release", err, result.Outcome)
				}
				if mode != "recover" && (err == nil || result.Outcome != identity.CommitOutcomeInProgress) {
					t.Fatal("unknown supplied proof")
				}
			} else {
				w, err := c.Begin(ctx, r)
				if err != nil {
					t.Fatal("complete domain phases rejected", err)
				}
				defer c.Abort(w, identity.UnavailableError{})
				result, err := c.ApplyFeature(ctx, w, command)
				if err == nil {
					result, err = c.Commit(w, result)
				} else {
					result, err = c.Abort(w, err)
				}
				if mode == "allow" && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || p.checks != 2) {
					t.Fatal("atomic domain use failed", err, result.Outcome, p.checks)
				}
				failedOutcome := identity.CommitOutcomeNotCommitted
				if strings.HasPrefix(mode, "release-") {
					failedOutcome = identity.CommitOutcomeUnknown
				}
				if mode != "allow" && (err == nil || result.Outcome != failedOutcome || strings.Contains(err.Error(), "private")) {
					t.Fatal("failed domain leaked or committed", err, result.Outcome)
				}
			}
			var evidence, state string
			var domain, audits, outbox int
			if err := pool.Raw().QueryRow(ctx, `SELECT e.state,c.state,(SELECT count(*) FROM identity.captcha_use_domain_fixture WHERE command_id=$3),(SELECT count(*) FROM identity.captcha_domain_audit WHERE command_id=$3),(SELECT count(*) FROM identity.captcha_domain_outbox WHERE command_id=$3) FROM identity.captcha_use_fixture e JOIN identity.commands c ON c.command_id=$1 WHERE e.digest=$2`, raw, plan.CaptchaEvidence.EvidenceDigest[:], string(b.CommandID)).Scan(&evidence, &state, &domain, &audits, &outbox); err != nil {
				t.Fatal(err)
			}
			if mode == "allow" {
				if evidence != "finalized" || state != "committed" || domain != 1 || audits != 1 || outbox != 1 {
					t.Fatal("successful effects not atomic", evidence, state, domain, audits, outbox)
				}
			} else if mode == "unknown" || mode == "divergent-recovery" || strings.HasPrefix(mode, "release-") {
				if evidence != "reserved" || state != "pending" || domain != 0 || audits != 0 || outbox != 0 {
					t.Fatal("unknown custody released", evidence, state, domain, audits, outbox)
				}
			} else {
				if evidence != "released" || state != "aborted" || domain != 0 || audits != 1 || outbox != 0 {
					t.Fatal("failure prefix escaped", evidence, state, domain, audits, outbox)
				}
			}
			if _, err := p.apply.Binding(p); err == nil {
				t.Fatal("returned apply revived")
			}
			if _, err := p.finalize.Binding(p); err == nil {
				t.Fatal("returned finalize revived")
			}
			if _, err := p.release.Binding(p); err == nil {
				t.Fatal("returned release revived")
			}
		})
	}
}
