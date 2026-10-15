//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// SQL fixture proves sole-coordinator atomicity, not production OTP cryptography,
// challenge policy or delivery. The native OTP adapter must implement those.
type sqlOTPAttempt struct {
	otpAttemptProbe
	mode     string
	calls    atomic.Int32
	retained OTPAttemptWork
}

func (p *sqlOTPAttempt) RecordOTPAttemptDenial(ctx context.Context, w OTPAttemptWork) (OTPAttemptDisposition, error) {
	p.calls.Add(1)
	p.retained = w
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.Binding(&sqlOTPAttempt{}); err == nil {
		return 0, invalidWork()
	}
	command, err := w.NativeCommand(p)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b.Command {
		return 0, invalidWork()
	}
	if _, ok := command.OneTimeCode(); !ok {
		return 0, invalidWork()
	}
	if _, err := w.DatabaseTime(ctx); err != nil {
		return 0, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.otp_denial_totals(tenant_id,value) VALUES($1,1) ON CONFLICT(tenant_id) DO UPDATE SET value=otp_denial_totals.value+1`, string(b.Command.TenantID)); err != nil {
		return 0, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.otp_denial_attempts(command_id,attempt_id,fingerprint) VALUES($1,$2,$3)`, string(b.Command.CommandID), b.Plan.AttemptID, b.Fingerprint[:]); err != nil {
		return 0, err
	}
	switch p.mode {
	case "unchanged":
		return OTPAttemptUnchanged, nil
	case "error":
		return 0, identity.UnavailableError{}
	case "panic":
		panic("private OTP attempt")
	case "zero":
		return 0, nil
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return OTPAttemptDenied, err
	case "commit-failure":
		_, err = w.Exec(ctx, `INSERT INTO public.otp_denial_guard(command_id,target) VALUES($1,'missing')`, string(b.Command.CommandID))
		if err != nil {
			return 0, err
		}
	}
	return OTPAttemptDenied, nil
}

type otpDenialAudit struct{ fail bool }

func (*otpDenialAudit) Descriptor() ContributorDescriptor { return (&domainAuditPhase{}).Descriptor() }
func (*otpDenialAudit) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}
func (p *otpDenialAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.otp_denial_audits(command_id,event_id,outcome) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), r.Record.ID(), string(r.Record.Outcome())); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func testOTPAttemptDenial(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.otp_denial_totals(tenant_id text PRIMARY KEY,value integer NOT NULL); CREATE TABLE public.otp_denial_attempts(command_id text PRIMARY KEY,attempt_id text NOT NULL UNIQUE,fingerprint bytea NOT NULL); CREATE TABLE public.otp_denial_audits(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL,outcome text NOT NULL); CREATE TABLE public.otp_denial_guard(command_id text PRIMARY KEY,target text REFERENCES public.otp_denial_attempts(command_id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"denied-replay", "concurrent", "rotation", "unchanged", "error", "panic", "zero", "rows", "audit-failure", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			owner := &sqlOTPAttempt{mode: mode}
			c, command, p := otpAttemptFixture(t, owner)
			registry, err := NewContributorRegistry([]Contributor{repo, &otpDenialAudit{fail: mode == "audit-failure"}, c.registry.state.entries[2].contributor, c.registry.state.entries[3].contributor, owner})
			if err != nil {
				t.Fatal(err)
			}
			queryPolicy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}
			c, err = NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: queryPolicy})
			if err != nil {
				t.Fatal(err)
			}
			s, _ := command.Feature()
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			s.Binding.CommandID, s.Binding.TenantID = id, identity.TenantID("otp-"+mode)
			p.Contributors = registry.Descriptors()
			p.OTP.AttemptID = string(id)
			p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
			command = codeCodecCommand(t, s, "123456")
			p, err = c.PrepareOTPAttemptPlan(s.Binding, command, p)
			if err != nil {
				t.Fatal(err)
			}
			b := s.Binding
			var result identity.CommandResult
			if mode == "concurrent" {
				var wg sync.WaitGroup
				for range 6 {
					wg.Go(func() {
						r, _ := c.RecordOTPAttemptDenial(ctx, b, command, p)
						if r.Outcome != identity.CommitOutcomeNotCommitted {
							t.Error("concurrent retry lost stable denial", r.Outcome)
						}
					})
				}
				wg.Wait()
				result, err = c.RecordOTPAttemptDenial(ctx, b, command, p)
			} else {
				result, err = c.RecordOTPAttemptDenial(ctx, b, command, p)
			}
			var total, attempts, audits, journals int
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if e := pool.Raw().QueryRow(ctx, `SELECT coalesce((SELECT value FROM public.otp_denial_totals WHERE tenant_id=$1),0),(SELECT count(*) FROM public.otp_denial_attempts WHERE command_id=$2),(SELECT count(*) FROM public.otp_denial_audits WHERE command_id=$2),(SELECT count(*) FROM identity.commands WHERE command_id=$3 AND state='aborted')`, string(b.TenantID), string(b.CommandID), key).Scan(&total, &attempts, &audits, &journals); e != nil {
				t.Fatal(e)
			}
			if mode != "denied-replay" && mode != "concurrent" && mode != "rotation" {
				if err == nil || total != 0 || attempts != 0 || audits != 0 || journals != 0 {
					t.Fatal("failed denial leaked prefix", mode, total, attempts, audits, journals)
				}
				if mode == "commit-failure" && result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("ambiguous commit called rollback")
				}
				return
			}
			if result.Outcome != identity.CommitOutcomeNotCommitted || total != 1 || attempts != 1 || audits != 1 || journals != 1 || owner.calls.Load() != 1 {
				t.Fatal("denial not atomic/exactly once", err, total, attempts, audits, journals, owner.calls.Load())
			}
			query, caller := queryInputs(b)
			recovered, recoveryErr := c.RecoverOTPAttemptDenial(ctx, query, *p.OTP, caller)
			if recovered.Outcome != identity.CommitOutcomeNotCommitted || recoveryErr == nil || owner.calls.Load() != 1 {
				t.Fatal("code-free primary recovery lost denied attempt or compared again", recovered.Outcome, recoveryErr)
			}
			changedAttempt := *p.OTP
			changedAttempt.AttemptFingerprint[0]++
			recovered, recoveryErr = c.RecoverOTPAttemptDenial(ctx, query, changedAttempt, caller)
			if recovered.Outcome != identity.CommitOutcomeInvalid || recoveryErr == nil || owner.calls.Load() != 1 {
				t.Fatal("changed original attempt disclosed primary history")
			}
			if _, err := owner.retained.Binding(owner); err == nil {
				t.Fatal("returned callback retained authority")
			}
			if mode == "rotation" {
				c.keys = claimKeys{current: 2, retained: map[uint32][32]byte{1: {1}, 2: {2}}}
				p, err = c.PrepareOTPAttemptPlan(b, command, p)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err = c.RecordOTPAttemptDenial(ctx, b, command, p)
			if err != nil || result.Outcome != identity.CommitOutcomeNotCommitted || owner.calls.Load() != 1 {
				t.Fatal("replay compared or charged again", err)
			}
			changed := p
			changed.OTP = cloneOTPPlan(p.OTP)
			changed.OTP.AttemptID = "AgAAAAAAAAAAAAAAAAAAAA"
			changed, err = c.PrepareOTPAttemptPlan(b, command, changed)
			if err != nil {
				t.Fatal(err)
			}
			result, err = c.RecordOTPAttemptDenial(ctx, b, command, changed)
			if err == nil || result.Outcome != identity.CommitOutcomeConflict || owner.calls.Load() != 1 {
				t.Fatal("different attempt adopted old command")
			}
			changedCode := codeCodecCommand(t, s, "654321")
			changed, err = c.PrepareOTPAttemptPlan(b, changedCode, p)
			if err != nil {
				t.Fatal(err)
			}
			result, err = c.RecordOTPAttemptDenial(ctx, b, changedCode, changed)
			if err == nil || result.Outcome != identity.CommitOutcomeConflict || owner.calls.Load() != 1 {
				t.Fatal("different code adopted old command")
			}
		})
	}
}
