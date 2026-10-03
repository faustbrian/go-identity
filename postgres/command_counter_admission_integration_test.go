//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Native risk-policy enforcement is a separate adapter contract; this SQL seam
// proves that the coordinator does not substitute a reservation for admission.
type sqlCounterAdmission struct {
	sqlCommandCounter
	checks            int
	mode              string
	retainedAdmission CommandCounterAdmissionWork
}

func (p *sqlCounterAdmission) ReserveCommandCounters(ctx context.Context, w CommandCounterWork) (CommandCounterDisposition, error) {
	return p.sqlCommandCounter.reserveCounters(ctx, w, p)
}

func (p *sqlCounterAdmission) CheckCommandCounters(ctx context.Context, w CommandCounterAdmissionWork) error {
	p.checks++
	p.retainedAdmission = w
	b, e := w.Binding(p)
	if e != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, e := w.Binding(&sqlCounterAdmission{}); e == nil {
		return invalidWork()
	}
	c, e := w.NativeCommand(p)
	s, ok := c.Feature()
	if e != nil || !ok || s.Binding != b.Command {
		return invalidWork()
	}
	rows, e := w.Query(ctx, `SELECT fingerprint,choice FROM public.identity_counter_charges WHERE command_id=$1 FOR UPDATE`, string(b.Command.CommandID))
	if e != nil {
		return e
	}
	var fingerprint []byte
	var choice int
	valid := rows.Next() && rows.Scan(&fingerprint, &choice) == nil
	if rows.Next() || rows.Err() != nil {
		valid = false
	}
	rows.Close()
	if !valid || string(fingerprint) != string(b.Fingerprint[:]) || choice != int(CommandCounterAllowed) {
		return identity.ForbiddenError{}
	}
	switch p.mode {
	case "deny-apply":
		return identity.ForbiddenError{}
	case "deny-commit":
		if p.checks == 2 {
			return identity.ForbiddenError{}
		}
	case "panic":
		panic("private counter authority")
	case "rows":
		_, e = w.Query(ctx, "SELECT 1")
		return e
	case "poison":
		_, _ = w.Query(ctx, "SELECT 1/0")
	}
	return nil
}

func testCommandCounterAdmission(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, e := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index));CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id))`); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"allow", "takeover", "deny-apply", "deny-commit", "panic", "rows", "poison"} {
		t.Run(mode, func(t *testing.T) {
			participant := &sqlCounterAdmission{mode: mode}
			phase := &featureExecutionPhase{}
			registry, e := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, phase, participant})
			if e != nil {
				t.Fatal(e)
			}
			c, e := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if e != nil {
				t.Fatal(e)
			}
			s := featureCodecSpec()
			s.Binding.CommandID, e = identity.NewCommandID()
			if e != nil {
				t.Fatal(e)
			}
			s.Binding.TenantID = identity.TenantID("admission-" + mode)
			s.Binding.RecordID = "counter-admission"
			s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-value"}}}
			command := featureCodecCommand(t, s)
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature.Contributor = registry.Descriptors(), phase.Descriptor()
			plan.SubjectType, plan.Audits[0].RetentionClass = "session", "standard"
			plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
			seed, e := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
			if e != nil {
				t.Fatal(e)
			}
			plan.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
			if e != nil {
				t.Fatal(e)
			}
			plan, e = c.PrepareCommandPlan(s.Binding, command, plan)
			if e != nil {
				t.Fatal(e)
			}
			r, result, e := c.ReserveCommand(ctx, s.Binding, command, plan)
			if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("counter reservation", e)
			}
			if mode == "takeover" {
				raw, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); e != nil {
					t.Fatal(e)
				}
				r, result, e = c.ReserveCommand(ctx, s.Binding, command, plan)
				if e != nil || r.state == nil || r.state.journal.generation != 2 {
					t.Fatal("counter takeover", e)
				}
			}
			w, e := c.Begin(ctx, r)
			if e != nil {
				t.Fatal("configured native admission cannot enter domain", e)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, e = c.ApplyFeature(ctx, w, command)
			if mode == "allow" || mode == "takeover" || mode == "deny-commit" {
				if e != nil {
					t.Fatal("guarded apply", e)
				}
				result, e = c.Commit(w, result)
			} else {
				if e == nil {
					t.Fatal("invalid admission allowed mutation")
				}
				result, e = c.Abort(w, e)
			}
			var domain, audits, outbox, charges, total int
			if e2 := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_feature_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT count(*) FROM public.identity_counter_charges WHERE command_id=$1),(SELECT value FROM public.identity_counter_totals WHERE tenant_id=$2)`, string(s.Binding.CommandID), string(s.Binding.TenantID)).Scan(&domain, &audits, &outbox, &charges, &total); e2 != nil {
				t.Fatal(e2)
			}
			if mode == "allow" || mode == "takeover" {
				if e != nil || result.Outcome != identity.CommitOutcomeCommitted || domain != 1 || outbox != 1 || participant.checks != 2 {
					t.Fatal("guarded commit incomplete", e, domain, outbox, participant.checks)
				}
			} else {
				if result.Outcome != identity.CommitOutcomeNotCommitted || domain != 0 || outbox != 0 {
					t.Fatal("admission failure retained domain prefix", e, result.Outcome, domain, outbox)
				}
				if mode == "deny-apply" || mode == "deny-commit" {
					var denied identity.ForbiddenError
					if !errors.As(e, &denied) {
						t.Fatal("denial classification", e)
					}
				}
			}
			if audits != 1 || charges != 1 || total != 1 {
				t.Fatal("failure/refund atomicity", audits, charges, total)
			}
			if _, e := participant.retainedAdmission.Binding(participant); e == nil {
				t.Fatal("retained admission authority")
			}
		})
	}
}
