//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Real SQL participants prove the coordinator reservation boundary, not native
// risk policy, cryptography, counter algorithms or password interoperability.
type sqlCommandCounter struct {
	mode     string
	retained CommandCounterWork
}

func (*sqlCommandCounter) Descriptor() ContributorDescriptor {
	return (&commandCounterProbe{}).Descriptor()
}
func (*sqlCommandCounter) ValidateCommandCounters(identity.Command, CommandCounterPlan) error {
	return nil
}
func (p *sqlCommandCounter) ReserveCommandCounters(ctx context.Context, w CommandCounterWork) (CommandCounterDisposition, error) {
	p.retained = w
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if _, err = w.Binding(&sqlCommandCounter{}); err == nil {
		return 0, invalidWork()
	}
	command, err := w.NativeCommand(p)
	if err != nil {
		return 0, err
	}
	s, ok := command.Feature()
	if !ok || s.Binding != b.Command {
		return 0, invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT fingerprint,choice FROM public.identity_counter_charges WHERE command_id=$1`, string(b.Command.CommandID))
	if err != nil {
		return 0, err
	}
	var fingerprint []byte
	var choice int
	found := rows.Next()
	if found && rows.Scan(&fingerprint, &choice) != nil {
		rows.Close()
		return 0, invalidWork()
	}
	if rows.Next() || rows.Err() != nil {
		rows.Close()
		return 0, invalidWork()
	}
	rows.Close()
	if b.PreviousGeneration != 0 {
		if !found || string(fingerprint) != string(b.Fingerprint[:]) || choice != int(CommandCounterAllowed) {
			return 0, invalidWork()
		}
		return CommandCounterAllowed, nil
	}
	if found {
		return 0, invalidWork()
	}
	rows, err = w.Query(ctx, `INSERT INTO public.identity_counter_totals(tenant_id,value) VALUES($1,1) ON CONFLICT(tenant_id) DO UPDATE SET value=identity_counter_totals.value+1 RETURNING value`, string(b.Command.TenantID))
	if err != nil {
		return 0, err
	}
	var value int
	if !rows.Next() || rows.Scan(&value) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return 0, invalidWork()
	}
	rows.Close()
	choice = int(CommandCounterAllowed)
	if value > 1 {
		choice = int(CommandCounterDenied)
	}
	if _, err = w.Exec(ctx, `INSERT INTO public.identity_counter_charges(command_id,fingerprint,choice) VALUES($1,$2,$3)`, string(b.Command.CommandID), b.Fingerprint[:], choice); err != nil {
		return 0, err
	}
	switch p.mode {
	case "error":
		return 0, identity.UnavailableError{}
	case "panic":
		panic("private counter details")
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return CommandCounterDisposition(choice), err
	case "poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	case "zero":
		return 0, nil
	case "commit-failure":
		_, err = w.Exec(ctx, `INSERT INTO public.identity_counter_commit_guard(command_id,target_id) VALUES($1,'missing')`, string(b.Command.CommandID))
		if err != nil {
			return 0, err
		}
	}
	return CommandCounterDisposition(choice), nil
}
func (p *sqlCommandCounter) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.CommandCounterBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT fingerprint,choice FROM public.identity_counter_charges WHERE command_id=$1`, string(b.Command.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var fingerprint []byte
	var choice int
	if !rows.Next() || rows.Scan(&fingerprint, &choice) != nil || rows.Next() || rows.Err() != nil || string(fingerprint) != string(b.Fingerprint[:]) || choice != int(CommandCounterAllowed) {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

type counterAuditPhase struct{ fail bool }

func (*counterAuditPhase) Descriptor() ContributorDescriptor {
	return (&domainAuditPhase{}).Descriptor()
}
func (p *counterAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err = w.Exec(ctx, `INSERT INTO public.identity_counter_audits(command_id,event_id) VALUES($1,$2)`, string(w.state.binding.CommandID), r.Record.ID()); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*counterAuditPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_counter_audits")
}

func testCommandCounterReservation(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_counter_totals(tenant_id text PRIMARY KEY,value integer NOT NULL);CREATE TABLE public.identity_counter_charges(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,choice integer NOT NULL);CREATE TABLE public.identity_counter_audits(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL);CREATE TABLE public.identity_counter_commit_guard(command_id text PRIMARY KEY,target_id text REFERENCES public.identity_counter_charges(command_id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"allow-deny-replay", "takeover", "error", "panic", "rows", "poison", "zero", "audit-failure", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			participant := &sqlCommandCounter{mode: mode}
			phase := &scopeFeatureParticipant{operations: featureRegistryInput().operations}
			auditing := &counterAuditPhase{fail: mode == "audit-failure"}
			_, _, base := coordinatorFixture(t)
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, &riskPassiveProbe{registryContributor{base.Contributors[2]}}, phase, participant})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			makeInput := func() (identity.CommandBinding, identity.Command, CommandPlan) {
				s := featureCodecSpec()
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				s.Binding.CommandID = id
				s.Binding.TenantID = identity.TenantID("counter-" + mode)
				s.Binding.RecordID = "counter-record"
				command := featureCodecCommand(t, s)
				_, _, p := featurePlanFixture(t)
				p.Contributors = registry.Descriptors()
				p.Feature.Contributor = phase.Descriptor()
				p.SubjectType = "session"
				p.Audits[0].RetentionClass = "standard"
				p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
				seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
				if err != nil {
					t.Fatal(err)
				}
				p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
				if err != nil {
					t.Fatal(err)
				}
				p, err = c.PrepareCommandPlan(s.Binding, command, p)
				if err != nil {
					t.Fatal(err)
				}
				return s.Binding, command, p
			}
			b, command, p := makeInput()
			r, result, err := c.ReserveCommand(ctx, b, command, p)
			var total, charges, audits int
			inspect := func() {
				if e := pool.Raw().QueryRow(ctx, `SELECT COALESCE((SELECT value FROM public.identity_counter_totals WHERE tenant_id=$1),0),(SELECT count(*) FROM public.identity_counter_charges WHERE command_id=$2),(SELECT count(*) FROM public.identity_counter_audits WHERE command_id=$2)`, string(b.TenantID), string(b.CommandID)).Scan(&total, &charges, &audits); e != nil {
					t.Fatal(e)
				}
			}
			inspect()
			if mode != "allow-deny-replay" && mode != "takeover" && mode != "audit-failure" {
				if err == nil || r.state != nil || total != 0 || charges != 0 || audits != 0 {
					t.Fatal("failed charge leaked durable prefix", mode, total, charges, audits)
				}
				if mode == "commit-failure" && result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("commit attempt failure was called rollback")
				}
				return
			}
			if err != nil || r.state == nil || result.Outcome != identity.CommitOutcomeInProgress || total != 1 || charges != 1 || audits != 0 {
				t.Fatal("allowance did not commit charge", err, total, charges, audits)
			}
			if _, e := participant.retained.Binding(participant); e == nil {
				t.Fatal("retained counter authority")
			}
			if _, e := c.Begin(ctx, r); e == nil {
				t.Fatal("reservation opened domain without current native apply checks")
			}
			if mode == "takeover" {
				id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
					t.Fatal(e)
				}
				r, result, err = c.ReserveCommand(ctx, b, command, p)
				inspect()
				if err != nil || r.state == nil || r.state.journal.generation != 2 || total != 1 || charges != 1 {
					t.Fatal("takeover charged again", err)
				}
				return
			}
			if mode == "allow-deny-replay" {
				_, result, err = c.ReserveCommand(ctx, b, command, p)
				inspect()
				if err != nil || result.Outcome != identity.CommitOutcomeInProgress || total != 1 {
					t.Fatal("live replay charged again", err)
				}
			}
			b, command, p = makeInput()
			r, result, err = c.ReserveCommand(ctx, b, command, p)
			inspect()
			if mode == "audit-failure" {
				if err == nil || total != 1 || charges != 0 || audits != 0 {
					t.Fatal("denial audit failure did not rollback")
				}
				return
			}
			if err == nil || r.state != nil || result.Outcome != identity.CommitOutcomeNotCommitted || total != 2 || charges != 1 || audits != 1 {
				t.Fatal("denial refunded charge or leaked ownership", err, total, charges, audits)
			}
			_, result, err = c.ReserveCommand(ctx, b, command, p)
			inspect()
			if err != nil || result.Outcome != identity.CommitOutcomeNotCommitted || total != 2 || charges != 1 || audits != 1 {
				t.Fatal("terminal denial replay charged again", err)
			}
		})
	}
}
