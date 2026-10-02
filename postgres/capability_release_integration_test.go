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

// This SQL participant is a deliberate storage boundary fixture, not the
// production capability adapter or proof of complete identifier orchestration.
type recoveryCapabilityPhase struct {
	sqlCapabilityReservation
	status                    RecoveryStatus
	failRelease, panicRelease bool
	leaveReleaseRows          bool
	retainedRelease           CapabilityReleaseWork
	retainedEvidence          RecoveryWork
}

func (p *recoveryCapabilityPhase) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='reserved',command_id=$4,fingerprint=$5,generation=$6::numeric WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='issued' AND expiry=$7 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *recoveryCapabilityPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	p.retainedEvidence = w
	b, err := w.CapabilityBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.capability_recovery_fixture WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7)`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), b.Plan.ExpiresAt)
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
func (p *recoveryCapabilityPhase) ReleaseCapability(ctx context.Context, w CapabilityReleaseWork) error {
	p.retainedRelease = w
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='released',generation=$7::numeric WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	if p.panicRelease {
		panic("private release diagnostic")
	}
	if p.failRelease {
		return identity.UnavailableError{}
	}
	if p.leaveReleaseRows {
		_, err := w.Query(ctx, "SELECT 1")
		return err
	}
	return nil
}

type incompleteRecoveryCapability struct {
	CapabilityReservationContributor
}

func (*incompleteRecoveryCapability) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func testCapabilityRecovery(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, "DROP TABLE identity.capability_recovery_fixture"); err != nil {
			t.Error(err)
		}
	})
	for _, scenario := range []string{"release", "wrong-expiry", "unknown", "committed", "wrong-binding", "terminal-capability", "missing-capability", "missing-release-phase", "committed-audit", "committed-outbox", "audit-failure", "release-failure", "release-panic", "release-open-rows", "existing-target"} {
		t.Run(scenario, func(t *testing.T) {
			p := &recoveryCapabilityPhase{status: RecoveryNotCommitted}
			a := &recoveryAuditPhase{}
			l := &recoveryLifecyclePhase{}
			c, command, plan := liveCapabilityReservation(t, p)
			registry, err := NewContributorRegistry([]Contributor{repo, a, l, p})
			if err != nil {
				t.Fatal(err)
			}
			c, err = NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			spec, _ := command.ChangeIdentifier()
			b := spec.Binding
			plan.Contributors = registry.Descriptors()
			record, err := kernelMutationAudit(ctx, b, 0, time.Now().UTC().Truncate(time.Microsecond), "committed")
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = AuditBindingDigest(b, record)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), b.OperationID, plan.Capability.CapabilityID, plan.Capability.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.ReserveCommand(ctx, b, command, plan); err != nil {
				t.Fatal(err)
			}
			live, err := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
			if err != nil || live.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("live reservation changed", err)
			}
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing-release-phase":
				c.registry, err = NewContributorRegistry([]Contributor{repo, a, l, &incompleteRecoveryCapability{p}})
				if err != nil {
					t.Fatal(err)
				}
			case "terminal-capability":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='finalized' WHERE capability_id=$1`, plan.Capability.CapabilityID); err != nil {
					t.Fatal(err)
				}
			case "committed-audit":
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_audits VALUES($1,$1)`, string(b.CommandID)); err != nil {
					t.Fatal(err)
				}
			case "committed-outbox":
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_lifecycle VALUES($1,$1)`, string(b.CommandID)); err != nil {
					t.Fatal(err)
				}
			case "release-open-rows":
				p.leaveReleaseRows = true
			case "wrong-expiry":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.capability_recovery_fixture SET expiry=clock_timestamp()-interval '1 second' WHERE capability_id=$1`, plan.Capability.CapabilityID); err != nil {
					t.Fatal(err)
				}
			case "missing-capability":
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.capability_recovery_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				p.status = RecoveryUnknown
			case "committed":
				p.status = RecoveryCommitted
			case "wrong-binding":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.capability_recovery_fixture SET generation=9 WHERE capability_id=$1`, plan.Capability.CapabilityID); err != nil {
					t.Fatal(err)
				}
			case "audit-failure":
				a.fail = true
			case "release-failure":
				p.failRelease = true
			case "release-panic":
				p.panicRelease = true
			case "existing-target":
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1) ON CONFLICT DO NOTHING`, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,$2,$3,'email',$4,1,1,1)`, string(b.TenantID), string(b.UserID), b.RecordID, string(b.CommandID)+"@example.test"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if _, err := pool.Raw().Exec(cleanup, `DELETE FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2`, string(b.TenantID), b.RecordID); err != nil {
						t.Error(err)
					}
					if _, err := pool.Raw().Exec(cleanup, `DELETE FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
						t.Error(err)
					}
				})
			}
			got, err := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
			if err == nil {
				t.Fatal("missing failure classification")
			}
			var state, generation, journalGeneration string
			var audits int
			if scenario == "missing-capability" {
				if err := pool.Raw().QueryRow(ctx, `SELECT generation::text,(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, key, string(b.CommandID)).Scan(&journalGeneration, &audits); err != nil {
					t.Fatal(err)
				}
				if got.Outcome != identity.CommitOutcomeInProgress || journalGeneration != "1" || audits != 0 {
					t.Fatal("absence released owning command")
				}
				return
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT state,generation::text,(SELECT generation::text FROM identity.commands WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3) FROM identity.capability_recovery_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID, key, string(b.CommandID)).Scan(&state, &generation, &journalGeneration, &audits); err != nil {
				t.Fatal(err)
			}
			if scenario == "release" {
				if got.Outcome != identity.CommitOutcomeNotCommitted || state != "released" || generation != "2" || journalGeneration != "2" || audits != 1 {
					t.Fatal("release/receipt/audit not atomic", got.Outcome, state, generation, journalGeneration, audits)
				}
				if _, err := p.retainedRelease.Binding(p); err == nil {
					t.Fatal("release authority retained")
				}
				if _, err := p.retainedRelease.Exec(ctx, "SELECT 1"); err == nil {
					t.Fatal("retained release SQL authority")
				}
				if _, err := p.retainedEvidence.CapabilityBinding(p); err == nil {
					t.Fatal("evidence authority retained")
				}
				repeat, _ := c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
				if repeat.Outcome != got.Outcome || repeat.Binding != got.Binding {
					t.Fatal("terminal receipt changed")
				}
			} else {
				want := "1"
				if scenario == "wrong-binding" {
					want = "9"
				}
				wantState, wantAudits := "reserved", 0
				if scenario == "terminal-capability" {
					wantState = "finalized"
				}
				if scenario == "committed-audit" {
					wantAudits = 1
				}
				if got.Outcome != identity.CommitOutcomeInProgress || state != wantState || generation != want || journalGeneration != "1" || audits != wantAudits {
					t.Fatal("unsafe recovery prefix", got.Outcome, state, generation, journalGeneration, audits)
				}
			}
		})
	}
}
