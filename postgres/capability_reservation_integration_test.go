//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This deliberate independently-implemented participant fixture proves the
// coordinator's transaction and invocation boundary, not production capability
// storage, cryptographic key custody or the complete one-time workflow.
type sqlCapabilityReservation struct {
	capabilityReservationProbe
	fail, panicAfter, leaveRows bool
	calls, rebinds              int
}

func (p *sqlCapabilityReservation) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	p.calls++
	p.retained = w
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlCapabilityReservation{}); err == nil {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_reservation_fixture SET state='reserved',command_id=$4,fingerprint=$5,generation=$6::numeric
 WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='issued' AND expiry=$7 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlCapabilityReservation) RebindCapability(ctx context.Context, w CapabilityReservationWork) error {
	p.rebinds++
	p.retained = w
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration == 0 {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_reservation_fixture SET generation=$6::numeric
 WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$7::numeric AND expiry=$8 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlCapabilityReservation) finish(ctx context.Context, w CapabilityReservationWork) error {
	if p.panicAfter {
		panic("private participant panic")
	}
	if p.fail {
		return errors.New("private participant diagnostic")
	}
	if p.leaveRows {
		_, err := w.Query(ctx, "SELECT 1")
		return err
	}
	return nil
}

func liveCapabilityReservation(t *testing.T, p Contributor) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, command, plan := reservationPlanFixture(t, p)
	spec, _ := command.ChangeIdentifier()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.CommandID = id
	spec.Proof = capability.Grant{}
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := identity.BuildIdentifierProofPayload(identity.IdentifierProofSpec{Command: spec, Issuer: "https://identity.example.test", Audience: "backend", ID: string(id), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("proof-key", []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{ID: "proof-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	spec.Proof, err = capability.Verify(context.Background(), token, keys, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	command, err = identity.NewIdentifierCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	plan.Capability.CapabilityID = payload.ID
	plan.Capability.ExpiresAt = payload.ExpiresAt
	return c, command, plan
}

func testCapabilityReservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.capability_reservation_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text NOT NULL,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric,PRIMARY KEY(tenant_id,purpose,capability_id))`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, "DROP TABLE identity.capability_reservation_fixture"); err != nil {
			t.Error(err)
		}
	})
	setup := func(t *testing.T, p *sqlCapabilityReservation) (*Coordinator, identity.Command, CommandPlan) {
		t.Helper()
		c, command, plan := liveCapabilityReservation(t, p)
		var err error
		c, err = NewCoordinator(pool, c.registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := command.ChangeIdentifier()
		plan, err = c.PrepareCommandPlan(spec.Binding, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_reservation_fixture(tenant_id,purpose,capability_id,expiry,state) VALUES($1,$2,$3,$4,'issued')`, string(spec.Binding.TenantID), spec.Binding.OperationID, plan.Capability.CapabilityID, plan.Capability.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return c, command, plan
	}
	t.Run("atomic reserve and takeover", func(t *testing.T) {
		participant := &sqlCapabilityReservation{}
		c, command, plan := setup(t, participant)
		spec, _ := command.ChangeIdentifier()
		b := spec.Binding
		r, result, err := c.ReserveCommand(ctx, b, command, plan)
		if err != nil || r.state == nil || result.Outcome != identity.CommitOutcomeInProgress || participant.calls != 1 {
			t.Fatal("atomic reserve", err)
		}
		if _, err := participant.retained.Binding(participant); err == nil {
			t.Fatal("retained reservation authority")
		}
		if _, err := participant.retained.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("retained SQL authority")
		}
		if _, err := c.Begin(ctx, r); err == nil || r.state.started.Load() {
			t.Fatal("incomplete workflow began")
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var generation string
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.capability_reservation_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID).Scan(&generation); err != nil || generation != "1" {
			t.Fatal("participant missing", err)
		}
		replay, _, err := c.ReserveCommand(ctx, b, command, plan)
		if err != nil || replay.state != nil || participant.calls != 1 {
			t.Fatal("live replay re-reserved", err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		successor, _, err := c.ReserveCommand(ctx, b, command, plan)
		if err != nil || successor.state == nil || successor.state.journal.generation != 2 || participant.rebinds != 1 {
			t.Fatal("takeover", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.capability_reservation_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID).Scan(&generation); err != nil || generation != "2" {
			t.Fatal("participant takeover missing", err)
		}
		// A terminal participant cannot be revived, and the journal takeover must
		// roll back with the failed CAS rather than leave a generation prefix.
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.capability_reservation_fixture SET state='finalized' WHERE capability_id=$1`, plan.Capability.CapabilityID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		failed, _, err := c.ReserveCommand(ctx, b, command, plan)
		if err == nil || failed.state != nil {
			t.Fatal("terminal capability reactivated")
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&generation); err != nil || generation != "2" {
			t.Fatal("partial journal takeover", err)
		}
		for _, mismatch := range []string{"command", "fingerprint", "generation", "missing"} {
			q, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := claimFingerprint([32]byte{1}, q.canonical)
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.capability_reservation_fixture SET state='reserved',command_id=$2,fingerprint=$3,generation=2 WHERE capability_id=$1`, plan.Capability.CapabilityID, string(b.CommandID), fingerprint[:]); err != nil {
				t.Fatal(err)
			}
			switch mismatch {
			case "command":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.capability_reservation_fixture SET command_id='foreign' WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "fingerprint":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.capability_reservation_fixture SET fingerprint=$2 WHERE capability_id=$1`, plan.Capability.CapabilityID, []byte{9})
			case "generation":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.capability_reservation_fixture SET generation=1 WHERE capability_id=$1`, plan.Capability.CapabilityID)
			case "missing":
				_, err = pool.Raw().Exec(ctx, `DELETE FROM identity.capability_reservation_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if r, _, err := c.ReserveCommand(ctx, b, command, plan); err == nil || r.state != nil {
				t.Fatal("mismatched participant accepted", mismatch)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&generation); err != nil || generation != "2" {
				t.Fatal("mismatch left journal prefix", mismatch, err)
			}
		}
	})
	for _, mode := range []string{"error", "panic", "open rows"} {
		t.Run(mode, func(t *testing.T) {
			participant := &sqlCapabilityReservation{fail: mode == "error", panicAfter: mode == "panic", leaveRows: mode == "open rows"}
			c, command, plan := setup(t, participant)
			spec, _ := command.ChangeIdentifier()
			b := spec.Binding
			r, result, err := c.ReserveCommand(ctx, b, command, plan)
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || r.state != nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("failed participant fabricated outcome", err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&count); err != nil || count != 0 {
				t.Fatal("claim prefix survived", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, id).Scan(&count); err != nil || count != 0 {
				t.Fatal("journal prefix survived", err)
			}
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.capability_reservation_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID).Scan(&state); err != nil || state != "issued" {
				t.Fatal("participant prefix survived", err)
			}
		})
	}
}
