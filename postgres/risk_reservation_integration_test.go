//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/faustbrian/go-audit"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// An independently implemented SQL participant exercises the coordinator's
// sole transaction, not the production risk journal or key authentication.
type sqlRiskReservation struct {
	riskReservationProbe
	mode           string
	calls, rebinds int
	registered     RiskReservationContributor
}

func (p *sqlRiskReservation) registeredParticipant() RiskReservationContributor {
	if p.registered != nil {
		return p.registered
	}
	return p
}

func (p *sqlRiskReservation) ReserveRiskEvidence(ctx context.Context, w RiskReservationWork) error {
	p.calls++
	p.retained = w
	b, err := w.Binding(p.registeredParticipant())
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlRiskReservation{}); err == nil {
		return invalidWork()
	}
	r := b.Plan
	now, err := w.DatabaseTime(ctx)
	if err != nil || now.Before(r.CheckedAt) {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE identity.risk_reservation_fixture SET state='reserved',command_id=$4,fingerprint=$5,generation=$6::numeric
 WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='issued' AND expiry=$7 AND intent=$8 AND proof=$9 AND policy=$10::numeric AND key_version=$11 AND issued_at=$12 AND expiry>clock_timestamp()`, r.Tenant, r.Purpose, r.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), r.ExpiresAt, r.IntentDigest[:], r.ProofDigest[:], strconv.FormatUint(r.PolicyVersion, 10), int64(r.KeyVersion), r.IssuedAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlRiskReservation) RebindRiskEvidence(ctx context.Context, w RiskReservationWork) error {
	p.rebinds++
	p.retained = w
	b, err := w.Binding(p.registeredParticipant())
	if err != nil || b.PreviousGeneration == 0 {
		return invalidWork()
	}
	r := b.Plan
	now, err := w.DatabaseTime(ctx)
	if err != nil || now.Before(r.CheckedAt) {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE identity.risk_reservation_fixture SET generation=$6::numeric
 WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$7::numeric AND expiry=$8 AND expiry>clock_timestamp() AND intent=$9 AND proof=$10 AND policy=$11::numeric AND key_version=$12 AND issued_at=$13`, r.Tenant, r.Purpose, r.EvidenceDigest[:], string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10), r.ExpiresAt, r.IntentDigest[:], r.ProofDigest[:], strconv.FormatUint(r.PolicyVersion, 10), int64(r.KeyVersion), r.IssuedAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlRiskReservation) finish(ctx context.Context, w RiskReservationWork) error {
	switch p.mode {
	case "error":
		return errors.New("private risk diagnostic")
	case "panic":
		panic("private risk panic")
	case "open rows":
		_, err := w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
		return nil
	case "closure":
		_, _ = w.Exec(ctx, "COMMIT")
		return nil
	}
	rows, err := w.Query(ctx, "SELECT 1")
	if err != nil {
		return err
	}
	defer rows.Close()
	var value int64
	if !rows.Next() || rows.Scan(&value) != nil || value != 1 || rows.Next() || rows.Err() != nil {
		return invalidWork()
	}
	rows.Close()
	_, err = w.DatabaseTime(ctx)
	return err
}

func testRiskReservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.risk_reservation_fixture(tenant_id text NOT NULL,purpose text NOT NULL,digest bytea NOT NULL,intent bytea NOT NULL,proof bytea NOT NULL,policy numeric NOT NULL,key_version bigint NOT NULL,issued_at timestamptz NOT NULL,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric,PRIMARY KEY(tenant_id,purpose,digest))`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, "DROP TABLE identity.risk_reservation_fixture"); err != nil {
			t.Error(err)
		}
	})
	setup := func(t *testing.T, participant Contributor) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan) {
		t.Helper()
		c, command, p := riskReservationFixture(t, participant)
		s, _ := command.Feature()
		s.Binding.CommandID, _ = identity.NewCommandID()
		p.RiskEvidence.ConsumerCommandID = string(s.Binding.CommandID)
		p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, "phone", s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
		// Unique digest per independent fixture; two-command contention below
		// deliberately shares this exact issued identity instead.
		q, _ := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		p.RiskEvidence.EvidenceDigest = claimFingerprint([32]byte{1}, q.canonical)
		command = featureCodecCommand(t, s)
		var err error
		c, err = NewCoordinator(pool, c.registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		p, err = c.PrepareCommandPlan(s.Binding, command, p)
		if err != nil {
			t.Fatal(err)
		}
		r := p.RiskEvidence
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.risk_reservation_fixture(tenant_id,purpose,digest,intent,proof,policy,key_version,issued_at,expiry,state) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,'issued')`, r.Tenant, r.Purpose, r.EvidenceDigest[:], r.IntentDigest[:], r.ProofDigest[:], strconv.FormatUint(r.PolicyVersion, 10), int64(r.KeyVersion), r.IssuedAt, r.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return c, s.Binding, command, p
	}
	assertNoCommand := func(t *testing.T, b identity.CommandBinding) {
		t.Helper()
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var claims, commands int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM identity.commands WHERE command_id=$1)`, id).Scan(&claims, &commands); err != nil || claims != 0 || commands != 0 {
			t.Fatal("reservation prefix survived", err, claims, commands)
		}
	}
	assertGeneration := func(t *testing.T, b identity.CommandBinding, p CommandPlan, want string) {
		t.Helper()
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var commandGen, riskGen, owner string
		if err := pool.Raw().QueryRow(ctx, `SELECT c.generation::text,r.generation::text,r.command_id FROM identity.commands c CROSS JOIN identity.risk_reservation_fixture r WHERE c.command_id=$1 AND r.digest=$2`, id, p.RiskEvidence.EvidenceDigest[:]).Scan(&commandGen, &riskGen, &owner); err != nil || commandGen != want || riskGen != want || owner != string(b.CommandID) {
			t.Fatal("command/risk ownership diverged", err, commandGen, riskGen)
		}
	}
	expireLease := func(t *testing.T, b identity.CommandBinding) {
		t.Helper()
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("terminal recovery", func(t *testing.T) { testRiskRelease(t, ctx, pool, setup, expireLease) })
	t.Run("atomic reserve replay and exact takeover", func(t *testing.T) {
		participant := &sqlRiskReservation{}
		c, b, command, p := setup(t, participant)
		r, _, err := c.ReserveCommand(ctx, b, command, p)
		if err != nil || r.state == nil {
			t.Fatal("risk not reserved", err)
		}
		assertGeneration(t, b, p, "1")
		changed := p
		cp := *p.RiskEvidence
		cp.ProofDigest[0]++
		changed.RiskEvidence = &cp
		if _, _, err := c.ReserveCommand(ctx, b, command, changed); err == nil {
			t.Fatal("same-command changed evidence replaced frozen plan")
		}
		assertGeneration(t, b, p, "1")
		if _, err := participant.retained.Binding(participant); err == nil {
			t.Fatal("retained binding authority")
		}
		if _, err := participant.retained.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("retained SQL authority")
		}
		if _, err := c.Begin(ctx, r); err == nil || r.state.started.Load() {
			t.Fatal("unfinished domain enabled")
		}
		if replay, _, err := c.ReserveCommand(ctx, b, command, p); err != nil || replay.state != nil || participant.calls != 1 {
			t.Fatal("live replay re-reserved", err)
		}
		expireLease(t, b)
		// Unsupported recovery must not run participant callbacks, take over or
		// terminalize while the authoritative risk row remains unresolved.
		query, caller := queryInputs(b)
		if receipt, err := c.RecoverCommand(ctx, query, caller); err == nil || receipt.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("incomplete recovery resolved evidence", err)
		}
		assertGeneration(t, b, p, "1")
		successor, _, err := c.ReserveCommand(ctx, b, command, p)
		if err != nil || successor.state == nil || participant.rebinds != 1 {
			t.Fatal("risk takeover failed", err)
		}
		assertGeneration(t, b, p, "2")
		expireLease(t, b)
		for _, mode := range []string{"command", "fingerprint", "generation", "terminal", "missing"} {
			q, _ := prepareClaim(command, [32]byte{1})
			fp := claimFingerprint([32]byte{1}, q.canonical)
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.risk_reservation_fixture SET state='reserved',command_id=$2,fingerprint=$3,generation=2 WHERE digest=$1`, p.RiskEvidence.EvidenceDigest[:], string(b.CommandID), fp[:]); err != nil {
				t.Fatal(err)
			}
			sql := map[string]string{"command": `UPDATE identity.risk_reservation_fixture SET command_id='foreign' WHERE digest=$1`, "fingerprint": `UPDATE identity.risk_reservation_fixture SET fingerprint='\\x01'::bytea WHERE digest=$1`, "generation": `UPDATE identity.risk_reservation_fixture SET generation=1 WHERE digest=$1`, "terminal": `UPDATE identity.risk_reservation_fixture SET state='finalized' WHERE digest=$1`, "missing": `DELETE FROM identity.risk_reservation_fixture WHERE digest=$1`}[mode]
			if _, err := pool.Raw().Exec(ctx, sql, p.RiskEvidence.EvidenceDigest[:]); err != nil {
				t.Fatal(err)
			}
			if failed, _, err := c.ReserveCommand(ctx, b, command, p); err == nil || failed.state != nil {
				t.Fatal("bad predecessor admitted", mode)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var gen string
			if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&gen); err != nil || gen != "2" {
				t.Fatal("partial takeover survived", mode, err)
			}
		}
	})
	for _, mode := range []string{"error", "panic", "open rows", "poison", "closure", "expired", "terminal", "missing", "proof", "policy", "key"} {
		t.Run(mode, func(t *testing.T) {
			participant := &sqlRiskReservation{mode: mode}
			c, b, command, p := setup(t, participant)
			sql := map[string]string{"expired": `UPDATE identity.risk_reservation_fixture SET expiry=clock_timestamp()-interval '1 second' WHERE digest=$1`, "terminal": `UPDATE identity.risk_reservation_fixture SET state='revoked' WHERE digest=$1`, "missing": `DELETE FROM identity.risk_reservation_fixture WHERE digest=$1`, "proof": `UPDATE identity.risk_reservation_fixture SET proof='\\x01'::bytea WHERE digest=$1`, "policy": `UPDATE identity.risk_reservation_fixture SET policy=policy+1 WHERE digest=$1`, "key": `UPDATE identity.risk_reservation_fixture SET key_version=key_version+1 WHERE digest=$1`}[mode]
			if sql != "" {
				if _, err := pool.Raw().Exec(ctx, sql, p.RiskEvidence.EvidenceDigest[:]); err != nil {
					t.Fatal(err)
				}
			}
			if r, _, err := c.ReserveCommand(ctx, b, command, p); err == nil || r.state != nil {
				t.Fatal("invalid participant reserved", mode)
			}
			if participant.calls != 1 {
				t.Fatal("failure did not reach enlisted participant", mode)
			}
			assertNoCommand(t, b)
			if sql == "" {
				var state string
				if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.risk_reservation_fixture WHERE digest=$1`, p.RiskEvidence.EvidenceDigest[:]).Scan(&state); err != nil || state != "issued" {
					t.Fatal("participant prefix survived", err)
				}
			}
		})
	}
	t.Run("two commands one evidence winner", func(t *testing.T) {
		first := &sqlRiskReservation{}
		c, b, command, p := setup(t, first)
		second := &sqlRiskReservation{}
		other, _, op := riskReservationFixture(t, second)
		other.pool = pool
		other.maximumDuration = 2 * time.Second
		s, _ := command.Feature()
		s.Binding.CommandID, _ = identity.NewCommandID()
		otherCommand := featureCodecCommand(t, s)
		cp := *p.RiskEvidence
		cp.ConsumerCommandID = string(s.Binding.CommandID)
		op = p
		op.Audits = append([]AuditPlan(nil), p.Audits...)
		op.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, "phone", s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
		op.RiskEvidence = &cp
		op.Contributors = other.registry.Descriptors()
		var err error
		op, err = other.PrepareCommandPlan(s.Binding, otherCommand, op)
		if err != nil {
			t.Fatal(err)
		}
		type outcome struct {
			b   identity.CommandBinding
			r   Reservation
			err error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, input := range []struct {
			c       *Coordinator
			b       identity.CommandBinding
			command identity.Command
			p       CommandPlan
		}{{c, b, command, p}, {other, s.Binding, otherCommand, op}} {
			wg.Go(func() {
				<-start
				r, _, err := input.c.ReserveCommand(ctx, input.b, input.command, input.p)
				results <- outcome{input.b, r, err}
			})
		}
		close(start)
		wg.Wait()
		close(results)
		wins := 0
		for result := range results {
			if result.err == nil && result.r.state != nil {
				wins++
				assertGeneration(t, result.b, p, "1")
			} else {
				var conflict identity.ConflictError
				if !errors.As(result.err, &conflict) {
					t.Fatal("race loser was not replay denial", result.err)
				}
				assertNoCommand(t, result.b)
			}
		}
		if wins != 1 {
			t.Fatal("evidence did not have exactly one winner", wins)
		}
	})
}
