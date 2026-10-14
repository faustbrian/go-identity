//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SQL fixture proves coordinator ownership, not production OTP cryptography.
type sqlOTPReservation struct {
	otpReservationProbe
	mode           string
	calls, rebinds atomic.Int32
	retained       OTPReservationWork
	registered     OTPReservationContributor
}

func (p *sqlOTPReservation) ReserveOTP(ctx context.Context, w OTPReservationWork) error {
	p.calls.Add(1)
	return p.apply(ctx, w, false)
}
func (p *sqlOTPReservation) RebindOTP(ctx context.Context, w OTPReservationWork) error {
	p.rebinds.Add(1)
	return p.apply(ctx, w, true)
}
func (p *sqlOTPReservation) apply(ctx context.Context, w OTPReservationWork, rebind bool) error {
	p.retained = w
	owner := p.registered
	if owner == nil {
		owner = p
	}
	b, err := w.Binding(owner)
	if err != nil || (b.PreviousGeneration != 0) != rebind {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlOTPReservation{}); err == nil {
		return invalidWork()
	}
	command, err := w.NativeCommand(owner)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b.Command {
		return invalidWork()
	}
	if _, ok := command.OneTimeCode(); !ok {
		return invalidWork()
	}
	if _, err := w.DatabaseTime(ctx); err != nil {
		return err
	}
	var n int64
	if rebind {
		n, err = w.Exec(ctx, `UPDATE public.otp_reservation_fixture SET generation=$6::numeric WHERE tenant_id=$1 AND challenge_id=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND attempt_id=$5 AND generation=$7::numeric AND expiry>clock_timestamp()`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10))
	} else {
		n, err = w.Exec(ctx, `UPDATE public.otp_reservation_fixture SET state='reserved',command_id=$3,fingerprint=$4,attempt_id=$5,generation=$6::numeric WHERE tenant_id=$1 AND challenge_id=$2 AND state='issued' AND expiry>clock_timestamp() AND version=$7::numeric`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.Plan.ExpectedVersion, 10))
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	switch p.mode {
	case "error":
		return errors.New("private OTP diagnostic")
	case "panic":
		panic("private OTP diagnostic")
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	case "commit-failure":
		_, err = w.Exec(ctx, `INSERT INTO public.otp_reservation_guard(target) VALUES('missing')`)
		return err
	}
	return nil
}
func testOTPReservation(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.otp_reservation_fixture(tenant_id text PRIMARY KEY,challenge_id text NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,attempt_id text,generation numeric,version numeric NOT NULL,expiry timestamptz NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.otp_reservation_guard(target text REFERENCES public.otp_reservation_fixture(tenant_id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"replay", "concurrent", "takeover", "foreign-prior", "competing", "error", "panic", "rows", "poison", "expired", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			owner := &sqlOTPReservation{mode: mode}
			c, command, p := otpAttemptFixture(t, owner)
			r, err := NewContributorRegistry([]Contributor{repo, c.registry.state.entries[1].contributor, c.registry.state.entries[2].contributor, c.registry.state.entries[3].contributor, owner})
			if err != nil {
				t.Fatal(err)
			}
			c, err = NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			s, _ := command.Feature()
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.TenantID = identity.TenantID("otp-reserve-" + mode)
			b := s.Binding
			p.OTP.AttemptID = string(b.CommandID)
			p.Contributors = r.Descriptors()
			p.Audits[0].BindingDigest = securityAuditScopeDigest(b, &s.Operation, p.SubjectType, b.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
			command = codeCodecCommand(t, s, "123456")
			p, err = c.PrepareOTPReservationPlan(b, command, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Raw().Exec(ctx, `INSERT INTO public.otp_reservation_fixture(tenant_id,challenge_id,state,version,expiry) VALUES($1,$2,'issued',1,clock_timestamp()+interval '1 minute')`, string(b.TenantID), p.OTP.ChallengeID); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				if _, err = pool.Raw().Exec(ctx, `UPDATE public.otp_reservation_fixture SET expiry=clock_timestamp()-interval '1 second' WHERE tenant_id=$1`, string(b.TenantID)); err != nil {
					t.Fatal(err)
				}
			}
			var reservation Reservation
			var outcome identity.CommandResult
			if mode == "concurrent" {
				var winners atomic.Int32
				var wg sync.WaitGroup
				for range 6 {
					wg.Go(func() {
						owned, result, e := c.ReserveOTPCommand(ctx, b, command, p)
						if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
							t.Error("retry failed", e)
						}
						if owned.state != nil {
							winners.Add(1)
						}
					})
				}
				wg.Wait()
				if winners.Load() != 1 {
					t.Fatal("multiple owners", winners.Load())
				}
			} else {
				reservation, outcome, err = c.ReserveOTPCommand(ctx, b, command, p)
			}
			var state string
			var generation uint64
			if e := pool.Raw().QueryRow(ctx, `SELECT state,coalesce(generation,0)::bigint FROM public.otp_reservation_fixture WHERE tenant_id=$1`, string(b.TenantID)).Scan(&state, &generation); e != nil {
				t.Fatal(e)
			}
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if mode == "error" || mode == "panic" || mode == "rows" || mode == "poison" || mode == "expired" || mode == "commit-failure" {
				var claims, journals int
				if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM identity.commands WHERE command_id=$1)`, key).Scan(&claims, &journals); e != nil {
					t.Fatal(e)
				}
				if err == nil || reservation.state != nil || state != "issued" || generation != 0 || claims != 0 || journals != 0 {
					t.Fatal("failed prefix persisted", state, generation, claims, journals)
				}
				if mode == "commit-failure" && outcome.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("commit attempt falsely classified rollback")
				}
				return
			}
			if err != nil || state != "reserved" || generation != 1 || owner.calls.Load() != 1 {
				t.Fatal("not exactly once", state, generation, err)
			}
			if _, e := owner.retained.Binding(owner); e == nil {
				t.Fatal("returned handle retained authority")
			}
			if mode != "concurrent" {
				if _, e := c.Begin(ctx, reservation); e == nil {
					t.Fatal("incomplete domain phases enabled")
				}
			}
			again, result, e := c.ReserveOTPCommand(ctx, b, command, p)
			if e != nil || again.state != nil || result.Outcome != identity.CommitOutcomeInProgress || owner.calls.Load() != 1 {
				t.Fatal("live replay compared again", e)
			}
			if mode == "competing" {
				other := s
				other.Binding.CommandID, _ = identity.NewCommandID()
				otherCommand := codeCodecCommand(t, other, "123456")
				otherPlan := p
				otherPlan.Audits = append([]AuditPlan(nil), p.Audits...)
				otherPlan.Audits[0].BindingDigest = securityAuditScopeDigest(other.Binding, &other.Operation, p.SubjectType, other.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
				otherPlan.OTP = cloneOTPPlan(p.OTP)
				otherPlan.OTP.AttemptID = string(other.Binding.CommandID)
				otherPlan, err = c.PrepareOTPReservationPlan(other.Binding, otherCommand, otherPlan)
				if err != nil {
					t.Fatal(err)
				}
				loser, _, e := c.ReserveOTPCommand(ctx, other.Binding, otherCommand, otherPlan)
				if e == nil || loser.state != nil {
					t.Fatal("second command stole challenge")
				}
				var winner string
				if e := pool.Raw().QueryRow(ctx, `SELECT command_id FROM public.otp_reservation_fixture WHERE tenant_id=$1`, string(b.TenantID)).Scan(&winner); e != nil || winner != string(b.CommandID) {
					t.Fatal("challenge winner changed", e)
				}
			}
			if mode == "takeover" || mode == "foreign-prior" {
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
					t.Fatal(e)
				}
				if mode == "foreign-prior" {
					if _, e := pool.Raw().Exec(ctx, `UPDATE public.otp_reservation_fixture SET generation=99 WHERE tenant_id=$1`, string(b.TenantID)); e != nil {
						t.Fatal(e)
					}
				}
				again, _, e = c.ReserveOTPCommand(ctx, b, command, p)
				if owner.rebinds.Load() != 1 || owner.calls.Load() != 1 {
					t.Fatal("takeover repeated comparison")
				}
				if mode == "foreign-prior" {
					if e == nil || again.state != nil {
						t.Fatal("foreign predecessor accepted")
					}
				} else if e != nil || again.state == nil || again.state.journal.generation != 2 {
					t.Fatal("exact takeover rejected", e)
				}
			}
		})
	}
}
