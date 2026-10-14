package postgres

import (
	"context"
	"crypto/hmac"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// VelocityRecoveryClosure is opaque custody of a stable primary journal cut.
// It is not native publication, temporal coverage or healthy admission authority.
type VelocityRecoveryClosure struct{ state *velocityRecoveryClosure }
type velocityRecoveryClosure struct {
	lease         *velocityRecoveryLease
	position      int64
	from, through time.Time
	started       time.Time
	activated     time.Time
}

func (VelocityRecoveryClosure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityRecoveryClosure(redacted)")
}
func (VelocityRecoveryClosure) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecoveryClosure) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// PrepareClosure drains overlapping writers and durably closes new journal
// admission for the exact live lease, using the existing epoch's replay cut.
// Every retained change must have attributable current-generation applied
// progress; pending, unknown and unpositioned history deny. Matching retries
// retain the original cut. Renewal reopens admission and invalidates the cut;
// expiry also ends its writer fence. No SQL lock spans external IO. This proves
// a stable journal cut only, not historical coverage or two-store health.
// Ambiguous commit returns no custody; retry reads the same primary cut.
func (r VelocityRecovery) PrepareClosure(ctx context.Context, lease VelocityRecoveryLease) (VelocityRecoveryClosure, error) {
	return r.primaryClosure(ctx, lease, true, false)
}

// PrepareCoveredClosure requires a complete maximum-window journal lifetime in
// addition to the applied stable cut. Install VelocityCoverageMigrationSource.
// Missing historical provenance starts at current primary time and returns
// unavailable; callers cannot backdate it. Initial adoption needs a full-window
// warmup. Ordinary renewal/takeover/boot preserves continuity. All native effects
// must use this journal before dispatch; mixed writers and incomplete restores
// are unsupported. This remains primary custody, not native publication/health.
func (r VelocityRecovery) PrepareCoveredClosure(ctx context.Context, lease VelocityRecoveryLease) (VelocityRecoveryClosure, error) {
	return r.primaryClosure(ctx, lease, true, true)
}

// CheckCoveredClosure checks the retained coverage and exact closed lease.
func (r VelocityRecovery) CheckCoveredClosure(ctx context.Context, closure VelocityRecoveryClosure) error {
	if closure.state == nil || closure.state.started.IsZero() {
		return identity.InvalidInputError{Field: "velocity_coverage"}
	}
	current, err := r.primaryClosure(ctx, VelocityRecoveryLease{state: closure.state.lease}, false, true)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	c := closure.state
	if current.state.position != c.position || !current.state.from.Equal(c.from) || !current.state.through.Equal(c.through) || !current.state.started.Equal(c.started) {
		return identity.UnavailableError{}
	}
	return nil
}

// CheckClosure verifies the exact retained cut and original lease against
// primary time. It is a point-in-time check, not native effect permission.
// Superseded, expired, foreign, altered or ambiguous custody fails closed.
func (r VelocityRecovery) CheckClosure(ctx context.Context, closure VelocityRecoveryClosure) error {
	if closure.state == nil {
		return identity.InvalidInputError{Field: "velocity_closure"}
	}
	c := closure.state
	current, err := r.primaryClosure(ctx, VelocityRecoveryLease{state: c.lease}, false, false)
	if err != nil {
		return err
	}
	if current.state.position != c.position || !current.state.from.Equal(c.from) || !current.state.through.Equal(c.through) {
		return identity.UnavailableError{}
	}
	return nil
}

func (r VelocityRecovery) primaryClosure(ctx context.Context, lease VelocityRecoveryLease, prepare, covered bool) (VelocityRecoveryClosure, error) {
	return r.primaryPublicationClosure(ctx, lease, prepare, covered, nil)
}

func (r VelocityRecovery) primaryPublicationClosure(ctx context.Context, lease VelocityRecoveryLease, prepare, covered bool, confirmation *velocityPublicationCheck) (VelocityRecoveryClosure, error) {
	// Authenticate applied custody first without retaining its transaction.
	// Recheck its seal and exact position under the final writer fence below:
	// concurrent advancement or a newly committed tail must not be skipped.
	cursor, err := r.ResumeApplied(ctx, lease)
	if err != nil {
		return VelocityRecoveryClosure{}, err
	}
	s, l := r.state, lease.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityRecoveryClosure{}, err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return VelocityRecoveryClosure{}, err
	}
	now, err := s.liveLease(bounded, tx, l)
	if err != nil {
		return VelocityRecoveryClosure{}, err
	}
	var from, through time.Time
	var generation *string
	var position int64
	var seal []byte
	if err := tx.QueryRow(bounded, `SELECT replay_from,replay_through,applied_generation::text,applied_position,applied_seal FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&from, &through, &generation, &position, &seal); err != nil {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	if position != cursor.state.position || from.IsZero() || through.Before(from) || through.After(now) || from.After(now.Add(-s.maximumWindow)) {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	if generation == nil {
		if position != 0 || len(seal) != 0 {
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
	} else if *generation != strconv.FormatUint(l.generation, 10) || position <= 0 || !hmac.Equal(seal, s.appliedSeal(l, position)) {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	var maximum *int64
	var recorded *time.Time
	var unresolved bool
	if err := tx.QueryRow(bounded, `SELECT max(replay_position),max(recorded_at),COALESCE(bool_or(replay_position IS NULL OR outcome IN('pending','unknown')),false) FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2`, l.tenant, s.journal.namespace).Scan(&maximum, &recorded, &unresolved); err != nil || unresolved || maximum == nil && position != 0 || maximum != nil && *maximum != position {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	if through.Equal(from) {
		if !prepare {
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
		through = now
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET replay_through=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], through); err != nil {
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
	}
	if recorded != nil && recorded.After(through) {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	var started time.Time
	if covered {
		var stored *time.Time
		if err := tx.QueryRow(bounded, `SELECT journal_started_at FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&stored); err != nil {
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
		if stored == nil {
			if prepare {
				if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET journal_started_at=$4,replay_through=replay_from WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], now); err != nil {
					return VelocityRecoveryClosure{}, identity.UnavailableError{}
				}
				if err := tx.Commit(bounded); err != nil {
					return VelocityRecoveryClosure{}, identity.UnavailableError{}
				}
			}
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
		started = *stored
		if started.IsZero() || started.After(through.Add(-s.maximumWindow)) {
			return VelocityRecoveryClosure{}, identity.UnavailableError{}
		}
	}
	now, err = s.liveLease(bounded, tx, l)
	if err != nil {
		return VelocityRecoveryClosure{}, err
	}
	result := &velocityRecoveryClosure{lease: l, position: position, from: from, through: through, started: started}
	if confirmation != nil {
		if err := s.confirmPublication(bounded, tx, l, result, confirmation, now); err != nil {
			return VelocityRecoveryClosure{}, err
		}
		now, err = s.liveLease(bounded, tx, l)
		if err != nil {
			return VelocityRecoveryClosure{}, err
		}
		if confirmation.activate {
			// Keep the native-confirmed snapshot watermark unchanged. Actual
			// activation time is separate and cannot launder cut freshness.
			if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET state='healthy',healthy_at=replay_through,activated_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], now); err != nil {
				return VelocityRecoveryClosure{}, identity.UnavailableError{}
			}
			result.activated = now
		}
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityRecoveryClosure{}, identity.UnavailableError{}
	}
	return VelocityRecoveryClosure{state: result}, nil
}
