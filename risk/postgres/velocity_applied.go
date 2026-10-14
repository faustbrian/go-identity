package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// RecordApplied durably acknowledges one original terminal recovery effect in
// journal change order. The native acknowledgement must belong to the exact
// live owned lease. Duplicate acknowledged positions are idempotent; gaps,
// unresolved or unauthenticated history, stale ownership and commit ambiguity
// fail closed. Applied progress never publishes health or authorizes a debit.
// Install VelocityAppliedMigrationSource before calling this method. All SQL
// locks are scoped to bounded primary work and never span native IO.
func (r VelocityRecovery) RecordApplied(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, ack risk.VelocityAcknowledgement) error {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state {
		return identity.InvalidInputError{Field: "velocity_applied"}
	}
	s, l := r.state, lease.state
	lb, custodyErr := s.journalReader.Lease(owned)
	if custodyErr != nil || lb.Tenant != l.tenant || !hmac.Equal(lb.Namespace[:], s.journal.namespace) || lb.Epoch != l.epoch || lb.Owner != l.token || lb.Generation != l.generation || !lb.ExpiresAt.Equal(l.expires) {
		return identity.InvalidInputError{Field: "velocity_applied"}
	}
	b, err := s.nativeVerifier.Applied(ctx, owned, ack)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return identity.UnavailableError{}
	}
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return err
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return err
	}
	var generation *string
	var position int64
	var seal []byte
	err = tx.QueryRow(bounded, `SELECT applied_generation::text,applied_position,applied_seal FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&generation, &position, &seal)
	if err != nil || position < 0 {
		return identity.UnavailableError{}
	}
	if generation == nil || *generation != strconv.FormatUint(l.generation, 10) {
		position = 0
	} else if !hmac.Equal(seal, s.appliedSeal(l, position)) {
		return identity.UnavailableError{}
	}
	var unpositioned bool
	if err := tx.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position IS NULL)`, l.tenant, s.journal.namespace).Scan(&unpositioned); err != nil || unpositioned {
		return identity.UnavailableError{}
	}
	var sequence int64
	if err := tx.QueryRow(bounded, `SELECT sequence FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position=$3`, l.tenant, s.journal.namespace, b.Position).Scan(&sequence); err != nil {
		return identity.UnavailableError{}
	}
	record, err := s.readReplayRecord(bounded, tx, l.tenant, sequence, b.Position)
	if err != nil {
		return err
	}
	original := record.state.projection
	if original.ID != b.ID || original.Fingerprint != b.Fingerprint || original.AttemptDigest != b.Attempt || (b.Outcome == risk.VelocityHistoryCommitted && original.Outcome != VelocityReplayCommitted) || (b.Outcome == risk.VelocityHistoryNotCommitted && original.Outcome != VelocityReplayNotCommitted) || (b.Outcome != risk.VelocityHistoryCommitted && b.Outcome != risk.VelocityHistoryNotCommitted) {
		return identity.UnavailableError{}
	}
	if b.Position > position {
		var next *int64
		if err := tx.QueryRow(bounded, `SELECT min(replay_position) FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position>$3`, l.tenant, s.journal.namespace, position).Scan(&next); err != nil || next == nil || *next != b.Position {
			return identity.UnavailableError{}
		}
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET applied_generation=$4::numeric,applied_position=$5,applied_seal=$6 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], strconv.FormatUint(l.generation, 10), b.Position, s.appliedSeal(l, b.Position)); err != nil {
			return identity.UnavailableError{}
		}
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return err
	}
	if err := tx.Commit(bounded); err != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (s *velocityRecovery) appliedSeal(l *velocityRecoveryLease, position int64) []byte {
	return velocityMAC(s.journal.key, "identity-risk-velocity-applied-v1", l.tenant, string(s.journal.namespace), string(l.epoch[:]), strconv.FormatUint(l.generation, 10), string(l.token[:]), strconv.FormatInt(position, 10))
}

// ResumeApplied reads authenticated durable applied progress under the exact
// live primary lease. Renewal preserves progress; takeover starts at zero.
// The returned cursor skips only acknowledged original terminal history, not
// merely scanned history. It grants neither health nor native effect authority.
// Missing or corrupt current-generation history and ambiguous commit deny a
// cursor. Install VelocityAppliedMigrationSource before calling this method.
func (r VelocityRecovery) ResumeApplied(ctx context.Context, lease VelocityRecoveryLease) (VelocityReplayCursor, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state || r.state.journalIssuer == (risk.VelocityJournalIssuer{}) {
		return VelocityReplayCursor{}, identity.InvalidInputError{Field: "velocity_applied"}
	}
	s, l := r.state, lease.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityReplayCursor{}, err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityReplayCursor{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return VelocityReplayCursor{}, err
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return VelocityReplayCursor{}, err
	}
	var generation *string
	var position int64
	var seal []byte
	err = tx.QueryRow(bounded, `SELECT applied_generation::text,applied_position,applied_seal FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&generation, &position, &seal)
	if err != nil || position < 0 {
		return VelocityReplayCursor{}, identity.UnavailableError{}
	}
	if generation == nil {
		if position != 0 || len(seal) != 0 {
			return VelocityReplayCursor{}, identity.UnavailableError{}
		}
	} else {
		g, err := strconv.ParseUint(*generation, 10, 64)
		if err != nil || g == 0 || g > l.generation || strconv.FormatUint(g, 10) != *generation || position <= 0 || len(seal) != 32 {
			return VelocityReplayCursor{}, identity.UnavailableError{}
		}
		if g < l.generation {
			// A successor must replay for its own native fence; predecessor
			// progress cannot attest application under the new owner.
			position = 0
		} else {
			if !hmac.Equal(seal, s.appliedSeal(l, position)) {
				return VelocityReplayCursor{}, identity.UnavailableError{}
			}
			var unpositioned bool
			if err := tx.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position IS NULL)`, l.tenant, s.journal.namespace).Scan(&unpositioned); err != nil || unpositioned {
				return VelocityReplayCursor{}, identity.UnavailableError{}
			}
			var sequence int64
			if err := tx.QueryRow(bounded, `SELECT sequence FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position=$3`, l.tenant, s.journal.namespace, position).Scan(&sequence); err != nil {
				return VelocityReplayCursor{}, identity.UnavailableError{}
			}
			record, err := s.readReplayRecord(bounded, tx, l.tenant, sequence, position)
			if err != nil {
				return VelocityReplayCursor{}, err
			}
			if outcome := record.state.projection.Outcome; outcome != VelocityReplayCommitted && outcome != VelocityReplayNotCommitted {
				return VelocityReplayCursor{}, identity.UnavailableError{}
			}
		}
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return VelocityReplayCursor{}, err
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityReplayCursor{}, identity.UnavailableError{}
	}
	return VelocityReplayCursor{state: &velocityReplayCursor{owner: s, lease: l, position: position}}, nil
}
