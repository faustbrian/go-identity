package postgres

import (
	"context"
	"crypto/hmac"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Restart abandons projection progress under the exact live replay lease. It
// returns a successor generation with a new owner and the original expiry;
// it neither extends custody nor grants healthy/native effect authority.
// The original history origin and journal lifetime remain unchanged. Applied
// progress, closure and publication are invalidated atomically. The applied
// and publication migrations must be installed; earlier schemas fail closed.
// A matching retry of the original receipt reconciles the same live successor
// without resetting its progress. Renewal, expiry or later generations deny
// that retry. Unknown commit acknowledgement returns no receipt; retrying the
// original receipt performs no external effect and reconciles on the primary.
func (r VelocityRecovery) Restart(ctx context.Context, lease VelocityRecoveryLease) (VelocityRecoveryLease, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state {
		return VelocityRecoveryLease{}, identity.InvalidInputError{Field: "velocity_recovery"}
	}
	s, l := r.state, lease.state
	if l.generation == 0 || l.generation == math.MaxUint64 || l.token == [16]byte{} || l.epoch == [16]byte{} || !velocityNamespace(l.tenant) || l.expires.IsZero() {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityRecoveryLease{}, err
	}
	defer cancel()
	// Deterministic, domain-separated ownership permits reconciliation after a
	// lost successful COMMIT response without another receipt journal.
	var nextToken [16]byte
	copy(nextToken[:], velocityMAC(s.journal.key, "identity-risk-velocity-restart-v1", l.tenant, string(s.journal.namespace), string(l.epoch[:]), strconv.FormatUint(l.generation, 10), string(l.token[:]), l.expires.UTC().Format(time.RFC3339Nano)))
	if nextToken == [16]byte{} || nextToken == l.token {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return VelocityRecoveryLease{}, err
	}
	var generation string
	var token []byte
	var expires time.Time
	var window int64
	err = tx.QueryRow(bounded, `SELECT generation::text,lease_owner,lease_expires_at,maximum_window_us FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3 AND state='replaying' FOR UPDATE`, l.tenant, s.journal.namespace, l.epoch[:]).Scan(&generation, &token, &expires, &window)
	if err != nil || !expires.Equal(l.expires) || window != s.maximumWindow.Microseconds() {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	var now time.Time
	if err := tx.QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil || !now.Before(expires) {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	current := generation == strconv.FormatUint(l.generation, 10) && hmac.Equal(token, l.token[:])
	reconciled := generation == strconv.FormatUint(l.generation+1, 10) && hmac.Equal(token, nextToken[:])
	if !current && !reconciled {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	if current {
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET generation=$4::numeric,lease_owner=$5,replay_through=replay_from,applied_generation=NULL,applied_position=0,applied_seal=NULL,publication_id=NULL,publication_confirmed_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], strconv.FormatUint(l.generation+1, 10), nextToken[:]); err != nil {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	return VelocityRecoveryLease{state: &velocityRecoveryLease{owner: s, tenant: l.tenant, epoch: l.epoch, token: nextToken, generation: l.generation + 1, expires: l.expires}}, nil
}
