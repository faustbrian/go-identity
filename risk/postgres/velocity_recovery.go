package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// VelocityRecoveryConfig selects a confirmed journal and explicit lease bound.
// The supported reference recovery interval is exactly one hour. LeaseDuration
// is microsecond-representable, positive and at most one minute. There is no
// healthy default, operator bypass, effect callback or private counter store.
type VelocityRecoveryConfig struct {
	Journal                      VelocityJournal
	MaximumWindow, LeaseDuration time.Duration
	// JournalIssuer and NativeVerifier opt into owned cross-adapter recovery.
	// Both must belong to one private composition graph. Omit both to preserve
	// the lease/page-only API; partial or crossed ownership is rejected.
	JournalIssuer  risk.VelocityJournalIssuer
	NativeVerifier risk.VelocityNativeVerifier
}

// VelocityRecovery owns PostgreSQL recovery leases, not counter mutation or
// replay/publication truth. Immutable local configuration is concurrent-safe;
// zero is invalid. It owns no goroutine and never closes the caller's pool.
// Acquire/Renew use primary database time after locks. Unknown acknowledgements
// expose no receipt; takeover requires authoritative expiry, never local time.
type VelocityRecovery struct{ state *velocityRecovery }
type velocityRecovery struct {
	journal                      *velocityJournal
	maximumWindow, leaseDuration time.Duration
	journalIssuer                risk.VelocityJournalIssuer
	journalReader                risk.VelocityJournalVerifier
	nativeVerifier               risk.VelocityNativeVerifier
}

// VelocityRecoveryLease is exact-instance custody of one acknowledged lease.
// It is not allowance, replay completeness, dispatch or publication authority.
// Renewal supersedes the prior receipt; takeover fences its generation. It is
// not constructible or serializable, and carries no exportable owner secret.
type VelocityRecoveryLease struct{ state *velocityRecoveryLease }
type velocityRecoveryLease struct {
	owner        *velocityRecovery
	tenant       string
	epoch, token [16]byte
	generation   uint64
	expires      time.Time
}

func (VelocityRecoveryConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityRecoveryConfig(redacted)")
}
func (VelocityRecoveryConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecoveryConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityRecovery(redacted)")
}
func (VelocityRecovery) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityRecovery) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityRecoveryLease) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityRecoveryLease(redacted)")
}
func (VelocityRecoveryLease) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecoveryLease) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// NewVelocityRecovery validates configuration without IO. Journal must already
// use VelocityReplayMigrationSource. Unsupported windows and lease bounds fail
// redacted with ErrInvalidPolicy; construction grants no external authority.
func NewVelocityRecovery(c VelocityRecoveryConfig) (VelocityRecovery, error) {
	if c.Journal.state == nil || c.MaximumWindow != time.Hour || c.LeaseDuration <= 0 || c.LeaseDuration > time.Minute || c.LeaseDuration%time.Microsecond != 0 {
		return VelocityRecovery{}, risk.ErrInvalidPolicy
	}
	if (c.JournalIssuer != (risk.VelocityJournalIssuer{}) || c.NativeVerifier != (risk.VelocityNativeVerifier{})) && c.JournalIssuer.ValidateNative(c.NativeVerifier) != nil {
		return VelocityRecovery{}, risk.ErrInvalidPolicy
	}
	reader, _ := c.JournalIssuer.Verifier()
	return VelocityRecovery{state: &velocityRecovery{journal: c.Journal.state, maximumWindow: c.MaximumWindow, leaseDuration: c.LeaseDuration, journalIssuer: c.JournalIssuer, journalReader: reader, nativeVerifier: c.NativeVerifier}}, nil
}

// Acquire obtains one scoped replaying lease for a trusted projection boot
// epoch. The epoch must be its nonzero random 128-bit boot marker, not request
// input. Only authoritative expiry permits replacing a live replay owner.
// Same-epoch takeover advances generation; a new epoch atomically retires the
// old one. Retired epochs cannot resurrect, including when their marker returns.
// Initial cursor has zero covered progress, and no path publishes healthy state.
// Concurrent losers, exhausted generations, corrupt state and commit ambiguity
// return UnavailableError with no receipt. No journal outcome is modified.
// Acquisition drains all overlapping journal writer transactions. Later writes
// remain evidence and must be accounted for by the still-unimplemented replay
// owner; successful acquisition is not a complete scan or stable final cursor.
func (r VelocityRecovery) Acquire(ctx context.Context, tenant string, epoch [16]byte) (VelocityRecoveryLease, error) {
	if r.state == nil || !velocityNamespace(tenant) || epoch == [16]byte{} {
		return VelocityRecoveryLease{}, identity.InvalidInputError{Field: "velocity_recovery"}
	}
	bounded, cancel, err := r.state.bounded(ctx)
	if err != nil {
		return VelocityRecoveryLease{}, err
	}
	defer cancel()
	s := r.state
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, tenant); err != nil {
		return VelocityRecoveryLease{}, err
	}
	var retired bool
	if err := tx.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3 AND state='retired')`, tenant, s.journal.namespace, epoch[:]).Scan(&retired); err != nil || retired {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	var previous []byte
	var generationText, state string
	var window int64
	var leaseExpires *time.Time
	var journalStarted *time.Time
	// JSON field lookup preserves lease/page compatibility with schemas predating
	// optional coverage metadata. Missing metadata never grants coverage.
	err = tx.QueryRow(bounded, `SELECT epoch,generation::text,maximum_window_us,state,lease_expires_at,(to_jsonb(velocity_epochs)->>'journal_started_at')::timestamptz FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND state<>'retired' FOR UPDATE`, tenant, s.journal.namespace).Scan(&previous, &generationText, &window, &state, &leaseExpires, &journalStarted)
	missing := err == pgx.ErrNoRows
	if err != nil && !missing {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	var now time.Time
	if err := tx.QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	generation := uint64(1)
	if journalStarted != nil && journalStarted.After(now) {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	if !missing {
		old, err := strconv.ParseUint(generationText, 10, 64)
		if err != nil || old == 0 || old == math.MaxUint64 || len(previous) != 16 || bytes.Equal(previous, make([]byte, 16)) || window != s.maximumWindow.Microseconds() || leaseExpires != nil && now.Before(*leaseExpires) || state == "healthy" && bytes.Equal(previous, epoch[:]) {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
		if state != "replaying" && state != "unavailable" && state != "healthy" {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
		generation = old + 1
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil || token == [16]byte{} {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	expires := now.Add(s.leaseDuration)
	from := now.Add(-s.maximumWindow)
	if !missing && !bytes.Equal(previous, epoch[:]) {
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET state='retired',lease_owner=NULL,lease_expires_at=NULL,healthy_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, s.journal.namespace, previous); err != nil {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
		missing = true
	}
	if missing {
		_, err = tx.Exec(bounded, `INSERT INTO `+s.journal.schema+`.velocity_epochs(tenant_id,namespace_digest,epoch,generation,maximum_window_us,state,lease_owner,lease_expires_at,replay_from,replay_through) VALUES($1,$2,$3,$4::numeric,$5,'replaying',$6,$7,$8,$8)`, tenant, s.journal.namespace, epoch[:], strconv.FormatUint(generation, 10), s.maximumWindow.Microseconds(), token[:], expires, from)
	} else {
		_, err = tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET generation=$4::numeric,state='replaying',lease_owner=$5,lease_expires_at=$6,replay_from=$7,replay_through=$7,healthy_at=NULL WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, s.journal.namespace, epoch[:], strconv.FormatUint(generation, 10), token[:], expires, from)
	}
	if err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	if missing && journalStarted != nil {
		// Carry the journal's lifetime across boot changes; recovery ownership is
		// replaced, but durable journal continuity is not restarted.
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET journal_started_at=$4 WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, tenant, s.journal.namespace, epoch[:], *journalStarted); err != nil {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
	}
	if !missing {
		if err := s.clearPublication(bounded, tx, tenant, epoch); err != nil {
			return VelocityRecoveryLease{}, err
		}
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	return VelocityRecoveryLease{state: &velocityRecoveryLease{owner: s, tenant: tenant, epoch: epoch, token: token, generation: generation, expires: expires}}, nil
}

// CheckLease compares exact current generation, owner, epoch and original lease
// expiry against primary database time. Success is a point-in-time ownership
// check only, not a durable effect permit or permission to publish health later.
// Expired, superseded, retired, foreign or ambiguous state is unavailable.
func (r VelocityRecovery) CheckLease(ctx context.Context, lease VelocityRecoveryLease) error {
	_, err := r.lease(ctx, lease, false)
	return err
}

// Renew extends only the exact live lease under primary locks and returns its
// superseding receipt after acknowledged commit. Concurrent renewal has one
// winner. Expired leases cannot renew or use local time to regain ownership.
// No cursor, history, generation, external result or epoch health is changed.
// A prepared closure is invalidated and journal evidence admission reopens.
func (r VelocityRecovery) Renew(ctx context.Context, lease VelocityRecoveryLease) (VelocityRecoveryLease, error) {
	return r.lease(ctx, lease, true)
}

func (r VelocityRecovery) lease(ctx context.Context, lease VelocityRecoveryLease, renew bool) (VelocityRecoveryLease, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state {
		return VelocityRecoveryLease{}, identity.InvalidInputError{Field: "velocity_recovery"}
	}
	s, l := r.state, lease.state
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityRecoveryLease{}, err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return VelocityRecoveryLease{}, err
	}
	now, err := s.liveLease(bounded, tx, l)
	if err != nil {
		return VelocityRecoveryLease{}, err
	}
	expires := l.expires
	if renew {
		expires = now.Add(s.leaseDuration)
		if !expires.After(l.expires) {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
		if _, err := tx.Exec(bounded, `UPDATE `+s.journal.schema+`.velocity_epochs SET lease_expires_at=$4,replay_through=replay_from WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3`, l.tenant, s.journal.namespace, l.epoch[:], expires); err != nil {
			return VelocityRecoveryLease{}, identity.UnavailableError{}
		}
		if err := s.clearPublication(bounded, tx, l.tenant, l.epoch); err != nil {
			return VelocityRecoveryLease{}, err
		}
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityRecoveryLease{}, identity.UnavailableError{}
	}
	return VelocityRecoveryLease{state: &velocityRecoveryLease{owner: s, tenant: l.tenant, epoch: l.epoch, token: l.token, generation: l.generation, expires: expires}}, nil
}

func (s *velocityRecovery) liveLease(ctx context.Context, tx pgx.Tx, l *velocityRecoveryLease) (time.Time, error) {
	var token []byte
	var expires time.Time
	var window int64
	err := tx.QueryRow(ctx, `SELECT lease_owner,lease_expires_at,maximum_window_us FROM `+s.journal.schema+`.velocity_epochs WHERE tenant_id=$1 AND namespace_digest=$2 AND epoch=$3 AND generation=$4::numeric AND state='replaying' FOR UPDATE`, l.tenant, s.journal.namespace, l.epoch[:], strconv.FormatUint(l.generation, 10)).Scan(&token, &expires, &window)
	if err != nil || !hmac.Equal(token, l.token[:]) || !expires.Equal(l.expires) || window != s.maximumWindow.Microseconds() {
		return time.Time{}, identity.UnavailableError{}
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !now.Before(expires) {
		return time.Time{}, identity.UnavailableError{}
	}
	return now, nil
}

func (s *velocityRecovery) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, identity.InvalidInputError{Field: "context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.journal.timeout)
	return bounded, cancel, nil
}

func (s *velocityRecovery) lock(ctx context.Context, tx pgx.Tx, tenant string) error {
	return s.journal.scopeLock(ctx, tx, tenant, false)
}
