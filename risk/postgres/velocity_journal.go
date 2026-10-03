package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// VelocityJournalConfig selects a caller-owned primary pool and migrated risk
// schema. Namespace identifies a stable deployment/projection, not a request.
// JournalKey is a separately retained 32..128-byte HMAC key; replacing it would
// lose replay identity and is not supported. Policy and complete newest-first
// Keys must be the exact values used by the ephemeral coordinator. Timeout is
// positive and at most one minute. Construction copies keys without IO.
type VelocityJournalConfig struct {
	Pool              *database.Pool
	Schema, Namespace string
	JournalKey        []byte
	Policy            risk.Policy
	Keys              []risk.CounterDigestKey
	Timeout           time.Duration
}

func (VelocityJournalConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityJournalConfig(redacted)")
}
func (VelocityJournalConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityJournalConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// VelocityJournal owns durable ephemeral intent, not Valkey mutation, lockouts,
// healthy epochs or protected identity transactions. It starts no goroutines and
// never closes the caller's pool. Immutable configuration permits concurrent
// calls; zero is invalid. Native completion and reconciliation remain separate.
type VelocityJournal struct{ state *velocityJournal }
type velocityJournal struct {
	pool      *database.Pool
	schema    string
	namespace []byte
	key       []byte
	policy    risk.Policy
	keys      []risk.CounterDigestKey
	timeout   time.Duration
}

func (VelocityJournal) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityJournal(redacted)")
}
func (VelocityJournal) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityJournal) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// VelocityAttempt is a private journal receipt for one confirmed intent commit.
// It is not dispatch, allowance, retry, epoch-health or counter-commit authority.
// Unknown commits return no receipt. It cannot be exported or caller-constructed.
type VelocityAttempt struct{ state *velocityAttempt }
type velocityAttempt struct {
	owner    *velocityJournal
	sequence int64
	command  risk.CounterCommand
}

func (VelocityAttempt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityAttempt(redacted)")
}
func (VelocityAttempt) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityAttempt) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// NewVelocityJournal validates copied local custody without pool access. The
// schema must include VelocityIntentMigrationSource. No store is enabled by
// successful construction; mismatches fail with redacted ErrInvalidPolicy.
func NewVelocityJournal(c VelocityJournalConfig) (VelocityJournal, error) {
	if c.Pool == nil || c.Pool.Raw() == nil || !validSchema(c.Schema) || !velocityNamespace(c.Namespace) || len(c.JournalKey) < 32 || len(c.JournalKey) > 128 || bytes.Equal(c.JournalKey, make([]byte, len(c.JournalKey))) || c.Timeout <= 0 || c.Timeout > time.Minute || len(c.Keys) == 0 || len(c.Keys) > 4 {
		return VelocityJournal{}, risk.ErrInvalidPolicy
	}
	if _, err := c.Policy.Admit("identity.password.signin"); err != nil {
		return VelocityJournal{}, risk.ErrInvalidPolicy
	}
	for i, k := range c.Keys {
		if k.Version() == 0 || i > 0 && c.Keys[i-1].Version() <= k.Version() {
			return VelocityJournal{}, risk.ErrInvalidPolicy
		}
	}
	key := slices.Clone(c.JournalKey)
	return VelocityJournal{state: &velocityJournal{pool: c.Pool, schema: pgx.Identifier{c.Schema}.Sanitize(), namespace: velocityMAC(key, "identity-risk-velocity-namespace-v1", c.Namespace), key: key, policy: c.Policy, keys: slices.Clone(c.Keys), timeout: c.Timeout}}, nil
}

func velocityNamespace(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}
func velocityMAC(key []byte, domain string, fields ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, s := range append([]string{domain}, fields...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		_, _ = m.Write(size[:])
		_, _ = m.Write([]byte(s))
	}
	return m.Sum(nil)
}

// RecordAttempt durably inserts one authenticated pending attempt and all exact
// target aliases in a short transaction before external work. It writes no
// snapshot or epoch and never invokes another store. Raw attempt/subject facts
// are not persisted. PreparedAt is rounded upward to PostgreSQL microseconds,
// and future preparation or sub-microsecond windows deny before insertion.
// Existing matching pending attempts remain unavailable; changed fingerprints
// fail with ErrInvalidCounterCommand. Neither expiry nor replay permits another
// dispatch. Every database/commit failure returns a redacted UnavailableError
// without a receipt, including commit ambiguity; callers must not retry effects.
func (j VelocityJournal) RecordAttempt(ctx context.Context, c risk.CounterCommand) (VelocityAttempt, error) {
	if j.state == nil || c.ValidateConfiguration(j.state.policy, j.state.keys) != nil {
		return VelocityAttempt{}, risk.ErrInvalidCounterCommand
	}
	if ctx == nil {
		return VelocityAttempt{}, identity.InvalidInputError{Field: "context"}
	}
	if err := ctx.Err(); err != nil {
		return VelocityAttempt{}, err
	}
	s := j.state
	b := c.Bindings()
	if b.Window%time.Microsecond != 0 {
		return VelocityAttempt{}, risk.ErrInvalidCounterCommand
	}
	fingerprint, err := hex.DecodeString(b.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return VelocityAttempt{}, risk.ErrInvalidCounterCommand
	}
	prepared := b.PreparedAt.UTC().Truncate(time.Microsecond)
	if prepared.Before(b.PreparedAt) {
		prepared = prepared.Add(time.Microsecond)
	}
	digest := velocityMAC(s.key, "identity-risk-velocity-attempt-v1", hex.EncodeToString(s.namespace), b.Tenant, string(b.Operation), string(b.Phase), b.Attempt)
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tx, err := s.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityAttempt{}, identity.UnavailableError{}
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	}()
	var now time.Time
	if err = tx.QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return VelocityAttempt{}, identity.UnavailableError{}
	}
	if prepared.After(now) {
		return VelocityAttempt{}, risk.ErrInvalidCounterCommand
	}
	var sequence int64
	err = tx.QueryRow(bounded, `INSERT INTO `+s.schema+`.velocity_attempts(tenant_id,namespace_digest,operation,phase,policy_version,attempt_digest,counter_fingerprint,prepared_at,recorded_at,window_us,attempt_limit,outcome) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11,'pending') ON CONFLICT(tenant_id,namespace_digest,operation,phase,attempt_digest) DO NOTHING RETURNING sequence`, b.Tenant, s.namespace, string(b.Operation), string(b.Phase), strconv.FormatUint(b.PolicyVersion, 10), digest, fingerprint, prepared, now, b.Window.Microseconds(), int64(b.Limit)).Scan(&sequence)
	if err == pgx.ErrNoRows {
		var previous []byte
		if err = tx.QueryRow(bounded, `SELECT counter_fingerprint FROM `+s.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND operation=$3 AND phase=$4 AND attempt_digest=$5`, b.Tenant, s.namespace, string(b.Operation), string(b.Phase), digest).Scan(&previous); err != nil {
			return VelocityAttempt{}, identity.UnavailableError{}
		}
		if !hmac.Equal(previous, fingerprint) {
			return VelocityAttempt{}, risk.ErrInvalidCounterCommand
		}
		return VelocityAttempt{}, identity.UnavailableError{}
	}
	if err != nil {
		return VelocityAttempt{}, identity.UnavailableError{}
	}
	for _, target := range b.Targets {
		if _, err = tx.Exec(bounded, `INSERT INTO `+s.schema+`.velocity_targets(sequence,phase,window_us,dimension) VALUES($1,$2,$3,$4)`, sequence, string(b.Phase), b.Window.Microseconds(), string(target.Dimension)); err != nil {
			return VelocityAttempt{}, identity.UnavailableError{}
		}
		for rank, key := range target.Keys {
			if _, err = tx.Exec(bounded, `INSERT INTO `+s.schema+`.velocity_aliases(sequence,dimension,key_rank,key_version,key_id) VALUES($1,$2,$3,$4,$5)`, sequence, string(target.Dimension), rank+1, int64(key.Version), key.Encoded); err != nil {
				return VelocityAttempt{}, identity.UnavailableError{}
			}
		}
	}
	if err = tx.Commit(bounded); err != nil {
		return VelocityAttempt{}, identity.UnavailableError{}
	}
	return VelocityAttempt{state: &velocityAttempt{owner: s, sequence: sequence, command: c}}, nil
}
