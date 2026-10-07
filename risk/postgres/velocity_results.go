package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// RecordResult atomically retains a configured ephemeral adapter's explicit
// declaration and original snapshots. The exact confirmed attempt receipt is
// required; journal durability does not establish truth of an external result.
// Pending may become committed, not-committed or unknown. Every terminal state
// is immutable, including unknown; identical declarations are idempotent.
// Snapshots must use exact full windows and microsecond-representable times;
// values/freshness are never rounded or renewed. No Valkey dispatch, retry,
// health publication or recovery proof is granted. Database/commit ambiguity
// returns UnavailableError and must not be interpreted as external noncommit.
// Its shared scope lock precedes attempt-row locks and remains until transaction
// resolution. Recovery acquisition drains overlapping declarations but does not
// discard later evidence or turn an explicit declaration into external truth.
func (j VelocityJournal) RecordResult(ctx context.Context, a VelocityAttempt, outcome risk.CounterOutcome, snapshot []risk.Counter) error {
	if j.state == nil || a.state == nil || a.state.owner != j.state || a.state.command.ValidateConfiguration(j.state.policy, j.state.keys) != nil {
		return risk.ErrInvalidCounterCommand
	}
	c := a.state.command
	b := c.Bindings()
	if len(snapshot) > len(b.Targets) {
		return risk.ErrInvalidCounterResult
	}
	snapshot = slices.Clone(snapshot)
	if _, err := risk.NewCounterResult(c, outcome, snapshot); err != nil {
		return err
	}
	if !velocitySnapshotsValid(b, snapshot) {
		return risk.ErrInvalidCounterResult
	}
	if ctx == nil {
		return identity.InvalidInputError{Field: "context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := j.state
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tx, err := s.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.scopeLock(bounded, tx, b.Tenant, true); err != nil {
		return err
	}
	sequence, state, stored, err := s.velocityRead(bounded, tx, c, true)
	if err != nil {
		return err
	}
	if sequence != a.state.sequence {
		return risk.ErrInvalidCounterCommand
	}
	name := velocityOutcomeName(outcome)
	if state != "pending" {
		if state != name || !velocitySnapshotsEqual(snapshot, stored) {
			return risk.ErrInvalidCounterResult
		}
		return nil
	}
	for _, counter := range snapshot {
		if _, err = tx.Exec(bounded, `INSERT INTO `+s.schema+`.velocity_snapshots(sequence,phase,window_us,dimension,value,observed_at,started_at,expires_at) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8)`, sequence, string(b.Phase), b.Window.Microseconds(), counter.Kind, strconv.FormatUint(counter.Value, 10), counter.ObservedAt, counter.WindowStartedAt, counter.WindowExpiresAt); err != nil {
			return identity.UnavailableError{}
		}
	}
	if _, err = tx.Exec(bounded, `UPDATE `+s.schema+`.velocity_attempts SET outcome=$1 WHERE sequence=$2 AND outcome='pending'`, name, sequence); err != nil {
		return identity.UnavailableError{}
	}
	if err := s.sealVelocity(bounded, tx, sequence); err != nil {
		return err
	}
	if err = tx.Commit(bounded); err != nil {
		return identity.UnavailableError{}
	}
	return nil
}

// ReadResult reconstructs an exact authenticated historical terminal result
// from primary authority. It preserves original timestamps and classification,
// not current positive validity; the core consumes freshness separately.
// Pending/missing/corrupt/unsealed history is unavailable. Explicit unknown remains
// unknown, never noncommit or retry permission. The transaction is bounded,
// read-only and repeatable; no callbacks, effects or epoch mutations occur.
func (j VelocityJournal) ReadResult(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	if j.state == nil || c.ValidateConfiguration(j.state.policy, j.state.keys) != nil {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	if ctx == nil {
		return risk.CounterResult{}, identity.InvalidInputError{Field: "context"}
	}
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	s := j.state
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tx, err := s.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	_, state, snapshot, err := s.velocityRead(bounded, tx, c, false)
	if err != nil {
		return risk.CounterResult{}, err
	}
	outcome := velocityOutcome(state)
	if outcome == 0 {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	result, err := risk.NewCounterResult(c, outcome, snapshot)
	if err != nil {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	if err = tx.Commit(bounded); err != nil {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	return result, nil
}

func velocityRollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func velocityOutcomeName(o risk.CounterOutcome) string {
	switch o {
	case risk.CounterCommitted:
		return "committed"
	case risk.CounterNotCommitted:
		return "not_committed"
	case risk.CounterUnknown:
		return "unknown"
	}
	return ""
}
func velocityOutcome(s string) risk.CounterOutcome {
	switch s {
	case "committed":
		return risk.CounterCommitted
	case "not_committed":
		return risk.CounterNotCommitted
	case "unknown":
		return risk.CounterUnknown
	}
	return 0
}
func velocitySnapshotsValid(b risk.CounterBinding, snapshot []risk.Counter) bool {
	for _, v := range snapshot {
		if v.WindowExpiresAt.Sub(v.WindowStartedAt) != b.Window || v.ObservedAt.Before(v.WindowStartedAt) || !v.ObservedAt.Before(v.WindowExpiresAt) {
			return false
		}
		for _, t := range []time.Time{v.ObservedAt, v.WindowStartedAt, v.WindowExpiresAt} {
			if t.Nanosecond()%1000 != 0 {
				return false
			}
		}
	}
	return true
}
func velocitySnapshotsEqual(a, b []risk.Counter) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		found := false
		for _, w := range b {
			if v.Kind == w.Kind && v.Value == w.Value && v.ObservedAt.Equal(w.ObservedAt) && v.WindowStartedAt.Equal(w.WindowStartedAt) && v.WindowExpiresAt.Equal(w.WindowExpiresAt) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// The attempt lock serializes terminal declarations. Alias and snapshot reads
// are bounded independently; constraints alone do not establish completeness.
func (s *velocityJournal) velocityRead(ctx context.Context, tx pgx.Tx, c risk.CounterCommand, lock bool) (int64, string, []risk.Counter, error) {
	b := c.Bindings()
	digest, err := s.replay.Attempt(c)
	if err != nil {
		return 0, "", nil, err
	}
	query := `SELECT sequence,outcome,counter_fingerprint FROM ` + s.schema + `.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND operation=$3 AND phase=$4 AND policy_version=$5::numeric AND attempt_digest=$6 AND window_us=$7 AND attempt_limit=$8`
	if lock {
		query += ` FOR UPDATE`
	}
	var sequence int64
	var state string
	var fingerprint []byte
	if err := tx.QueryRow(ctx, query, b.Tenant, s.namespace, string(b.Operation), string(b.Phase), strconv.FormatUint(b.PolicyVersion, 10), digest[:], b.Window.Microseconds(), int64(b.Limit)).Scan(&sequence, &state, &fingerprint); err != nil {
		return 0, "", nil, identity.UnavailableError{}
	}
	expected, _ := hex.DecodeString(b.Fingerprint)
	if !hmac.Equal(expected, fingerprint) {
		return 0, "", nil, risk.ErrInvalidCounterCommand
	}
	rows, err := tx.Query(ctx, `SELECT t.dimension,t.phase,t.window_us,a.key_rank,a.key_version,a.key_id FROM `+s.schema+`.velocity_targets t LEFT JOIN `+s.schema+`.velocity_aliases a USING(sequence,dimension) WHERE t.sequence=$1 ORDER BY t.dimension,a.key_rank LIMIT 17`, sequence)
	if err != nil {
		return 0, "", nil, identity.UnavailableError{}
	}
	seen := make(map[string]bool, 16)
	expectedCount := 0
	for _, target := range b.Targets {
		expectedCount += len(target.Keys)
	}
	for rows.Next() {
		var dimension, phase, key string
		var window, rank, version int64
		if err = rows.Scan(&dimension, &phase, &window, &rank, &version, &key); err != nil {
			rows.Close()
			return 0, "", nil, identity.UnavailableError{}
		}
		matched := false
		for _, target := range b.Targets {
			if dimension == string(target.Dimension) && rank >= 1 && rank <= int64(len(target.Keys)) {
				k := target.Keys[rank-1]
				matched = key == k.Encoded && version == int64(k.Version)
			}
		}
		id := dimension + ":" + strconv.FormatInt(rank, 10)
		if !matched || seen[id] || phase != string(b.Phase) || window != b.Window.Microseconds() {
			rows.Close()
			return 0, "", nil, identity.UnavailableError{}
		}
		seen[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(seen) != expectedCount {
		return 0, "", nil, identity.UnavailableError{}
	}
	rows, err = tx.Query(ctx, `SELECT dimension,value::text,observed_at,started_at,expires_at FROM `+s.schema+`.velocity_snapshots WHERE sequence=$1 ORDER BY dimension LIMIT 5`, sequence)
	if err != nil {
		return 0, "", nil, identity.UnavailableError{}
	}
	var snapshot []risk.Counter
	for rows.Next() {
		var v risk.Counter
		var value string
		if err = rows.Scan(&v.Kind, &value, &v.ObservedAt, &v.WindowStartedAt, &v.WindowExpiresAt); err != nil {
			rows.Close()
			return 0, "", nil, identity.UnavailableError{}
		}
		v.Value, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			rows.Close()
			return 0, "", nil, identity.UnavailableError{}
		}
		snapshot = append(snapshot, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !velocitySnapshotsValid(b, snapshot) {
		return 0, "", nil, identity.UnavailableError{}
	}
	if state == "pending" {
		if len(snapshot) != 0 {
			return 0, "", nil, identity.UnavailableError{}
		}
	} else {
		if _, err = risk.NewCounterResult(c, velocityOutcome(state), snapshot); err != nil {
			return 0, "", nil, identity.UnavailableError{}
		}
	}
	if err := s.checkVelocitySeal(ctx, tx, sequence); err != nil {
		return 0, "", nil, err
	}
	return sequence, state, snapshot, nil
}
