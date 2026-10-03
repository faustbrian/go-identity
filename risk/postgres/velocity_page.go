package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// VelocityReplayOutcome preserves journal classification, not external truth.
// Pending and Unknown never mean noncommit or retry permission. Zero is invalid.
type VelocityReplayOutcome uint8

const (
	VelocityReplayPending VelocityReplayOutcome = iota + 1
	VelocityReplayCommitted
	VelocityReplayNotCommitted
	VelocityReplayUnknown
)

// VelocityReplayProjection is a copied owned-adapter view, never HTTP data or
// CounterCommand authority. ID is a stable keyed opaque logical-record identity;
// it reveals neither raw attempt nor stored fingerprint. Targets retain all
// original ordered aliases; Snapshot retains original values and windows.
type VelocityReplayProjection struct {
	ID                     string
	Operation              risk.Action
	Phase                  risk.Phase
	PolicyVersion          uint64
	PreparedAt, RecordedAt time.Time
	Window                 time.Duration
	Limit                  uint64
	Outcome                VelocityReplayOutcome
	Targets                []risk.CounterTarget
	Snapshot               []risk.Counter
}

// VelocityReplayRecord is immutable authenticated history from one acknowledged
// page. It cannot be constructed or serialized, and is not effect permission.
type VelocityReplayRecord struct{ state *velocityReplayRecord }
type velocityReplayRecord struct{ projection VelocityReplayProjection }

// Projection returns independent target/key/snapshot slices; zero is invalid.
func (r VelocityReplayRecord) Projection() VelocityReplayProjection {
	if r.state == nil {
		return VelocityReplayProjection{}
	}
	b := r.state.projection
	b.Targets = slices.Clone(b.Targets)
	for i := range b.Targets {
		b.Targets[i].Keys = slices.Clone(b.Targets[i].Keys)
	}
	b.Snapshot = slices.Clone(b.Snapshot)
	return b
}

// VelocityReplayCursor is exact recovery-instance/scope/epoch/generation custody
// of a change position. Zero starts the retained history. Renewal within the
// same generation accepts the cursor with the NEW lease; old leases still deny.
// Takeover or another recovery instance cannot reuse it. It proves no effects.
type VelocityReplayCursor struct{ state *velocityReplayCursor }
type velocityReplayCursor struct {
	owner    *velocityRecovery
	lease    *velocityRecoveryLease
	position int64
}

// VelocityReplayPage contains at most the requested batch. Empty is only an
// observation: later insertions/declarations remain discoverable with Next.
// No method publishes health, advances applied progress or dispatches effects.
type VelocityReplayPage struct{ state *velocityReplayPage }
type velocityReplayPage struct {
	records []VelocityReplayRecord
	next    VelocityReplayCursor
}

// Records returns an independent slice of immutable records. Zero returns nil.
func (p VelocityReplayPage) Records() []VelocityReplayRecord {
	if p.state == nil {
		return nil
	}
	return slices.Clone(p.state.records)
}

// Next returns opaque continuation custody; zero page has no usable successor.
func (p VelocityReplayPage) Next() VelocityReplayCursor {
	if p.state == nil {
		return VelocityReplayCursor{}
	}
	return p.state.next
}

func (VelocityReplayProjection) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityReplayProjection(redacted)")
}
func (VelocityReplayProjection) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityReplayProjection) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityReplayRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityReplayRecord(redacted)")
}
func (VelocityReplayRecord) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityReplayRecord) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityReplayCursor) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityReplayCursor(redacted)")
}
func (VelocityReplayCursor) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityReplayCursor) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityReplayPage) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.VelocityReplayPage(redacted)")
}
func (VelocityReplayPage) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityReplayPage) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// ReadPage drains overlapping native writers and reads changes AFTER the opaque
// cursor under the exact live primary lease. Batches are 1..1000 (reference100).
// It reads all retained history, including expired original snapshots: storage
// time cannot exclude unknown/pending work or refresh original counter windows.
// Each insertion/first declaration receives a new authenticated change position;
// identical terminal replay does not. An empty page is never stable closure.
// Pre-positioned authenticated history is initialized in bounded native batches,
// without changing original facts/times. Unsealed/corrupt history fails closed.
// Scoped locks remain inside Timeout, never span callbacks or external effects.
// A failed/cancelled/expired/ambiguous transaction returns no records or cursor.
func (r VelocityRecovery) ReadPage(ctx context.Context, lease VelocityRecoveryLease, cursor VelocityReplayCursor, batch int) (VelocityReplayPage, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state || batch < 1 || batch > 1000 {
		return VelocityReplayPage{}, identity.InvalidInputError{Field: "velocity_replay"}
	}
	s, l := r.state, lease.state
	position := int64(0)
	if c := cursor.state; c != nil {
		if c.owner != s || c.lease == nil || c.lease.tenant != l.tenant || c.lease.epoch != l.epoch || c.lease.generation != l.generation || c.lease.token != l.token || c.position < 0 {
			return VelocityReplayPage{}, identity.InvalidInputError{Field: "velocity_replay"}
		}
		position = c.position
	}
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return VelocityReplayPage{}, err
	}
	defer cancel()
	// Read committed is deliberate: a repeatable snapshot established by the
	// advisory-lock statement could predate writer commits drained by that lock.
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return VelocityReplayPage{}, err
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return VelocityReplayPage{}, err
	}
	rows, err := tx.Query(bounded, `SELECT sequence FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position IS NULL ORDER BY sequence LIMIT $3`, l.tenant, s.journal.namespace, batch)
	if err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	var legacy []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			rows.Close()
			return VelocityReplayPage{}, identity.UnavailableError{}
		}
		legacy = append(legacy, seq)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	for _, seq := range legacy {
		if err := s.journal.checkVelocitySeal(bounded, tx, seq); err != nil {
			return VelocityReplayPage{}, err
		}
		if err := s.journal.sealVelocity(bounded, tx, seq); err != nil {
			return VelocityReplayPage{}, err
		}
	}
	rows, err = tx.Query(bounded, `SELECT sequence,replay_position FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND replay_position>$3 ORDER BY replay_position LIMIT $4`, l.tenant, s.journal.namespace, position, batch)
	if err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	type selected struct{ sequence, position int64 }
	var selectedRows []selected
	for rows.Next() {
		var v selected
		if err := rows.Scan(&v.sequence, &v.position); err != nil {
			rows.Close()
			return VelocityReplayPage{}, identity.UnavailableError{}
		}
		selectedRows = append(selectedRows, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	var records []VelocityReplayRecord
	for _, v := range selectedRows {
		record, err := s.readReplayRecord(bounded, tx, l.tenant, v.sequence, v.position)
		if err != nil {
			return VelocityReplayPage{}, err
		}
		records = append(records, record)
		position = v.position
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return VelocityReplayPage{}, err
	}
	if err := tx.Commit(bounded); err != nil {
		return VelocityReplayPage{}, identity.UnavailableError{}
	}
	next := VelocityReplayCursor{state: &velocityReplayCursor{owner: s, lease: l, position: position}}
	return VelocityReplayPage{state: &velocityReplayPage{records: records, next: next}}, nil
}

func (s *velocityRecovery) readReplayRecord(ctx context.Context, tx pgx.Tx, tenant string, sequence, position int64) (VelocityReplayRecord, error) {
	if err := s.journal.checkVelocitySeal(ctx, tx, sequence); err != nil {
		return VelocityReplayRecord{}, err
	}
	var b VelocityReplayProjection
	var phase, policy, limit, outcome string
	var window int64
	var seal, positionSeal []byte
	err := tx.QueryRow(ctx, `SELECT operation,phase,policy_version::text,prepared_at,recorded_at,window_us,attempt_limit::text,outcome,replay_seal,position_seal FROM `+s.journal.schema+`.velocity_attempts WHERE tenant_id=$1 AND namespace_digest=$2 AND sequence=$3 AND replay_position=$4`, tenant, s.journal.namespace, sequence, position).Scan(&b.Operation, &phase, &policy, &b.PreparedAt, &b.RecordedAt, &window, &limit, &outcome, &seal, &positionSeal)
	if err != nil || !hmac.Equal(positionSeal, s.journal.velocityPositionSeal(sequence, position, seal)) {
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	b.PolicyVersion, err = strconv.ParseUint(policy, 10, 64)
	if err != nil || b.PolicyVersion == 0 || window <= 0 || window > time.Hour.Microseconds() {
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	b.Limit, err = strconv.ParseUint(limit, 10, 64)
	if err != nil || b.Limit == 0 || b.Limit > 120 {
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	b.Phase = risk.Phase(phase)
	b.Window = time.Duration(window) * time.Microsecond
	b.ID = base64.RawURLEncoding.EncodeToString(velocityMAC(s.journal.key, "identity-risk-velocity-replay-id-v1", string(s.journal.namespace), tenant, strconv.FormatInt(sequence, 10)))
	switch outcome {
	case "pending":
		b.Outcome = VelocityReplayPending
	case "committed":
		b.Outcome = VelocityReplayCommitted
	case "not_committed":
		b.Outcome = VelocityReplayNotCommitted
	case "unknown":
		b.Outcome = VelocityReplayUnknown
	default:
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	targets, err := s.readReplayTargets(ctx, tx, sequence, b.Phase, b.Window)
	if err != nil {
		return VelocityReplayRecord{}, err
	}
	b.Targets = targets
	rows, err := tx.Query(ctx, `SELECT dimension,value::text,observed_at,started_at,expires_at FROM `+s.journal.schema+`.velocity_snapshots WHERE sequence=$1 ORDER BY dimension LIMIT 5`, sequence)
	if err != nil {
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	seen := make(map[string]bool, 4)
	for rows.Next() {
		var v risk.Counter
		var value string
		if err := rows.Scan(&v.Kind, &value, &v.ObservedAt, &v.WindowStartedAt, &v.WindowExpiresAt); err != nil {
			rows.Close()
			return VelocityReplayRecord{}, identity.UnavailableError{}
		}
		v.Value, err = strconv.ParseUint(value, 10, 64)
		matched := false
		for _, target := range targets {
			if v.Kind == string(target.Dimension) {
				matched = true
			}
		}
		if err != nil || !matched || seen[v.Kind] || len(b.Snapshot) >= 4 {
			rows.Close()
			return VelocityReplayRecord{}, identity.UnavailableError{}
		}
		seen[v.Kind] = true
		b.Snapshot = append(b.Snapshot, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !velocitySnapshotsValid(risk.CounterBinding{Window: b.Window}, b.Snapshot) || (b.Outcome == VelocityReplayCommitted && len(b.Snapshot) != len(targets)) || (b.Outcome != VelocityReplayCommitted && len(b.Snapshot) != 0) {
		return VelocityReplayRecord{}, identity.UnavailableError{}
	}
	return VelocityReplayRecord{state: &velocityReplayRecord{projection: b}}, nil
}

func (s *velocityRecovery) readReplayTargets(ctx context.Context, tx pgx.Tx, sequence int64, phase risk.Phase, window time.Duration) ([]risk.CounterTarget, error) {
	dimensions := []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}
	if phase == risk.BeforeReturn {
		dimensions = []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}
	} else if phase != risk.BeforeCredential {
		return nil, identity.UnavailableError{}
	}
	rows, err := tx.Query(ctx, `SELECT t.dimension,t.phase,t.window_us,a.key_rank,a.key_version,a.key_id FROM `+s.journal.schema+`.velocity_targets t LEFT JOIN `+s.journal.schema+`.velocity_aliases a USING(sequence,dimension) WHERE t.sequence=$1 ORDER BY t.dimension,a.key_rank LIMIT 17`, sequence)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	byDimension := make(map[risk.Dimension][]risk.CounterKey, 4)
	count := 0
	for rows.Next() {
		var dimension, storedPhase, key string
		var storedWindow, rank, version int64
		if err := rows.Scan(&dimension, &storedPhase, &storedWindow, &rank, &version, &key); err != nil {
			rows.Close()
			return nil, identity.UnavailableError{}
		}
		d := risk.Dimension(dimension)
		previous := byDimension[d]
		count++
		prefix := "rv1:" + strconv.FormatInt(version, 10) + ":"
		validKey := false
		if len(key) == len(prefix)+43 && len(key) <= 58 && key[:len(prefix)] == prefix {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(key[len(prefix):])
			validKey = err == nil && len(decoded) == 32
		}
		if count > 16 || !slices.Contains(dimensions, d) || storedPhase != string(phase) || storedWindow != window.Microseconds() || rank != int64(len(previous)+1) || rank > 4 || version <= 0 || version > int64(^uint32(0)) || len(previous) > 0 && previous[len(previous)-1].Version <= uint32(version) || !validKey {
			rows.Close()
			return nil, identity.UnavailableError{}
		}
		byDimension[d] = append(previous, risk.CounterKey{Version: uint32(version), Encoded: key})
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(byDimension) != len(dimensions) {
		return nil, identity.UnavailableError{}
	}
	var result []risk.CounterTarget
	aliases := 0
	for _, d := range dimensions {
		keys := byDimension[d]
		if len(keys) == 0 || aliases > 0 && len(keys) != aliases {
			return nil, identity.UnavailableError{}
		}
		aliases = len(keys)
		result = append(result, risk.CounterTarget{Dimension: d, Keys: keys})
	}
	return result, nil
}
