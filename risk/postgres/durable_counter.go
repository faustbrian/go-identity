package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
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

// DurableCounterConfig selects one durable PostgreSQL admission authority.
// Namespace and ReplayKey are stable deployment custody, not rotation knobs.
// Keys are complete newest-first dimension-key history; Tenants is an explicit
// allowlist of 1..128 scopes. MaximumRecords is 1..1000000 retained attempts per
// tenant: reaching capacity denies, never evicts replay history or resets quotas.
// Timeout is 1ms..1min. Install DurableCounterMigrationSource before use.
type DurableCounterConfig struct {
	Pool              *database.Pool
	Schema, Namespace string
	Policy            risk.Policy
	Keys              []risk.CounterDigestKey
	ReplayKey         []byte
	Tenants           []string
	MaximumRecords    int64
	Timeout           time.Duration
}

func (DurableCounterConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.DurableCounterConfig(redacted)")
}
func (DurableCounterConfig) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (DurableCounterConfig) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// DurableCounterStore implements the core CounterStore with database-owned
// fixed windows and atomic retained outcomes. This durable lane is disjoint
// from the optional ephemeral Valkey lane and protected-command participants.
// It performs no external callback, starts no goroutines and borrows its pool.
// Copies are concurrent-safe. Cancellation/SQL/commit ambiguity denies with no
// positive result; matching retry reads the original committed timestamps and
// never charges twice. Expiry does not delete original replay history.
type DurableCounterStore struct{ state *durableCounterState }
type durableCounterState struct {
	config  DurableCounterConfig
	schema  string
	tenants map[string]bool
	replay  risk.VelocityReplayIdentity
}

var _ risk.CounterStore = DurableCounterStore{}

func (DurableCounterStore) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.DurableCounterStore(redacted)")
}
func (DurableCounterStore) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (DurableCounterStore) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// NewDurableCounterStore validates/copies custody without IO or admission.
// A changed stable key fails against durable scope identity on first use.
func NewDurableCounterStore(c DurableCounterConfig) (DurableCounterStore, error) {
	if c.Pool == nil || c.Pool.Raw() == nil || !validSchema(c.Schema) || c.Timeout < time.Millisecond || c.Timeout > time.Minute || c.MaximumRecords < 1 || c.MaximumRecords > 1000000 || len(c.Keys) < 1 || len(c.Keys) > 4 || len(c.Tenants) < 1 || len(c.Tenants) > 128 {
		return DurableCounterStore{}, risk.ErrInvalidPolicy
	}
	replay, err := risk.NewVelocityReplayIdentity(c.Namespace, c.ReplayKey)
	if err != nil {
		return DurableCounterStore{}, err
	}
	if _, err := c.Policy.Admit("identity.password.signin"); err != nil {
		return DurableCounterStore{}, risk.ErrInvalidPolicy
	}
	for i, key := range c.Keys {
		if key.Version() == 0 || i > 0 && c.Keys[i-1].Version() <= key.Version() {
			return DurableCounterStore{}, risk.ErrInvalidPolicy
		}
	}
	tenants := make(map[string]bool, len(c.Tenants))
	for _, tenant := range c.Tenants {
		if !velocityNamespace(tenant) || tenants[tenant] {
			return DurableCounterStore{}, risk.ErrInvalidPolicy
		}
		tenants[tenant] = true
	}
	c.ReplayKey, c.Keys, c.Tenants = slices.Clone(c.ReplayKey), slices.Clone(c.Keys), slices.Clone(c.Tenants)
	return DurableCounterStore{state: &durableCounterState{config: c, schema: pgx.Identifier{c.Schema}.Sanitize(), tenants: tenants, replay: replay}}, nil
}

// Check observes the selected scope's current stable custody and capacity
// without debiting a counter or extending evidence. Missing fresh scope is
// eligible only after the native tables exist. Changed keys, corruption,
// capacity exhaustion and unavailable primary authority fail closed.
func (s DurableCounterStore) Check(ctx context.Context, tenant string) error {
	if s.state == nil || ctx == nil || !s.state.tenants[tenant] {
		return risk.ErrInvalidPolicy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := s.state
	bounded, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	var marker []byte
	var records int64
	err := p.config.Pool.Raw().QueryRow(bounded, `SELECT key_marker,records FROM `+p.schema+`.durable_counter_scopes WHERE namespace=$1 AND tenant_id=$2`, p.config.Namespace, tenant).Scan(&marker, &records)
	if err == pgx.ErrNoRows {
		return nil
	}
	expected := velocityMAC(p.config.ReplayKey, "identity-risk-durable-scope-v1", p.config.Namespace, tenant)
	if err != nil || records < 0 || records >= p.config.MaximumRecords || !hmac.Equal(expected, marker) {
		return identity.UnavailableError{}
	}
	return nil
}

// Mutate charges every target once in one PostgreSQL transaction, including
// denied attempts. Conflicting replay, missing/changed retained keys, corrupt
// history, exhausted capacity and unavailable authority return no allowance.
// Original results remain historical facts; core admission enforces freshness.
func (s DurableCounterStore) Mutate(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
	if s.state == nil || ctx == nil {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	p := s.state
	if command.ValidateConfiguration(p.config.Policy, p.config.Keys) != nil {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	b := command.Bindings()
	if !p.tenants[b.Tenant] || b.Window%time.Microsecond != 0 {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	attempt, err := p.replay.Attempt(command)
	if err != nil {
		return risk.CounterResult{}, err
	}
	fingerprint, err := hex.DecodeString(b.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	bounded, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	tx, err := p.config.Pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	result, err := p.mutate(bounded, tx, command, attempt[:], fingerprint)
	if err != nil {
		return risk.CounterResult{}, err
	}
	if err := tx.Commit(bounded); err != nil {
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	return result, nil
}

func (s *durableCounterState) mutate(ctx context.Context, tx pgx.Tx, command risk.CounterCommand, attempt, fingerprint []byte) (risk.CounterResult, error) {
	fail := func() (risk.CounterResult, error) { return risk.CounterResult{}, identity.UnavailableError{} }
	b := command.Bindings()
	ns := s.config.Namespace
	marker := velocityMAC(s.config.ReplayKey, "identity-risk-durable-scope-v1", ns, b.Tenant)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.durable_counter_scopes(namespace,tenant_id,key_marker) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, ns, b.Tenant, marker); err != nil {
		return fail()
	}
	var retained []byte
	var records int64
	if err := tx.QueryRow(ctx, `SELECT key_marker,records FROM `+s.schema+`.durable_counter_scopes WHERE namespace=$1 AND tenant_id=$2 FOR UPDATE`, ns, b.Tenant).Scan(&retained, &records); err != nil || !hmac.Equal(marker, retained) {
		return fail()
	}
	// Replay must obey authoritative key history too: an old binary cannot
	// bypass a later rotation merely by retaining a once-valid command.
	if err := s.checkKeys(ctx, tx, b); err != nil {
		return risk.CounterResult{}, err
	}
	var oldFingerprint, payload, seal []byte
	err := tx.QueryRow(ctx, `SELECT fingerprint,snapshots,seal FROM `+s.schema+`.durable_counter_attempts WHERE namespace=$1 AND tenant_id=$2 AND attempt_digest=$3`, ns, b.Tenant, attempt).Scan(&oldFingerprint, &payload, &seal)
	if err == nil {
		if !hmac.Equal(fingerprint, oldFingerprint) {
			return risk.CounterResult{}, risk.ErrInvalidCounterCommand
		}
		if len(payload) > 4096 || !hmac.Equal(seal, s.seal(b.Tenant, attempt, fingerprint, payload)) {
			return fail()
		}
		var snapshot []risk.Counter
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&snapshot); err != nil || len(snapshot) != len(b.Targets) {
			return fail()
		}
		if err := decoder.Decode(new(any)); err != io.EOF || !velocitySnapshotsValid(b, snapshot) {
			return fail()
		}
		return risk.NewCounterResult(command, risk.CounterCommitted, snapshot)
	}
	if err != pgx.ErrNoRows || records >= s.config.MaximumRecords {
		return fail()
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return fail()
	}
	if b.PreparedAt.After(now) {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	snapshot := make([]risk.Counter, 0, len(b.Targets))
	for _, target := range b.Targets {
		counter, err := s.charge(ctx, tx, b, target, now)
		if err != nil {
			return risk.CounterResult{}, err
		}
		snapshot = append(snapshot, counter)
	}
	result, err := risk.NewCounterResult(command, risk.CounterCommitted, snapshot)
	if err != nil {
		return risk.CounterResult{}, err
	}
	payload, err = json.Marshal(snapshot)
	if err != nil || len(payload) > 4096 {
		return fail()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.durable_counter_attempts(namespace,tenant_id,attempt_digest,fingerprint,snapshots,seal) VALUES($1,$2,$3,$4,$5,$6)`, ns, b.Tenant, attempt, fingerprint, payload, s.seal(b.Tenant, attempt, fingerprint, payload)); err != nil {
		return fail()
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.durable_counter_scopes SET records=records+1 WHERE namespace=$1 AND tenant_id=$2`, ns, b.Tenant); err != nil {
		return fail()
	}
	return result, nil
}

func (s *durableCounterState) seal(tenant string, attempt, fingerprint, payload []byte) []byte {
	return velocityMAC(s.config.ReplayKey, "identity-risk-durable-result-v1", s.config.Namespace, tenant, hex.EncodeToString(attempt), hex.EncodeToString(fingerprint), string(payload))
}

func (s *durableCounterState) checkKeys(ctx context.Context, tx pgx.Tx, b risk.CounterBinding) error {
	var tenantKeys []risk.CounterKey
	for _, target := range b.Targets {
		if target.Dimension == risk.TenantDimension {
			tenantKeys = target.Keys
		}
	}
	if len(tenantKeys) != len(s.config.Keys) {
		return risk.ErrInvalidCounterCommand
	}
	args := []any{s.config.Namespace, b.Tenant, string(b.Operation), string(b.Phase)}
	rows, err := tx.Query(ctx, `SELECT key_version,key_id FROM `+s.schema+`.durable_counter_keys WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 ORDER BY key_version DESC LIMIT 5`, args...)
	if err != nil {
		return identity.UnavailableError{}
	}
	known := make(map[uint32]string, 4)
	var maximum uint32
	for rows.Next() {
		var version uint32
		var id string
		if rows.Scan(&version, &id) != nil || len(known) == 4 {
			rows.Close()
			return identity.UnavailableError{}
		}
		known[version] = id
		if version > maximum {
			maximum = version
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return identity.UnavailableError{}
	}
	for version, id := range known {
		matched := false
		for _, key := range tenantKeys {
			if key.Version == version && key.Encoded == id {
				matched = true
			}
		}
		if !matched {
			return risk.ErrInvalidCounterCommand
		}
	}
	for _, key := range tenantKeys {
		if _, ok := known[key.Version]; ok {
			continue
		}
		if key.Version <= maximum {
			return risk.ErrInvalidCounterCommand
		}
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.durable_counter_keys(namespace,tenant_id,operation,phase,key_version,key_id) VALUES($1,$2,$3,$4,$5,$6)`, append(args, int64(key.Version), key.Encoded)...); err != nil {
			return identity.UnavailableError{}
		}
	}
	return nil
}

func (s *durableCounterState) charge(ctx context.Context, tx pgx.Tx, b risk.CounterBinding, target risk.CounterTarget, now time.Time) (risk.Counter, error) {
	fail := func() (risk.Counter, error) { return risk.Counter{}, identity.UnavailableError{} }
	args := []any{s.config.Namespace, b.Tenant, string(b.Operation), string(b.Phase), string(target.Dimension)}
	root := ""
	for _, key := range target.Keys {
		var found string
		err := tx.QueryRow(ctx, `SELECT root_key FROM `+s.schema+`.durable_counter_aliases WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 AND dimension=$5 AND key_id=$6`, append(args, key.Encoded)...).Scan(&found)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil || root != "" && root != found {
			return fail()
		}
		root = found
	}
	start, end, value := now, now.Add(b.Window), uint64(0)
	if root == "" {
		root = target.Keys[len(target.Keys)-1].Encoded
	} else {
		var raw string
		var window int64
		if err := tx.QueryRow(ctx, `SELECT value::text,window_us,started_at,expires_at FROM `+s.schema+`.durable_counter_windows WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 AND dimension=$5 AND root_key=$6`, append(args, root)...).Scan(&raw, &window, &start, &end); err != nil {
			return fail()
		}
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || window < 1 || window > time.Hour.Microseconds() || now.Before(start) || !end.Equal(start.Add(time.Duration(window)*time.Microsecond)) {
			return fail()
		}
		if !now.Before(end) {
			start, end = now, now.Add(b.Window)
		} else {
			if window != b.Window.Microseconds() {
				return fail()
			}
			value = parsed
		}
	}
	if value < ^uint64(0) {
		value++
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.durable_counter_windows(namespace,tenant_id,operation,phase,dimension,root_key,value,window_us,started_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10) ON CONFLICT(namespace,tenant_id,operation,phase,dimension,root_key) DO UPDATE SET value=EXCLUDED.value,window_us=EXCLUDED.window_us,started_at=EXCLUDED.started_at,expires_at=EXCLUDED.expires_at`, append(args, root, strconv.FormatUint(value, 10), b.Window.Microseconds(), start, end)...); err != nil {
		return fail()
	}
	for _, key := range target.Keys {
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.durable_counter_aliases(namespace,tenant_id,operation,phase,dimension,key_id,root_key) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, append(args, key.Encoded, root)...); err != nil {
			return fail()
		}
	}
	return risk.Counter{Kind: string(target.Dimension), Value: value, ObservedAt: now, WindowStartedAt: start, WindowExpiresAt: end}, nil
}
