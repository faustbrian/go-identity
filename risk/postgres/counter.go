package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.CommandCounterContributor = (*Repository)(nil)

// ReserveCommandCounters charges exactly one protected attempt inside the sole
// coordinator reservation transaction. Fixed windows start at primary time and
// reset at their exclusive expiry; values saturate rather than wrap. Every
// retained digest alias names the same window. New-key registration preserves
// all known versions and key identities; removing/changing known keys fails
// closed. Denied is a provisional disposition, not an error, so its charge,
// snapshot, failure audit and aborted receipt can commit atomically. Takeover
// transfers exact predecessor linkage and returns the original decision without
// recounting, refunding or refreshing observation time. It performs no provider
// call, private transaction or domain mutation. Any error requires rollback;
// SQL success alone never establishes CounterCommitted or domain commitment.
func (r *Repository) ReserveCommandCounters(ctx context.Context, w identitypostgres.CommandCounterWork) (identitypostgres.CommandCounterDisposition, error) {
	if ctx == nil || r == nil || r.counters == nil {
		return 0, risk.ErrInvalidCounterCommand
	}
	b, e := w.Binding(r)
	if e != nil {
		return 0, e
	}
	c, e := w.NativeCommand(r)
	if e != nil {
		return 0, e
	}
	native, e := r.restoreCounter(c, b.Plan)
	if e != nil {
		return 0, e
	}
	if nativeMFACounterAction(native.scope.Operation) && native.capabilityID != "" {
		child, completion, scopeErr := w.MFACompletionScope(r)
		if scopeErr != nil || native.subject.User != string(completion.UserID) || native.capabilityID != child.CapabilityID || child.CapabilityID != string(completion.ID) {
			return 0, risk.ErrInvalidCounterCommand
		}
	}
	if b.Generation == 0 || b.PreviousGeneration == ^uint64(0) || b.PreviousGeneration != 0 && b.Generation != b.PreviousGeneration+1 {
		return 0, identity.ConflictError{}
	}
	raw, e := base64.RawURLEncoding.DecodeString(string(b.Command.CommandID))
	if e != nil || len(raw) != 16 {
		return 0, identity.ConflictError{}
	}
	if b.PreviousGeneration != 0 {
		return r.transferCounterCharge(ctx, w, b, raw)
	}
	currentPlan, e := counterPlan(native.current)
	if e != nil || currentPlan != b.Plan {
		return 0, identity.ConflictError{}
	}
	if e = r.checkCounterKeys(ctx, w, native.current); e != nil {
		return 0, e
	}
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return 0, e
	}
	if native.validateAt(now) != nil {
		return 0, identity.ConflictError{}
	}
	binding := native.current
	snapshots := make([]risk.Counter, 0, len(binding.Targets))
	allowed := true
	for _, target := range binding.Targets {
		counter, e := r.chargeCounter(ctx, w, binding, target, now)
		if e != nil {
			return 0, e
		}
		snapshots = append(snapshots, counter)
		if counter.Value > binding.Limit {
			allowed = false
		}
	}
	n, e := w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_charges(command_id,tenant_id,operation,command_fingerprint,counter_fingerprint,policy_version,generation,allowed,observed_at,prepared_at) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10)`, raw, string(b.Command.TenantID), b.Command.OperationID, b.Fingerprint[:], b.Plan.Fingerprint[:], strconv.FormatUint(b.Plan.PolicyVersion, 10), strconv.FormatUint(b.Generation, 10), allowed, now, binding.PreparedAt)
	if e != nil {
		return 0, e
	}
	if n != 1 {
		return 0, identity.ConflictError{}
	}
	for _, s := range snapshots {
		n, e = w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_snapshots(command_id,dimension,value,observed_at,started_at,expires_at) VALUES($1,$2,$3::numeric,$4,$5,$6)`, raw, s.Kind, strconv.FormatUint(s.Value, 10), s.ObservedAt, s.WindowStartedAt, s.WindowExpiresAt)
		if e != nil {
			return 0, e
		}
		if n != 1 {
			return 0, identity.ConflictError{}
		}
	}
	if allowed {
		return identitypostgres.CommandCounterAllowed, nil
	}
	return identitypostgres.CommandCounterDenied, nil
}

// Tenant exclusion is already owned by the coordinator. The tenant dimension's
// stable keyed projection attests retained secret identity independently of raw
// subjects and mutable policy/windows. Once seen, versions cannot disappear or
// be rebound to a different secret; new versions must be strictly newer.
func (r *Repository) checkCounterKeys(ctx context.Context, w counterWriteWork, b risk.CounterBinding) error {
	var keys []risk.CounterKey
	for _, t := range b.Targets {
		if t.Dimension == risk.TenantDimension {
			keys = t.Keys
		}
	}
	if len(keys) == 0 || len(keys) > 4 {
		return identity.ConflictError{}
	}
	rows, e := w.Query(ctx, `SELECT key_version,tenant_key FROM `+r.schema+`.counter_key_history WHERE tenant_id=$1 AND operation=$2 ORDER BY key_version DESC LIMIT 5 FOR UPDATE`, b.Tenant, string(b.Operation))
	if e != nil {
		return e
	}
	known := map[uint32]string{}
	var maximum uint32
	for rows.Next() {
		var version int64
		var key string
		if rows.Scan(&version, &key) != nil || version <= 0 || version > int64(^uint32(0)) {
			rows.Close()
			return identity.ConflictError{}
		}
		v := uint32(version)
		known[v] = key
		if v > maximum {
			maximum = v
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(known) > 4 {
		return identity.ConflictError{}
	}
	for v, k := range known {
		found := false
		for _, supplied := range keys {
			if supplied.Version == v && supplied.Encoded == k {
				found = true
			}
		}
		if !found {
			return identity.ConflictError{}
		}
	}
	for _, k := range keys {
		if _, ok := known[k.Version]; ok {
			continue
		}
		if maximum != 0 && k.Version <= maximum {
			return identity.ConflictError{}
		}
		n, e := w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_key_history(tenant_id,operation,key_version,tenant_key) VALUES($1,$2,$3,$4)`, b.Tenant, string(b.Operation), int64(k.Version), k.Encoded)
		if e != nil {
			return e
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	return nil
}

func (r *Repository) chargeCounter(ctx context.Context, w identitypostgres.CommandCounterWork, b risk.CounterBinding, t risk.CounterTarget, now time.Time) (risk.Counter, error) {
	fail := func() (risk.Counter, error) { return risk.Counter{}, identity.ConflictError{} }
	ids := make([]string, len(t.Keys))
	args := []any{b.Tenant, string(b.Operation), string(t.Dimension)}
	for i, k := range t.Keys {
		ids[i] = "$" + strconv.Itoa(i+4)
		args = append(args, k.Encoded)
	}
	rows, e := w.Query(ctx, `SELECT counter_id FROM `+r.schema+`.counter_aliases WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND key_id IN (`+strings.Join(ids, ",")+`) LIMIT 5`, args...)
	if e != nil {
		return risk.Counter{}, e
	}
	root := ""
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || root != "" && root != id {
			rows.Close()
			return fail()
		}
		root = id
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return risk.Counter{}, e
	}
	if root == "" {
		root = t.Keys[len(t.Keys)-1].Encoded
		n, e := w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_windows(tenant_id,operation,dimension,counter_id,value,window_us,started_at,expires_at) VALUES($1,$2,$3,$4,0,$5,$6,$7) ON CONFLICT DO NOTHING`, b.Tenant, string(b.Operation), string(t.Dimension), root, int64(b.Window/time.Microsecond), now, now.Add(b.Window))
		if e != nil {
			return risk.Counter{}, e
		}
		if n != 1 {
			return fail()
		}
	}
	rows, e = w.Query(ctx, `SELECT value::text,window_us,started_at,expires_at FROM `+r.schema+`.counter_windows WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND counter_id=$4 FOR UPDATE`, b.Tenant, string(b.Operation), string(t.Dimension), root)
	if e != nil {
		return risk.Counter{}, e
	}
	var decimal string
	var window int64
	var start, end time.Time
	matched := rows.Next() && rows.Scan(&decimal, &window, &start, &end) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	value, e := strconv.ParseUint(decimal, 10, 64)
	if !matched || e != nil || now.Before(start) {
		return fail()
	}
	if !now.Before(end) {
		value = 0
		start, end = now, now.Add(b.Window)
		window = int64(b.Window / time.Microsecond)
	}
	if window != int64(b.Window/time.Microsecond) || !end.Equal(start.Add(b.Window)) {
		return fail()
	}
	if value < ^uint64(0) {
		value++
	}
	n, e := w.Exec(ctx, `UPDATE `+r.schema+`.counter_windows SET value=$5::numeric,window_us=$6,started_at=$7,expires_at=$8 WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND counter_id=$4`, b.Tenant, string(b.Operation), string(t.Dimension), root, strconv.FormatUint(value, 10), window, start, end)
	if e != nil {
		return risk.Counter{}, e
	}
	if n != 1 {
		return fail()
	}
	for _, k := range t.Keys {
		n, e = w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_aliases(tenant_id,operation,dimension,key_version,key_id,counter_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, b.Tenant, string(b.Operation), string(t.Dimension), int64(k.Version), k.Encoded, root)
		if e != nil {
			return risk.Counter{}, e
		}
		_ = n
	}
	return risk.Counter{Kind: string(t.Dimension), Value: value, ObservedAt: now, WindowStartedAt: start.UTC(), WindowExpiresAt: end.UTC()}, nil
}

type counterReadWork interface {
	Query(context.Context, string, ...any) (*identitypostgres.WorkRows, error)
}

type counterWriteWork interface {
	counterReadWork
	Exec(context.Context, string, ...any) (int64, error)
}

func (r *Repository) readCounterCharge(ctx context.Context, w counterReadWork, b identitypostgres.CommandCounterBinding, raw []byte) (bool, error) {
	rows, e := w.Query(ctx, `SELECT tenant_id,operation,command_fingerprint,counter_fingerprint,policy_version::text,generation::text,allowed FROM `+r.schema+`.counter_charges WHERE command_id=$1`, raw)
	if e != nil {
		return false, e
	}
	var tenant, operation, policy, generation string
	var fingerprint, scope []byte
	var allowed bool
	matched := rows.Next() && rows.Scan(&tenant, &operation, &fingerprint, &scope, &policy, &generation, &allowed) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	expected := b.PreviousGeneration
	if expected == 0 {
		expected = b.Generation
	}
	if !matched || tenant != string(b.Command.TenantID) || operation != b.Command.OperationID || !bytes.Equal(fingerprint, b.Fingerprint[:]) || !bytes.Equal(scope, b.Plan.Fingerprint[:]) || policy != strconv.FormatUint(b.Plan.PolicyVersion, 10) || generation != strconv.FormatUint(expected, 10) {
		return false, identity.ConflictError{}
	}
	rows, e = w.Query(ctx, `SELECT dimension,value::text,observed_at,started_at,expires_at FROM `+r.schema+`.counter_snapshots WHERE command_id=$1 ORDER BY dimension LIMIT 5`, raw)
	if e != nil {
		return false, e
	}
	count := 0
	for rows.Next() {
		var dimension, value string
		var observed, start, end time.Time
		if rows.Scan(&dimension, &value, &observed, &start, &end) != nil {
			rows.Close()
			return false, identity.ConflictError{}
		}
		v, e := strconv.ParseUint(value, 10, 64)
		if e != nil || v == 0 || observed.Before(start) || !observed.Before(end) {
			rows.Close()
			return false, identity.ConflictError{}
		}
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return false, e
	}
	if count != 4 {
		return false, identity.ConflictError{}
	}
	return allowed, nil
}
func (r *Repository) transferCounterCharge(ctx context.Context, w identitypostgres.CommandCounterWork, b identitypostgres.CommandCounterBinding, raw []byte) (identitypostgres.CommandCounterDisposition, error) {
	allowed, e := r.readCounterCharge(ctx, w, b, raw)
	if e != nil {
		return 0, e
	}
	if !allowed {
		return 0, identity.ConflictError{}
	}
	n, e := w.Exec(ctx, `UPDATE `+r.schema+`.counter_charges SET generation=$2::numeric WHERE command_id=$1 AND generation=$3::numeric`, raw, strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10))
	if e != nil {
		return 0, e
	}
	if n != 1 {
		return 0, identity.ConflictError{}
	}
	return identitypostgres.CommandCounterAllowed, nil
}
func (r *Repository) recoverCommandCounter(ctx context.Context, w identitypostgres.RecoveryWork, b identitypostgres.CommandCounterBinding) (identitypostgres.RecoveryStatus, error) {
	raw, e := base64.RawURLEncoding.DecodeString(string(b.Command.CommandID))
	if e != nil || len(raw) != 16 {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	// The coordinator already holds a provisional successor; the retained charge
	// must match its exact predecessor. Recovery does not transfer or recount it.
	// A matching charge contributes prerequisite evidence, never domain proof.
	allowed, e := r.readCounterCharge(ctx, w, b, raw)
	if e != nil || !allowed {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	return identitypostgres.RecoveryNotCommitted, nil
}
