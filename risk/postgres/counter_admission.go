package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.CommandCounterAdmissionContributor = (*Repository)(nil)

// CheckCommandCounters rechecks native fixed-counter custody and current
// allowance only during the exact coordinator domain invocation. It locks the
// retained original charge, validates all original snapshots and current key
// history, and locks each current logical window before sampling primary time.
// Original preparation, observation and window expiry never renew; expired or
// incomplete evidence requires a new command, not an allowance reset. No counter,
// journal, alias or key-history mutation occurs here. Success grants no domain
// authorization or full risk verdict; the feature owner checks its own current
// authority. Selected durable lockouts are read under these same locks; their
// original intervals survive counter-window resets and retained-key rotation.
// Lockout mutation and overrides remain separate implementation work.
// Zero/disabled/foreign Work fails redacted.
func (r *Repository) CheckCommandCounters(ctx context.Context, w identitypostgres.CommandCounterAdmissionWork) error {
	deny := func() error { return identity.ForbiddenError{} }
	if ctx == nil || r == nil || r.counters == nil {
		return risk.ErrInvalidCounterCommand
	}
	b, e := w.Binding(r)
	if e != nil {
		return e
	}
	c, e := w.NativeCommand(r)
	if e != nil {
		return e
	}
	native, e := r.restoreCounter(c, b.Plan)
	if e != nil || b.Generation == 0 {
		return deny()
	}
	if native.scope.Operation == "identity.mfa.totp-verify" && native.capabilityID != "" {
		child, completion, scopeErr := w.MFACompletionScope(r)
		if scopeErr != nil || native.subject.User != string(completion.UserID) || native.capabilityID != child.CapabilityID || child.CapabilityID != string(completion.ID) {
			return deny()
		}
	}
	raw, e := base64.RawURLEncoding.DecodeString(string(b.Command.CommandID))
	if e != nil || len(raw) != 16 {
		return deny()
	}
	rows, e := w.Query(ctx, `SELECT prepared_at,observed_at FROM `+r.schema+`.counter_charges WHERE command_id=$1 FOR UPDATE`, raw)
	if e != nil {
		return e
	}
	var prepared, observed time.Time
	valid := rows.Next() && rows.Scan(&prepared, &observed) == nil
	if rows.Next() || rows.Err() != nil {
		valid = false
	}
	rows.Close()
	if !valid || !prepared.Equal(native.command.Bindings().PreparedAt) || observed.Before(prepared) {
		return deny()
	}
	allowed, e := r.readCounterCharge(ctx, w, b, raw)
	if e != nil {
		var conflict identity.ConflictError
		if errors.As(e, &conflict) {
			return deny()
		}
		return e
	}
	if !allowed {
		return deny()
	}
	if e := r.validateCurrentCounterKeys(ctx, w, native.current); e != nil {
		return e
	}
	original := native.command.Bindings()
	rows, e = w.Query(ctx, `SELECT dimension,value::text,observed_at,started_at,expires_at FROM `+r.schema+`.counter_snapshots WHERE command_id=$1 ORDER BY dimension LIMIT 5`, raw)
	if e != nil {
		return e
	}
	snapshots := make(map[string]risk.Counter, 4)
	for rows.Next() {
		var s risk.Counter
		var value string
		if rows.Scan(&s.Kind, &value, &s.ObservedAt, &s.WindowStartedAt, &s.WindowExpiresAt) != nil {
			rows.Close()
			return deny()
		}
		s.Value, e = strconv.ParseUint(value, 10, 64)
		if e != nil || s.Value == 0 || s.Value > original.Limit || !s.ObservedAt.Equal(observed) || s.WindowExpiresAt.Sub(s.WindowStartedAt) != original.Window {
			rows.Close()
			return deny()
		}
		snapshots[s.Kind] = s
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(snapshots) != len(original.Targets) {
		return deny()
	}
	current := make([]risk.Counter, 0, len(native.current.Targets))
	var restrictions []nativeLockout
	for _, target := range native.current.Targets {
		old, ok := snapshots[string(target.Dimension)]
		if !ok {
			return deny()
		}
		var originalKeys []risk.CounterKey
		for _, previous := range original.Targets {
			if previous.Dimension == target.Dimension {
				originalKeys = previous.Keys
			}
		}
		s, e := r.readCurrentCounter(ctx, w, native.current, target, originalKeys)
		if e != nil {
			return e
		}
		// A changed/expired window cannot extend the old positive observation.
		if s.Value < old.Value || !s.WindowStartedAt.Equal(old.WindowStartedAt) || !s.WindowExpiresAt.Equal(old.WindowExpiresAt) {
			return deny()
		}
		current = append(current, s.Counter)
		if r.lockouts {
			lockout, e := r.readCurrentLockout(ctx, w, native.current, target, s.root)
			if e != nil {
				return e
			}
			if lockout != nil {
				restrictions = append(restrictions, *lockout)
			}
		}
	}
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return e
	}
	if native.validateAt(now) != nil {
		return deny()
	}
	for _, s := range current {
		if s.Value > original.Limit || now.Before(observed) || now.Before(s.WindowStartedAt) || !now.Before(s.WindowExpiresAt) {
			return deny()
		}
	}
	for _, restriction := range restrictions {
		// Future start is invalid authority, not permission. A selected durable
		// restriction ends exactly at its exclusive database-time boundary.
		if restriction.denies(now) {
			return deny()
		}
	}
	return nil
}

// Current checks never register a new version. Newer configured versions may
// coexist with retained original aliases; every durable version must still have
// the same tenant identity. Only reservation may register the new projections.
func (r *Repository) validateCurrentCounterKeys(ctx context.Context, w counterReadWork, b risk.CounterBinding) error {
	var keys []risk.CounterKey
	for _, target := range b.Targets {
		if target.Dimension == risk.TenantDimension {
			keys = target.Keys
		}
	}
	rows, e := w.Query(ctx, `SELECT key_version,tenant_key FROM `+r.schema+`.counter_key_history WHERE tenant_id=$1 AND operation=$2 ORDER BY key_version DESC LIMIT 5 FOR UPDATE`, b.Tenant, string(b.Operation))
	if e != nil {
		return e
	}
	count := 0
	var maximum uint32
	known := make(map[uint32]bool, 4)
	for rows.Next() {
		var version int64
		var encoded string
		if rows.Scan(&version, &encoded) != nil || version <= 0 || version > int64(^uint32(0)) {
			rows.Close()
			return identity.ForbiddenError{}
		}
		v := uint32(version)
		found := false
		for _, k := range keys {
			if k.Version == v && k.Encoded == encoded {
				found = true
			}
		}
		if !found {
			rows.Close()
			return identity.ForbiddenError{}
		}
		known[v] = true
		if v > maximum {
			maximum = v
		}
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if count == 0 || count > 4 {
		return identity.ForbiddenError{}
	}
	for _, k := range keys {
		if !known[k.Version] && k.Version <= maximum {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

type currentCounter struct {
	risk.Counter
	root string
}

func (r *Repository) readCurrentCounter(ctx context.Context, w counterReadWork, b risk.CounterBinding, target risk.CounterTarget, originalKeys []risk.CounterKey) (currentCounter, error) {
	deny := func() (currentCounter, error) { return currentCounter{}, identity.ForbiddenError{} }
	args := []any{b.Tenant, string(b.Operation), string(target.Dimension)}
	placeholders := make([]string, len(target.Keys))
	for i, k := range target.Keys {
		args = append(args, k.Encoded)
		placeholders[i] = "$" + strconv.Itoa(i+4)
	}
	rows, e := w.Query(ctx, `SELECT key_version,key_id,counter_id FROM `+r.schema+`.counter_aliases WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND key_id IN (`+strings.Join(placeholders, ",")+`) LIMIT 5`, args...)
	if e != nil {
		return currentCounter{}, e
	}
	root, count := "", 0
	found := make(map[uint32]bool, 4)
	for rows.Next() {
		var version int64
		var key, id string
		if rows.Scan(&version, &key, &id) != nil || root != "" && root != id {
			rows.Close()
			return deny()
		}
		matched := false
		for _, k := range target.Keys {
			if int64(k.Version) == version && k.Encoded == key {
				matched = true
			}
		}
		if !matched {
			rows.Close()
			return deny()
		}
		root = id
		found[uint32(version)] = true
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return currentCounter{}, e
	}
	if root == "" || count > 4 {
		return deny()
	}
	for _, key := range originalKeys {
		if !found[key.Version] {
			return deny()
		}
	}
	rows, e = w.Query(ctx, `SELECT value::text,window_us,started_at,expires_at FROM `+r.schema+`.counter_windows WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND counter_id=$4 FOR UPDATE`, b.Tenant, string(b.Operation), string(target.Dimension), root)
	if e != nil {
		return currentCounter{}, e
	}
	var s risk.Counter
	var decimal string
	var window int64
	valid := rows.Next() && rows.Scan(&decimal, &window, &s.WindowStartedAt, &s.WindowExpiresAt) == nil
	if rows.Next() || rows.Err() != nil {
		valid = false
	}
	rows.Close()
	s.Kind = string(target.Dimension)
	s.Value, e = strconv.ParseUint(decimal, 10, 64)
	if !valid || e != nil || s.Value == 0 || window != int64(b.Window/time.Microsecond) || s.WindowExpiresAt.Sub(s.WindowStartedAt) != b.Window {
		return deny()
	}
	return currentCounter{Counter: s, root: root}, nil
}
