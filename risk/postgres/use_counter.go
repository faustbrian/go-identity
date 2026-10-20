package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

type useCounterWork interface {
	Query(context.Context, string, ...any) (*identitypostgres.WorkRows, error)
	DatabaseTime(context.Context) (time.Time, error)
}

func (r *Repository) checkUseCounters(ctx context.Context, w useCounterWork, original risk.PhoneEvidenceRequest, prepared risk.PreparedEvidenceUse) (time.Time, error) {
	bad := func() (time.Time, error) { return time.Time{}, risk.ErrEvidenceUnavailable }
	if r == nil || r.useIssuer == nil || r.useCounters == nil || ctx == nil {
		return bad()
	}
	s := r.useCounters
	tenant := original.Recovery.Binding.Tenant
	if !s.tenants[tenant] {
		return bad()
	}
	// DurableCounterStore.mutate locks this exact scope FOR UPDATE before
	// rotating keys, charging windows or retaining attempts. A shared lock here
	// fences those writers until protected commit without another transaction.
	rows, err := w.Query(ctx, `SELECT key_marker,records FROM `+s.schema+`.durable_counter_scopes WHERE namespace=$1 AND tenant_id=$2 FOR SHARE`, s.config.Namespace, tenant)
	if err != nil {
		return time.Time{}, err
	}
	var marker []byte
	var records int64
	matched := rows.Next() && rows.Scan(&marker, &records) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	wantMarker := velocityMAC(s.config.ReplayKey, "identity-risk-durable-scope-v1", s.config.Namespace, tenant)
	// Capacity bounds new attempts in mutate; consuming an existing retained
	// attempt allocates nothing and stays valid at that exact capacity bound.
	if !matched || records < 1 || records > s.config.MaximumRecords || !hmac.Equal(marker, wantMarker) {
		return bad()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	command, err := r.useIssuer.PrepareUseCounters(original, prepared, now)
	if err != nil || command.ValidateConfiguration(s.config.Policy, s.config.Keys) != nil {
		return bad()
	}
	binding := command.Bindings()
	if binding.Window%time.Microsecond != 0 || r.checkUseCounterKeys(ctx, w, binding) != nil {
		return bad()
	}
	previous, err := r.readUseCounterOriginal(ctx, w, command, prepared)
	if err != nil {
		return time.Time{}, err
	}
	for _, target := range binding.Targets {
		old, ok := previous[string(target.Dimension)]
		if !ok || r.checkUseCounterWindow(ctx, w, binding, target, old) != nil {
			return bad()
		}
	}
	// Waiting for exclusions/reads cannot preserve a positive earlier instant.
	// The signed CheckedAt and original source/window interval remain unchanged.
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if _, err := r.useIssuer.RecheckUse(original, prepared, now); err != nil {
		return bad()
	}
	for _, old := range previous {
		if now.Before(old.ObservedAt) || now.Before(old.WindowStartedAt) || !now.Before(old.WindowExpiresAt) {
			return bad()
		}
	}
	return now, nil
}

func (r *Repository) checkUseCounterKeys(ctx context.Context, w counterReadWork, b risk.CounterBinding) error {
	s := r.useCounters
	var keys []risk.CounterKey
	for _, target := range b.Targets {
		if target.Dimension == risk.TenantDimension {
			keys = target.Keys
		}
	}
	if len(keys) < 1 || len(keys) > 4 {
		return risk.ErrEvidenceUnavailable
	}
	rows, err := w.Query(ctx, `SELECT key_version,key_id FROM `+s.schema+`.durable_counter_keys WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 ORDER BY key_version DESC LIMIT 5 FOR SHARE`, s.config.Namespace, b.Tenant, string(b.Operation), string(b.Phase))
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var version int64
		var id string
		if rows.Scan(&version, &id) != nil || count >= len(keys) || version != int64(keys[count].Version) || id != keys[count].Encoded {
			return risk.ErrEvidenceUnavailable
		}
		count++
	}
	if rows.Err() != nil || count != len(keys) {
		return risk.ErrEvidenceUnavailable
	}
	return nil
}

func (r *Repository) readUseCounterOriginal(ctx context.Context, w counterReadWork, command risk.CounterCommand, prepared risk.PreparedEvidenceUse) (map[string]risk.Counter, error) {
	bad := func() (map[string]risk.Counter, error) { return nil, risk.ErrEvidenceUnavailable }
	s := r.useCounters
	b := command.Bindings()
	attempt, err := s.replay.Attempt(command)
	if err != nil {
		return bad()
	}
	fingerprint, err := hex.DecodeString(b.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return bad()
	}
	rows, err := w.Query(ctx, `SELECT fingerprint,snapshots,seal FROM `+s.schema+`.durable_counter_attempts WHERE namespace=$1 AND tenant_id=$2 AND attempt_digest=$3 FOR SHARE`, s.config.Namespace, b.Tenant, attempt[:])
	if err != nil {
		return nil, err
	}
	var original, payload, seal []byte
	matched := rows.Next() && rows.Scan(&original, &payload, &seal) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched || !hmac.Equal(original, fingerprint) || len(payload) > 4096 || !hmac.Equal(seal, s.seal(b.Tenant, attempt[:], original, payload)) {
		return bad()
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshots []risk.Counter
	if decoder.Decode(&snapshots) != nil || decoder.Decode(new(any)) != io.EOF || !velocitySnapshotsValid(b, snapshots) {
		return bad()
	}
	if _, err := risk.NewCounterResult(command, risk.CounterCommitted, snapshots); err != nil {
		return bad()
	}
	previous := make(map[string]risk.Counter, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.Value == 0 || snapshot.Value > b.Limit || snapshot.ObservedAt.After(prepared.IssuedAt) || prepared.ExpiresAt.After(snapshot.WindowExpiresAt) || !snapshot.ObservedAt.Equal(snapshots[0].ObservedAt) {
			return bad()
		}
		previous[snapshot.Kind] = snapshot
	}
	return previous, nil
}

func (r *Repository) checkUseCounterWindow(ctx context.Context, w counterReadWork, b risk.CounterBinding, target risk.CounterTarget, original risk.Counter) error {
	s := r.useCounters
	if len(target.Keys) < 1 || len(target.Keys) > 4 {
		return risk.ErrEvidenceUnavailable
	}
	args := []any{s.config.Namespace, b.Tenant, string(b.Operation), string(b.Phase), string(target.Dimension)}
	ids := make([]string, len(target.Keys))
	for i, key := range target.Keys {
		ids[i] = "$" + strconv.Itoa(i+6)
		args = append(args, key.Encoded)
	}
	rows, err := w.Query(ctx, `SELECT key_id,root_key FROM `+s.schema+`.durable_counter_aliases WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 AND dimension=$5 AND key_id IN (`+strings.Join(ids, ",")+`) LIMIT 5 FOR SHARE`, args...)
	if err != nil {
		return err
	}
	root, count := "", 0
	for rows.Next() {
		var key, found string
		if rows.Scan(&key, &found) != nil || root != "" && root != found {
			rows.Close()
			return risk.ErrEvidenceUnavailable
		}
		root, count = found, count+1
	}
	err = rows.Err()
	rows.Close()
	if err != nil || root == "" || count != len(target.Keys) {
		return risk.ErrEvidenceUnavailable
	}
	rows, err = w.Query(ctx, `SELECT value::text,window_us,started_at,expires_at FROM `+s.schema+`.durable_counter_windows WHERE namespace=$1 AND tenant_id=$2 AND operation=$3 AND phase=$4 AND dimension=$5 AND root_key=$6 FOR SHARE`, s.config.Namespace, b.Tenant, string(b.Operation), string(b.Phase), string(target.Dimension), root)
	if err != nil {
		return err
	}
	var raw string
	var window int64
	var started, expires time.Time
	matched := rows.Next() && rows.Scan(&raw, &window, &started, &expires) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	value, err := strconv.ParseUint(raw, 10, 64)
	if !matched || err != nil || value < original.Value || value > b.Limit || window != b.Window.Microseconds() || !started.Equal(original.WindowStartedAt) || !expires.Equal(original.WindowExpiresAt) {
		return risk.ErrEvidenceUnavailable
	}
	return nil
}
