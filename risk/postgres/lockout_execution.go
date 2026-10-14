package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Native transitions retain the actor epoch lock through the sole domain commit.
// Policy callbacks already ran outside Work; the signed original permit cannot
// be manufactured through NewFeatureCommand or refreshed by execution/replay.
func (r *Repository) applyLockout(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	fail := func(err error) (identity.FeatureReceipt, error) { return identity.FeatureReceipt{}, err }
	n, e := r.restoreLockout(c)
	if e != nil {
		return fail(e)
	}
	s, _ := c.Feature()
	b, f, l, e := w.FeatureScope(r)
	_, event := lockoutEvents(n.request.Mode)
	if e != nil || b != s.Binding || f.Contributor != r.Descriptor() || f.Operation != s.Operation || l.EventType != event || l.BeforeVersion != n.request.ExpectedVersion || l.AfterVersion != n.request.ExpectedVersion+1 {
		return fail(risk.ErrInvalidCounterCommand)
	}
	actor := authority.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: r.lockoutMutation.config.AuthorityNamespace, SubjectID: authorization.SubjectID(b.ActorID)}
	if e = authority.RequireAuthority(ctx, w, actor, n.authority, r.lockoutMutation.config.MaximumDuration); e != nil {
		if errors.Is(e, authority.ErrAuthorityDenied) {
			return fail(identity.ForbiddenError{})
		}
		return fail(identity.UnavailableError{})
	}
	intent := n.command.Bindings()
	if e = r.checkCounterKeys(ctx, w, intent.Counter); e != nil {
		return fail(e)
	}
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return fail(e)
	}
	root, e := r.lockoutRoot(ctx, w, intent.Counter, intent.Target, now, n.request.Mode == risk.StartLockout)
	if e != nil {
		return fail(e)
	}
	rows, e := w.Query(ctx, `SELECT version::text,record_id,started_at,expires_at,ended_at FROM `+r.schema+`.counter_lockouts WHERE tenant_id=$1 AND operation=$2 AND dimension='subject' AND counter_id=$3 FOR UPDATE`, intent.Counter.Tenant, string(intent.Counter.Operation), root)
	if e != nil {
		return fail(e)
	}
	var current uint64
	var id *string
	var started, expires time.Time
	var ended *time.Time
	if rows.Next() {
		var version string
		if rows.Scan(&version, &id, &started, &expires, &ended) != nil {
			rows.Close()
			return fail(identity.UnavailableError{})
		}
		current, e = strconv.ParseUint(version, 10, 64)
		if e != nil || current == 0 || !lockoutTime(started) || !lockoutTime(expires) || !expires.After(started) || ended != nil && (!lockoutTime(*ended) || ended.Before(started)) {
			rows.Close()
			return fail(identity.UnavailableError{})
		}
	}
	if rows.Next() || rows.Err() != nil {
		rows.Close()
		return fail(identity.UnavailableError{})
	}
	rows.Close()
	// Sample after all locks. Neither lock wait nor a current epoch read renews
	// the original decision interval. Future/expired permits fail before writes.
	now, e = w.DatabaseTime(ctx)
	if e != nil {
		return fail(e)
	}
	if now.Before(n.at) || !now.Before(n.at.Add(r.lockoutMutation.config.AdmissionTTL)) || r.lockoutMutation.policy.Validate(n.command, n.request, now) != nil {
		return fail(identity.ForbiddenError{})
	}
	if current != n.request.ExpectedVersion || id != nil && *id != b.RecordID || id == nil && b.RecordID != string(b.CommandID) {
		return fail(identity.ConflictError{})
	}
	if n.request.Mode == risk.StartLockout {
		if current > 0 && (now.Before(started) || ended == nil && now.Before(expires)) {
			return fail(identity.ConflictError{})
		}
		started, expires, ended = now, now.Add(n.request.Duration), nil
		if !lockoutTime(expires) {
			return fail(identity.UnavailableError{})
		}
	} else {
		if current == 0 || now.Before(started) || ended != nil {
			return fail(identity.ConflictError{})
		}
		ended = &now
	}
	digest := bindingDigest(b)
	raw, e := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if e != nil || len(raw) != 16 {
		return fail(risk.ErrInvalidCounterCommand)
	}
	var changed int64
	if current == 0 {
		changed, e = w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_lockouts(tenant_id,operation,dimension,counter_id,version,policy_version,started_at,expires_at,record_id,ended_at,command_id,binding_digest,command_operation) VALUES($1,$2,'subject',$3,1,$4::numeric,$5,$6,$7,NULL,$8,$9,$10) ON CONFLICT DO NOTHING`, intent.Counter.Tenant, string(intent.Counter.Operation), root, strconv.FormatUint(r.policy, 10), started, expires, b.RecordID, raw, digest[:], b.OperationID)
	} else {
		var end any
		if ended != nil {
			end = *ended
		}
		changed, e = w.Exec(ctx, `UPDATE `+r.schema+`.counter_lockouts SET version=version+1,policy_version=$4::numeric,started_at=$5,expires_at=$6,record_id=$7,ended_at=$8,command_id=$9,binding_digest=$10,command_operation=$11 WHERE tenant_id=$1 AND operation=$2 AND dimension='subject' AND counter_id=$3 AND version=$12::numeric`, intent.Counter.Tenant, string(intent.Counter.Operation), root, strconv.FormatUint(r.policy, 10), started, expires, b.RecordID, end, raw, digest[:], b.OperationID, strconv.FormatUint(current, 10))
	}
	if e != nil {
		return fail(e)
	}
	if changed != 1 {
		return fail(identity.ConflictError{})
	}
	var end any
	if ended != nil {
		end = *ended
	}
	original := lockoutIntentDigest(r.lockoutMutation.config.SigningKeys[n.signing], b, n.request, n.authority)
	changed, e = w.Exec(ctx, `INSERT INTO `+r.schema+`.lockout_transitions(command_id,tenant_id,command_operation,record_id,binding_digest,before_version,after_version,operation,counter_id,policy_version,started_at,expires_at,ended_at,intent_digest,signing_version,authority_version) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10::numeric,$11,$12,$13,$14,$15,$16::numeric)`, raw, string(b.TenantID), b.OperationID, b.RecordID, digest[:], strconv.FormatUint(current, 10), strconv.FormatUint(current+1, 10), string(intent.Counter.Operation), root, strconv.FormatUint(r.policy, 10), started, expires, end, original[:], int64(n.signing), strconv.FormatUint(n.authority, 10))
	if e != nil {
		return fail(e)
	}
	if changed != 1 {
		return fail(identity.ConflictError{})
	}
	return identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: current, AfterVersion: current + 1}, nil
}

// The logical root has one synchronization owner. New starts establish a zero
// counter root without charging an authentication attempt or resetting an
// existing window. Retained aliases and key history prevent rotation bypass.
func (r *Repository) lockoutRoot(ctx context.Context, w identitypostgres.Work, b risk.CounterBinding, target risk.CounterTarget, now time.Time, create bool) (string, error) {
	args := []any{b.Tenant, string(b.Operation)}
	marks := make([]string, len(target.Keys))
	for i, k := range target.Keys {
		args = append(args, k.Encoded)
		marks[i] = "$" + strconv.Itoa(i+3)
	}
	rows, e := w.Query(ctx, `SELECT counter_id FROM `+r.schema+`.counter_aliases WHERE tenant_id=$1 AND operation=$2 AND dimension='subject' AND key_id IN (`+strings.Join(marks, ",")+`) LIMIT 5`, args...)
	if e != nil {
		return "", e
	}
	root := ""
	count := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || root != "" && root != id {
			rows.Close()
			return "", identity.ConflictError{}
		}
		root = id
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	if count > 4 {
		return "", identity.ConflictError{}
	}
	if root == "" {
		if !create {
			return "", identity.ConflictError{}
		}
		root = target.Keys[len(target.Keys)-1].Encoded
		n, e := w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_windows(tenant_id,operation,dimension,counter_id,value,window_us,started_at,expires_at) VALUES($1,$2,'subject',$3,0,$4,$5,$6) ON CONFLICT DO NOTHING`, b.Tenant, string(b.Operation), root, int64(b.Window/time.Microsecond), now, now.Add(b.Window))
		if e != nil {
			return "", e
		}
		if n != 1 {
			return "", identity.ConflictError{}
		}
	}
	rows, e = w.Query(ctx, `SELECT counter_id FROM `+r.schema+`.counter_windows WHERE tenant_id=$1 AND operation=$2 AND dimension='subject' AND counter_id=$3 FOR UPDATE`, b.Tenant, string(b.Operation), root)
	if e != nil {
		return "", e
	}
	var locked string
	valid := rows.Next() && rows.Scan(&locked) == nil && locked == root
	if rows.Next() || rows.Err() != nil {
		valid = false
	}
	rows.Close()
	if !valid {
		return "", identity.UnavailableError{}
	}
	for _, key := range target.Keys {
		_, e = w.Exec(ctx, `INSERT INTO `+r.schema+`.counter_aliases(tenant_id,operation,dimension,key_version,key_id,counter_id) VALUES($1,$2,'subject',$3,$4,$5) ON CONFLICT DO NOTHING`, b.Tenant, string(b.Operation), int64(key.Version), key.Encoded, root)
		if e != nil {
			return "", e
		}
	}
	return root, nil
}

// Immutable domain transition evidence proves the exact historical effect,
// even after later starts/ends change current state. It owns no command state,
// lease, replay decision or retry mechanism: those remain coordinator-owned.
func (r *Repository) recoverLockout(ctx context.Context, w identitypostgres.RecoveryWork, b identity.CommandBinding, f identitypostgres.FeatureRegistration, l identitypostgres.LifecyclePlan) (identitypostgres.RecoveryStatus, error) {
	unknown := func() (identitypostgres.RecoveryStatus, error) {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if r.lockoutMutation == nil || f.Contributor != r.Descriptor() || !isLockoutOperation(f.Operation) {
		return unknown()
	}
	raw, e := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if e != nil || len(raw) != 16 {
		return unknown()
	}
	rows, e := w.Query(ctx, `SELECT record_id,command_operation,binding_digest,before_version::text,after_version::text FROM `+r.schema+`.lockout_transitions WHERE command_id=$1 AND tenant_id=$2`, raw, string(b.TenantID))
	if e != nil {
		return unknown()
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return unknown()
		}
		return identitypostgres.RecoveryNotCommitted, nil
	}
	var id, op, before, after string
	var digest []byte
	if rows.Scan(&id, &op, &digest, &before, &after) != nil || rows.Next() || rows.Err() != nil {
		return unknown()
	}
	expected := bindingDigest(b)
	if id != b.RecordID || op != b.OperationID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || len(digest) != 32 || subtle.ConstantTimeCompare(digest, expected[:]) != 1 {
		return unknown()
	}
	return identitypostgres.RecoveryCommitted, nil
}
