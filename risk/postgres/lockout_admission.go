package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

type nativeLockout struct{ startedAt, expiresAt time.Time }

func (l nativeLockout) denies(now time.Time) bool {
	return now.Before(l.startedAt) || now.Before(l.expiresAt)
}

// The current logical counter root is already FOR UPDATE locked. PostgreSQL's
// immediate FK check needs a conflicting KEY SHARE lock for a new restriction,
// fencing absence against concurrent insertion through domain commit. Existing
// restriction rows are SHARE locked here to fence update/deletion. Both owners
// therefore use one database lock order: logical counter, then restriction.
// No row is created, expired, extended, cleared or cached by admission.
func (r *Repository) readCurrentLockout(ctx context.Context, w counterReadWork, b risk.CounterBinding, target risk.CounterTarget, root string) (*nativeLockout, error) {
	rows, err := w.Query(ctx, `SELECT version::text,policy_version::text,started_at,expires_at FROM `+r.schema+`.counter_lockouts WHERE tenant_id=$1 AND operation=$2 AND dimension=$3 AND counter_id=$4 FOR SHARE`, b.Tenant, string(b.Operation), string(target.Dimension), root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return nil, identity.UnavailableError{}
		}
		return nil, nil
	}
	var restriction nativeLockout
	var version, policy string
	if rows.Scan(&version, &policy, &restriction.startedAt, &restriction.expiresAt) != nil || rows.Next() || rows.Err() != nil {
		return nil, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	p, pe := strconv.ParseUint(policy, 10, 64)
	if err != nil || pe != nil || v == 0 || p == 0 || !lockoutTime(restriction.startedAt) || !lockoutTime(restriction.expiresAt) || !restriction.expiresAt.After(restriction.startedAt) {
		return nil, identity.UnavailableError{}
	}
	// A new configured policy cannot erase an older durable restriction. The
	// current-state read preserves its original interval regardless of version;
	// only a separately authorized same-coordinator transition may end it.
	return &restriction, nil
}

func lockoutTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
