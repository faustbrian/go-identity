package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

type nativeLockout struct {
	startedAt, expiresAt time.Time
	endedAt              *time.Time
}

func (l nativeLockout) denies(now time.Time) bool {
	if l.endedAt != nil {
		return now.Before(l.startedAt) || now.Before(*l.endedAt)
	}
	return now.Before(l.startedAt) || now.Before(l.expiresAt)
}

// The current logical counter root is already FOR UPDATE locked. PostgreSQL's
// immediate FK check needs a conflicting KEY SHARE lock for a new restriction,
// fencing absence against concurrent insertion through domain commit. Existing
// restriction rows are SHARE locked here to fence update/deletion. Both owners
// therefore use one database lock order: logical counter, then restriction.
// No row is created, expired, extended, cleared or cached by admission.
func (r *Repository) readCurrentLockout(ctx context.Context, w counterReadWork, b risk.CounterBinding, target risk.CounterTarget, root string) (*nativeLockout, error) {
	columns := `l.version::text,l.policy_version::text,l.started_at,l.expires_at`
	if r.lockoutMutation != nil {
		// Only the selected native profile may honor explicit ends. Its latest
		// state must match the immutable same-command domain version; structural
		// command linkage alone does not attest a committed transition.
		columns += `,l.ended_at,(l.record_id IS NULL OR EXISTS(SELECT 1 FROM ` + r.schema + `.lockout_transitions t WHERE t.command_id=l.command_id AND t.tenant_id=l.tenant_id AND t.command_operation=l.command_operation AND t.record_id=l.record_id AND t.binding_digest=l.binding_digest AND t.after_version=l.version AND t.operation=l.operation AND t.counter_id=l.counter_id AND t.policy_version=l.policy_version AND t.started_at=l.started_at AND t.expires_at=l.expires_at AND t.ended_at IS NOT DISTINCT FROM l.ended_at))`
	}
	rows, err := w.Query(ctx, `SELECT `+columns+` FROM `+r.schema+`.counter_lockouts l WHERE l.tenant_id=$1 AND l.operation=$2 AND l.dimension=$3 AND l.counter_id=$4 FOR SHARE OF l`, b.Tenant, string(b.Operation), string(target.Dimension), root)
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
	proven := true
	dest := []any{&version, &policy, &restriction.startedAt, &restriction.expiresAt}
	if r.lockoutMutation != nil {
		dest = append(dest, &restriction.endedAt, &proven)
	}
	if rows.Scan(dest...) != nil || rows.Next() || rows.Err() != nil || !proven {
		return nil, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	p, pe := strconv.ParseUint(policy, 10, 64)
	if err != nil || pe != nil || v == 0 || p == 0 || !lockoutTime(restriction.startedAt) || !lockoutTime(restriction.expiresAt) || !restriction.expiresAt.After(restriction.startedAt) || restriction.endedAt != nil && (!lockoutTime(*restriction.endedAt) || restriction.endedAt.Before(restriction.startedAt)) {
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
