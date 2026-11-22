package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// The unchanged linked account is negative evidence only: a committed unlink
// must atomically advance this version and retain its unlinked tombstone. A
// changed/missing account never reconstructs success or proves rollback. The
// coordinator holds journal/tenant fences and still requires every other
// participant's independent negative evidence before release/terminalization.
func recoverAccountUnlink(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.accountUnlink == nil || w.state.plan.lifecycle == nil || !accountUnlinkBinding(b) {
		return RecoveryUnknown, invalidWork()
	}
	before := w.state.plan.lifecycle.BeforeVersion
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.accounts
WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND version=$4::numeric AND linked)`, string(b.TenantID), string(b.UserID), b.RecordID, before)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var unchanged bool
	if !rows.Next() || rows.Scan(&unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if unchanged {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}
