package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// Only an unchanged original core version is negative kernel evidence. A
// successor or missing user is not proof that this command committed. Native
// projection/audit/outbox participants retain their independent recovery fences.
func recoverSCIMUserUpdate(ctx context.Context, recovery RecoveryWork) (RecoveryStatus, error) {
	update := recovery.state.plan.scimUserUpdate
	if update == nil || update.ExpectedVersion == 0 {
		return RecoveryUnknown, invalidSCIMUpdate()
	}
	if !update.Required {
		return RecoveryNotCommitted, nil
	}
	b, err := recovery.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := recovery.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric)`, string(b.TenantID), string(b.UserID), strconv.FormatUint(update.ExpectedVersion, 10))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var unchanged bool
	if !rows.Next() || rows.Scan(&unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if !unchanged {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
