package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// RequireActiveUserStatus locks and checks the command-bound user's active
// status and exact original user-security epoch during this feature owner's
// live invocation. Expected must come from the identity owner and be frozen in
// the native command's intent. It authenticates neither the feature's credential
// nor its actor and decides no permission. The user is the target/owner; an
// API-key actor must not be represented as that human.
//
// The SHARE lock is the same user-row fence used by lifecycle writers and lasts
// until coordinator closure. Acquire it before feature aggregate/key locks.
// Aggregate User.Version is validated structurally but is not a security epoch:
// ordinary metadata, identifier and password changes must not silently become
// API-key-owner revocation. Use the existing stronger credential/user-authority
// guards when those additional dimensions actually authorize the operation.
// Missing, inactive or changed security denies uniformly. Live failures poison
// Work even if ignored; returned invocations cannot poison a later invocation.
// This check performs no write, freshness renewal or independent transaction.
func (w Work) RequireActiveUserStatus(ctx context.Context, owner FeatureExecutionContributor, expected identity.UserStatusRecord) error {
	if w.state == nil || w.state.featureInvocation == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if expected.User.Validate(b.TenantID) != nil || expected.User.TenantID != b.TenantID || expected.User.ID != b.UserID || expected.User.Status != identity.StatusActive || expected.AuthorityVersion == 0 {
		return w.fail(ctx, invalidWork())
	}
	rows, err := w.Query(ctx, `SELECT status,authority_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return w.fail(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return w.fail(ctx, err)
		}
		return w.fail(ctx, identity.ForbiddenError{})
	}
	var status, raw string
	if err := rows.Scan(&status, &raw); err != nil {
		return w.fail(ctx, err)
	}
	if rows.Next() {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if err := rows.Err(); err != nil {
		return w.fail(ctx, err)
	}
	version, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != raw {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if status != string(identity.StatusActive) || version != expected.AuthorityVersion {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return nil
}
