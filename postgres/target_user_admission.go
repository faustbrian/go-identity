package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// RequireActiveTargetUser locks and checks the original command's exact target
// user, tenant, active status and aggregate record version. Call only during
// this owner's live feature invocation, before credential/authorization and
// feature-aggregate locks; the existing identity lifecycle writers share this
// user-row lock. SHARE locks for distinct actor/target users commute.
//
// The native feature must bind expected.ID and Version into original command
// intent and recheck them on retries. Missing, inactive or stale rows deny
// uniformly; live errors poison Work. No epoch is derived from User.Version.
// This is target existence/state admission, not authentication, permission,
// credential admission, session validity or a replacement for security epochs.
// For operations such as membership removal that must support inactive targets,
// use the feature's existing membership authority rather than this active gate.
func (w Work) RequireActiveTargetUser(ctx context.Context, owner FeatureExecutionContributor, expected identity.User) error {
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
	if expected.Validate(b.TenantID) != nil || expected.TenantID != b.TenantID || expected.ID != b.UserID || expected.Status != identity.StatusActive {
		return w.fail(ctx, invalidWork())
	}
	rows, err := w.Query(ctx, `SELECT status,version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
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
	if status != string(identity.StatusActive) || version != expected.Version {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return nil
}
