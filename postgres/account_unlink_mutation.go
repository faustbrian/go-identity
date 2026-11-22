package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// These storage phases do not issue protected authority. The enclosing typed
// owner must establish fresh password/session/factor policy, actual remaining
// access, one-use consumption, encrypted-token deletion and required effects
// in this same Work before the coordinator may close the command.
func lockAccountUnlinkState(ctx context.Context, w Work, change identity.AccountUnlinkChange) (identity.AccountUnlinkState, time.Time, error) {
	zero := identity.AccountUnlinkState{}
	if err := w.usable(); err != nil {
		return zero, time.Time{}, err
	}
	fail := func(err error) (identity.AccountUnlinkState, time.Time, error) {
		return zero, time.Time{}, w.fail(w.state.ctx, err)
	}
	query := identity.AccountUnlinkQuery{TenantID: change.TenantID, UserID: change.UserID, AccountID: change.AccountID}
	if ctx == nil || !validAccountUnlinkQuery(query) || change.TenantID != w.state.binding.TenantID || change.UserID != w.state.binding.UserID || w.state.rows != nil {
		return fail(invalidWork())
	}
	// Same lock order as link and credential mutation: tenant writer fence is
	// established by configureKernelWork, then user aggregate, then exact link.
	locks := []struct {
		sql  string
		args []any
	}{
		{`SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, []any{string(change.TenantID), string(change.UserID)}},
		{`SELECT account_id FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 FOR UPDATE`, []any{string(change.TenantID), string(change.UserID), string(change.AccountID)}},
	}
	for _, lock := range locks {
		rows, err := w.Query(ctx, lock.sql, lock.args...)
		if err != nil {
			return zero, time.Time{}, err
		}
		found := rows.Next()
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fail(err)
		}
		if !found {
			return fail(identity.ForbiddenError{})
		}
	}
	deadline, _ := w.state.ctx.Deadline()
	bounded, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(w.state.ctx, cancel)
	defer func() { stop(); cancel() }()
	state, err := readAccountUnlinkState(bounded, w.state.tx, query)
	if err != nil {
		return fail(err)
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return zero, time.Time{}, err
	}
	return state, now, nil
}

// A removed link is a durable tombstone, never a deleted/reassignable identity.
// Retire every associated provider reference, including an already-disabled
// one: its record version must advance so restoring ownership cannot resurrect
// the old credential. Associations remain as history until exact relinking
// retires them through the existing link owner. All writes are provisional.
func persistAccountUnlinkMutation(ctx context.Context, w Work, change identity.AccountUnlinkChange, next identity.AccountUnlinkMutation) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func(err error) error { return w.fail(w.state.ctx, err) }
	a := next.Removed
	if ctx == nil || change.TenantID != w.state.binding.TenantID || change.UserID != w.state.binding.UserID || a.ID != change.AccountID || a.Validate(change.TenantID, change.UserID) != nil {
		return fail(invalidWork())
	}
	if a.Version != change.ExpectedAccountVersion || next.TombstoneVersion != a.Version+1 || next.SocialLinkVersion != change.ExpectedSocialLinkVersion+1 || next.Access.User.TenantID != change.TenantID || next.Access.User.ID != change.UserID || next.Access.User.Version != change.ExpectedUserVersion+1 {
		return fail(invalidWork())
	}
	expectedCredentials := change.ExpectedCredentialVersion
	if next.InvalidatesCredential {
		expectedCredentials++
	}
	if next.CredentialVersion != expectedCredentials {
		return fail(invalidWork())
	}
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=$4::numeric,credential_version=$5::numeric
 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric AND credential_version=$6::numeric`, string(change.TenantID), string(change.UserID), change.ExpectedUserVersion, next.Access.User.Version, next.CredentialVersion, change.ExpectedCredentialVersion)
	if err != nil {
		return err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.accounts SET version=$7::numeric,social_link_version=$8::numeric,linked=false
 WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND provider=$4 AND issuer=$5 AND subject=$6
 AND version=$9::numeric AND social_link_version=$10::numeric AND linked`, string(a.TenantID), string(a.UserID), string(a.ID), a.Provider, a.Issuer, a.Subject, next.TombstoneVersion, next.SocialLinkVersion, change.ExpectedAccountVersion, change.ExpectedSocialLinkVersion)
	if err != nil {
		return err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.credential_references c SET enabled=false,version=c.version+1
 FROM identity.account_credentials m
 WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.account_id=$3
 AND c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.credential_id
 AND c.kind=3 AND c.owner='identity/oauth'`, string(a.TenantID), string(a.UserID), string(a.ID))
	if err != nil {
		return err
	}
	if n > 128 || (n > 0) != next.InvalidatesCredential {
		return fail(identity.ConflictError{})
	}
	return w.usable()
}
