package postgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

var _ identity.AccountUnlinkRepository = (*Repository)(nil)

// GetAccountUnlinkState reads one bounded, consistent primary user/account
// partition, including the removed account's retained social-link epoch.
// Credential references are conservative: Usable remains false until actual
// credential/factor owners establish current eligibility. The protected owner
// must repeat the snapshot under locks; this read authenticates neither the
// caller nor a remaining login method. No provider token material is read.
// Missing user/account is ErrUserAbsent; malformed/overflowed storage returns
// redacted Unavailable without partial state. The caller owns the pool.
func (r *Repository) GetAccountUnlinkState(ctx context.Context, q identity.AccountUnlinkQuery) (identity.AccountUnlinkState, error) {
	zero := identity.AccountUnlinkState{}
	if !r.validAccountRead(ctx) || !validAccountUnlinkQuery(q) {
		return zero, invalidAccountQuery()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	tx, err := r.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return zero, readFailure(bounded, err)
	}
	defer func() { _ = tx.Rollback(bounded) }()
	state, err := readAccountUnlinkState(bounded, tx, q)
	if err != nil {
		return zero, err
	}
	if err := tx.Commit(bounded); err != nil {
		return zero, readFailure(bounded, err)
	}
	return state, nil
}

func validAccountUnlinkQuery(q identity.AccountUnlinkQuery) bool {
	return validAccountQuery(identity.AccountQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumAccounts: 100}) && queryScopeText(string(q.AccountID))
}

func readAccountUnlinkState(ctx context.Context, tx pgx.Tx, q identity.AccountUnlinkQuery) (identity.AccountUnlinkState, error) {
	zero := identity.AccountUnlinkState{}
	rows, err := tx.Query(ctx, accountListSQL, string(q.TenantID), string(q.UserID), 101)
	if err != nil {
		return zero, readFailure(ctx, err)
	}
	list, err := collectAccountRows(ctx, rows, identity.AccountQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumAccounts: 100})
	if err != nil {
		return zero, err
	}
	var social, credential string
	err = tx.QueryRow(ctx, `SELECT a.social_link_version::text,u.credential_version::text
 FROM identity.accounts a JOIN identity.users u ON u.tenant_id=a.tenant_id AND u.user_id=a.user_id
 WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.account_id=$3`, string(q.TenantID), string(q.UserID), string(q.AccountID)).Scan(&social, &credential)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, identity.ErrUserAbsent
	}
	if err != nil {
		return zero, readFailure(ctx, err)
	}
	state := identity.AccountUnlinkState{AccountID: q.AccountID, Access: identity.AccountAccessSnapshot{User: list.User, Accounts: list.Accounts}}
	if state.SocialLinkVersion, err = parseAccountVersion(social); err != nil {
		return zero, err
	}
	if state.CredentialVersion, err = parseAccountVersion(credential); err != nil {
		return zero, err
	}
	state.Access.Methods, err = readAccountMethods(ctx, tx, q.TenantID, q.UserID, list.Accounts)
	if err != nil {
		return zero, err
	}
	return state, nil
}
