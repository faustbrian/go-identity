package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	_ identity.AccountRepository     = (*Repository)(nil)
	_ identity.AccountLinkRepository = (*Repository)(nil)
)

const accountListSQL = `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 a.account_id,a.provider,a.issuer,a.subject,a.version::text
 FROM identity.users u LEFT JOIN LATERAL (
  SELECT account_id,provider,issuer,subject,version FROM identity.accounts
  WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND linked
  ORDER BY account_id LIMIT $3::integer
 ) a ON true WHERE u.tenant_id=$1 AND u.user_id=$2 ORDER BY a.account_id`

// ListAccounts returns one complete, ordered primary user/account snapshot.
// MaximumAccounts must be 1..100; overflow/corruption fails redacted Unavailable
// without partial rows. Missing user is ErrUserAbsent. Caller/configured budgets
// bound I/O, and returned slices own their memory. No authorization, provider
// proof, network work, credential usability or cache freshness is established.
func (r *Repository) ListAccounts(ctx context.Context, q identity.AccountQuery) (identity.AccountSnapshot, error) {
	if !r.validAccountRead(ctx) || !validAccountQuery(q) {
		return identity.AccountSnapshot{}, invalidAccountQuery()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	rows, err := r.pool.Raw().Query(bounded, accountListSQL, string(q.TenantID), string(q.UserID), int(q.MaximumAccounts)+1)
	if err != nil {
		return identity.AccountSnapshot{}, readFailure(bounded, err)
	}
	return collectAccountRows(bounded, rows, q)
}

func (r *Repository) validAccountRead(ctx context.Context) bool {
	return r != nil && r.pool != nil && r.pool.Raw() != nil && ctx != nil && r.maximumDuration > 0 && r.maximumDuration <= time.Minute
}

func validAccountQuery(q identity.AccountQuery) bool {
	u := identity.User{TenantID: q.TenantID, ID: q.UserID, Status: identity.StatusActive, Version: 1}
	return u.Validate(q.TenantID) == nil && q.MaximumAccounts > 0 && q.MaximumAccounts <= 100
}

func invalidAccountQuery() error { return identity.InvalidInputError{Field: "account_query"} }

func collectAccountRows(ctx context.Context, rows pgx.Rows, q identity.AccountQuery) (identity.AccountSnapshot, error) {
	defer rows.Close()
	out := identity.AccountSnapshot{Accounts: []identity.Account{}}
	for rows.Next() {
		var tenant, user, status, version string
		var id, provider, issuer, subject, accountVersion pgtype.Text
		if err := rows.Scan(&tenant, &user, &status, &version, &id, &provider, &issuer, &subject, &accountVersion); err != nil {
			return identity.AccountSnapshot{}, readFailure(ctx, err)
		}
		v, err := parseAccountVersion(version)
		u := identity.User{TenantID: identity.TenantID(tenant), ID: identity.UserID(user), Status: identity.Status(status), Version: v}
		if err != nil || u.ID != q.UserID || u.Validate(q.TenantID) != nil || out.User.ID != "" && out.User != u {
			return identity.AccountSnapshot{}, identity.UnavailableError{}
		}
		out.User = u
		if !id.Valid {
			if provider.Valid || issuer.Valid || subject.Valid || accountVersion.Valid || len(out.Accounts) != 0 {
				return identity.AccountSnapshot{}, identity.UnavailableError{}
			}
			continue
		}
		v, err = parseAccountVersion(accountVersion.String)
		a := identity.Account{TenantID: u.TenantID, UserID: u.ID, ID: identity.AccountID(id.String), Provider: provider.String, Issuer: issuer.String, Subject: subject.String, Version: v}
		if !provider.Valid || !issuer.Valid || !subject.Valid || !accountVersion.Valid || err != nil || a.Validate(q.TenantID, q.UserID) != nil || len(out.Accounts) >= int(q.MaximumAccounts) || len(out.Accounts) != 0 && out.Accounts[len(out.Accounts)-1].ID >= a.ID {
			return identity.AccountSnapshot{}, identity.UnavailableError{}
		}
		out.Accounts = append(out.Accounts, a)
	}
	if err := rows.Err(); err != nil {
		return identity.AccountSnapshot{}, readFailure(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return identity.AccountSnapshot{}, readFailure(ctx, err)
	}
	if out.User.ID == "" {
		return identity.AccountSnapshot{}, identity.ErrUserAbsent
	}
	return out, nil
}

func parseAccountVersion(raw string) (uint64, error) {
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != raw {
		return 0, identity.UnavailableError{}
	}
	return v, nil
}

// GetAccountLinkState returns one bounded repeatable-read primary snapshot of
// the user, all live links, retained candidate tombstone, exact provider-subject
// collision and credential references. It never locks for mutation or treats a
// read as proof. The native protected owner must repeat/fence admission in Work.
// Unsupported implicit mode fails closed until its identifier projection is
// composed. Methods are conservative reference observations: Usable is false
// until the corresponding credential/factor/provider owners establish eligibility.
// This read cannot authorize unlink or session issuance. No token material is read.
func (r *Repository) GetAccountLinkState(ctx context.Context, q identity.AccountLinkQuery) (identity.AccountLinkState, error) {
	zero := identity.AccountLinkState{}
	a := q.Account
	if !r.validAccountRead(ctx) || a.Validate(a.TenantID, a.UserID) != nil || q.Mode != identity.AccountLinkExplicit && q.Mode != identity.AccountLinkAdministrative {
		return zero, invalidAccountQuery()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	tx, err := r.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return zero, readFailure(bounded, err)
	}
	defer func() { _ = tx.Rollback(bounded) }()
	rows, err := tx.Query(bounded, accountListSQL, string(a.TenantID), string(a.UserID), 101)
	if err != nil {
		return zero, readFailure(bounded, err)
	}
	list, err := collectAccountRows(bounded, rows, identity.AccountQuery{TenantID: a.TenantID, UserID: a.UserID, MaximumAccounts: 100})
	if err != nil {
		return zero, err
	}
	out := identity.AccountLinkState{Candidate: a, Access: identity.AccountAccessSnapshot{User: list.User, Accounts: list.Accounts, Methods: []identity.LoginMethod{}}, SocialLinkVersion: 1}
	var credentialVersion string
	if err := tx.QueryRow(bounded, `SELECT credential_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(a.TenantID), string(a.UserID)).Scan(&credentialVersion); err != nil {
		return zero, readFailure(bounded, err)
	}
	if out.CredentialVersion, err = parseAccountVersion(credentialVersion); err != nil {
		return zero, err
	}
	var stored identity.Account
	var tenant, user, id, record, social string
	err = tx.QueryRow(bounded, `SELECT tenant_id,user_id,account_id,provider,issuer,subject,version::text,social_link_version::text FROM identity.accounts WHERE tenant_id=$1 AND account_id=$2`, string(a.TenantID), string(a.ID)).Scan(&tenant, &user, &id, &stored.Provider, &stored.Issuer, &stored.Subject, &record, &social)
	if err == nil {
		stored.TenantID, stored.UserID, stored.ID = identity.TenantID(tenant), identity.UserID(user), identity.AccountID(id)
		stored.Version, err = parseAccountVersion(record)
		if err != nil || stored.Validate(a.TenantID, a.UserID) != nil || stored.ID != a.ID || stored.Provider != a.Provider || stored.Issuer != a.Issuer || stored.Subject != a.Subject {
			return zero, identity.UnavailableError{}
		}
		out.RecordVersion = stored.Version
		if out.SocialLinkVersion, err = parseAccountVersion(social); err != nil {
			return zero, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, readFailure(bounded, err)
	}
	var owner identity.Account
	err = tx.QueryRow(bounded, `SELECT tenant_id,user_id,account_id,provider,issuer,subject,version::text FROM identity.accounts
 WHERE tenant_id=$1 AND linked AND subject_key=sha256(convert_to(
 octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text,'UTF8'))`, string(a.TenantID), a.Provider, a.Issuer, a.Subject).Scan(&tenant, &user, &id, &owner.Provider, &owner.Issuer, &owner.Subject, &record)
	if err == nil {
		owner.TenantID, owner.UserID, owner.ID = identity.TenantID(tenant), identity.UserID(user), identity.AccountID(id)
		owner.Version, err = parseAccountVersion(record)
		if err != nil || owner.Validate(a.TenantID, owner.UserID) != nil || owner.Provider != a.Provider || owner.Issuer != a.Issuer || owner.Subject != a.Subject {
			return zero, identity.UnavailableError{}
		}
		out.SubjectOwner = &owner
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, readFailure(bounded, err)
	}
	if out.Access.Methods, err = readAccountMethods(bounded, tx, a.TenantID, a.UserID, list.Accounts); err != nil {
		return zero, err
	}
	if err := tx.Commit(bounded); err != nil {
		return zero, readFailure(bounded, err)
	}
	return out, nil
}

func readAccountMethods(ctx context.Context, tx pgx.Tx, tenant identity.TenantID, user identity.UserID, accounts []identity.Account) ([]identity.LoginMethod, error) {
	// Disabled non-provider references include permanently removed passkeys
	// (RemovePasskeyCredential); they must not exhaust a current-method budget.
	// A live account still retains its provider method even when disabled.
	// Missing/invalid associations remain selected for fail-closed validation.
	rows, err := tx.Query(ctx, `SELECT c.credential_id,c.kind,c.owner,c.version::text,c.expires_at,a.account_id,l.linked
 FROM identity.credential_references c LEFT JOIN identity.account_credentials a
 ON a.tenant_id=c.tenant_id AND a.user_id=c.user_id AND a.credential_id=c.credential_id
 LEFT JOIN identity.accounts l ON l.tenant_id=a.tenant_id AND l.user_id=a.user_id AND l.account_id=a.account_id
 WHERE c.tenant_id=$1 AND c.user_id=$2
 AND (c.enabled OR (c.kind=3 AND l.linked IS DISTINCT FROM false)
  OR (c.kind<>3 AND a.account_id IS NOT NULL))
 ORDER BY c.credential_id LIMIT 129`, string(tenant), string(user))
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	defer rows.Close()
	out := []identity.LoginMethod{}
	count := 0
	for rows.Next() {
		var id, owner, version string
		var kind int16
		var expiry pgtype.Timestamptz
		var account pgtype.Text
		var linked pgtype.Bool
		if err := rows.Scan(&id, &kind, &owner, &version, &expiry, &account, &linked); err != nil {
			return nil, readFailure(ctx, err)
		}
		v, err := parseAccountVersion(version)
		count++
		if err != nil || kind < 1 || kind > 4 || count > 128 {
			return nil, identity.UnavailableError{}
		}
		m := identity.LoginMethod{Credential: identity.CredentialRef{TenantID: tenant, UserID: user, ID: identity.CredentialID(id), Kind: identity.CredentialKind(kind), Owner: owner, Version: v}}
		if m.Credential.Validate(tenant, user) != nil {
			return nil, identity.UnavailableError{}
		}
		if expiry.Valid {
			m.ExpiresAt = expiry.Time.UTC()
			if expiry.InfinityModifier != pgtype.Finite || m.ExpiresAt.IsZero() || m.ExpiresAt.Year() < 1 || m.ExpiresAt.Year() > 9999 || m.ExpiresAt.Nanosecond()%1000 != 0 {
				return nil, identity.UnavailableError{}
			}
		}
		if kind == int16(identity.CredentialProvider) {
			if !account.Valid || !linked.Valid || !linked.Bool {
				return nil, identity.UnavailableError{}
			}
			m.AccountID = identity.AccountID(account.String)
			found := false
			for _, a := range accounts {
				found = found || a.ID == m.AccountID
			}
			if !found {
				return nil, identity.UnavailableError{}
			}
		} else if account.Valid || linked.Valid {
			return nil, identity.UnavailableError{}
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, readFailure(ctx, err)
	}
	return out, nil
}
