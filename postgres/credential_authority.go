package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ identity.CredentialAuthorityRepository = (*Repository)(nil)

// GetCredentialAuthority reads an exact user/reference and independent credential
// epoch from one primary statement. Missing exact user or reference is
// ErrUserAbsent; missing schema or corrupt data is redacted Unavailable, never a
// default version. Caller/configured deadlines bound the read. Disabled, expired
// and blocked states are preserved for the core eligibility decision, not hidden
// or restored. The reference contains no verifier and grants no lookup access,
// factor/provider assurance, proof provenance or renewable validity lease.
func (r *Repository) GetCredentialAuthority(ctx context.Context, q identity.CredentialAuthorityQuery) (identity.CredentialAuthorityRecord, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || q.Validate() != nil {
		return identity.CredentialAuthorityRecord{}, identity.InvalidInputError{Field: "credential_query"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.CredentialAuthorityRecord{}, readFailure(bounded, err)
	}
	var row credentialStorageRow
	err := r.pool.Raw().QueryRow(bounded, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,
 c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at
 FROM identity.users u JOIN identity.credential_references c
 ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3`, string(q.TenantID), string(q.UserID), string(q.CredentialID)).Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.id, &row.kind, &row.owner, &row.version, &row.enabled, &row.expires)
	if err != nil {
		return identity.CredentialAuthorityRecord{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return identity.CredentialAuthorityRecord{}, readFailure(bounded, err)
	}
	return decodeCredentialAuthority(q, row)
}

type credentialStorageRow struct {
	tenant, user, status, userVersion, authority string
	id, owner, version                           string
	kind                                         int16
	enabled                                      bool
	expires                                      pgtype.Timestamptz
}

func decodeCredentialAuthority(q identity.CredentialAuthorityQuery, row credentialStorageRow) (identity.CredentialAuthorityRecord, error) {
	v, ve := strconv.ParseUint(row.userVersion, 10, 64)
	a, ae := strconv.ParseUint(row.authority, 10, 64)
	c, ce := strconv.ParseUint(row.version, 10, 64)
	user := identity.User{TenantID: identity.TenantID(row.tenant), ID: identity.UserID(row.user), Status: identity.Status(row.status), Version: v}
	// Check before conversion: narrowing an unknown stored kind could turn it
	// into a supported feature owner and incorrectly supply eligibility.
	if q.Validate() != nil || ve != nil || ae != nil || ce != nil || a == 0 || strconv.FormatUint(v, 10) != row.userVersion || strconv.FormatUint(a, 10) != row.authority || strconv.FormatUint(c, 10) != row.version || user.Validate(q.TenantID) != nil || user.ID != q.UserID || row.kind < 1 || row.kind > 4 {
		return identity.CredentialAuthorityRecord{}, identity.UnavailableError{}
	}
	credential := identity.CredentialRef{ID: identity.CredentialID(row.id), TenantID: user.TenantID, UserID: user.ID, Kind: identity.CredentialKind(row.kind), Owner: row.owner, Version: c}
	if credential.ID != q.CredentialID || credential.Validate(q.TenantID, q.UserID) != nil {
		return identity.CredentialAuthorityRecord{}, identity.UnavailableError{}
	}
	var expiry time.Time
	if row.expires.Valid {
		expiry = row.expires.Time.UTC()
		if row.expires.InfinityModifier != pgtype.Finite || expiry.IsZero() || expiry.Year() < 1 || expiry.Year() > 9999 || expiry.Nanosecond()%1000 != 0 {
			return identity.CredentialAuthorityRecord{}, identity.UnavailableError{}
		}
	}
	return identity.CredentialAuthorityRecord{User: user, AuthorityVersion: a, Credential: credential, Enabled: row.enabled, ExpiresAt: expiry}, nil
}
