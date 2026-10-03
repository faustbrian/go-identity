package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

var _ identity.UserStatusRepository = (*Repository)(nil)

// GetStatus returns the exact tenant/user's consistent primary status and
// independent security epoch. It does not auto-restore expired restrictions,
// infer authority from aggregate or identifier versions, or grant permission.
// A missing user returns ErrUserAbsent; missing schema/corrupt data is redacted
// Unavailable. Earlier caller/configured deadlines bound the one statement.
func (r *Repository) GetStatus(ctx context.Context, q identity.UserStatusQuery) (identity.UserStatusRecord, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute {
		return identity.UserStatusRecord{}, identity.InvalidInputError{Field: "status_query"}
	}
	shape := identity.User{TenantID: q.TenantID, ID: q.UserID, Status: identity.StatusActive, Version: 1}
	if shape.Validate(q.TenantID) != nil {
		return identity.UserStatusRecord{}, identity.InvalidInputError{Field: "status_query"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.UserStatusRecord{}, readFailure(bounded, err)
	}
	var tenant, user, status, version, authority string
	err := r.pool.Raw().QueryRow(bounded, `SELECT tenant_id,user_id,status,version::text,authority_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(q.TenantID), string(q.UserID)).Scan(&tenant, &user, &status, &version, &authority)
	if err != nil {
		return identity.UserStatusRecord{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return identity.UserStatusRecord{}, readFailure(bounded, err)
	}
	return decodeStatus(q, tenant, user, status, version, authority)
}

func decodeStatus(q identity.UserStatusQuery, tenant, id, status, version, authority string) (identity.UserStatusRecord, error) {
	v, e := strconv.ParseUint(version, 10, 64)
	a, ae := strconv.ParseUint(authority, 10, 64)
	user := identity.User{TenantID: identity.TenantID(tenant), ID: identity.UserID(id), Status: identity.Status(status), Version: v}
	if e != nil || ae != nil || a == 0 || strconv.FormatUint(v, 10) != version || strconv.FormatUint(a, 10) != authority || user.Validate(q.TenantID) != nil || user.ID != q.UserID {
		return identity.UserStatusRecord{}, identity.UnavailableError{}
	}
	return identity.UserStatusRecord{User: user, AuthorityVersion: a}, nil
}
