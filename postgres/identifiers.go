package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ identity.IdentifierRepository = (*Repository)(nil)

const identifierSelect = `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 u.identifier_version::text,statement_timestamp(),
 i.identifier_id,i.kind,i.canonical_value,i.display_value,i.verified,i.is_primary,
 i.version::text,i.verification_state,i.verification_version::text,i.verified_at
 FROM identity.users u
 LEFT JOIN LATERAL (
  SELECT * FROM identity.identifiers
  WHERE tenant_id=u.tenant_id AND user_id=u.user_id
  ORDER BY identifier_id LIMIT $3::integer
 ) i ON true
 WHERE u.tenant_id=$1 AND u.user_id=$2 ORDER BY i.identifier_id`

// GetIdentifierState returns one complete tenant/user primary snapshot through
// the existing IdentifierRepository port. One statement observes the user,
// identifier authority and ordered identifier/verification rows consistently.
// MaximumIdentifiers must be 1..128. An extra row returns Unavailable with no
// partial result rather than silently truncating; a missing user is ErrUserAbsent.
// Stored canonical/display values are never normalized, defaulted or logged.
// Full uint64 versions and microsecond verification instants are preserved.
//
// This trusted storage port confers no authorization, proof, uniqueness claim
// or freshness beyond its primary snapshot. IdentifierService owns admission;
// coordinated writes, proof consumption and tombstones remain separate work.
// Reads use the configured finite budget and earlier caller deadline. Returned
// slices own their memory; no pool, rows, transaction or callback is retained.
func (r *Repository) GetIdentifierState(ctx context.Context, q identity.IdentifierQuery) (identity.IdentifierState, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute {
		return identity.IdentifierState{}, invalidIdentifierQuery()
	}
	shape := identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if shape.Validate(q.TenantID) != nil || q.MaximumIdentifiers == 0 || q.MaximumIdentifiers > 128 {
		return identity.IdentifierState{}, invalidIdentifierQuery()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.IdentifierState{}, readFailure(bounded, err)
	}
	rows, err := r.pool.Raw().Query(bounded, identifierSelect, string(q.TenantID), string(q.UserID), int(q.MaximumIdentifiers)+1)
	if err != nil {
		return identity.IdentifierState{}, readFailure(bounded, err)
	}
	defer rows.Close()
	var state identity.IdentifierState
	for rows.Next() {
		var row identifierStorageRow
		if err := rows.Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.now, &row.id, &row.kind, &row.canonical, &row.display, &row.verified, &row.primary, &row.version, &row.verificationState, &row.verificationVersion, &row.verifiedAt); err != nil {
			return identity.IdentifierState{}, readFailure(bounded, err)
		}
		user, authority, identifier, verification, present, err := decodeIdentifierRow(q, row)
		if err != nil {
			return identity.IdentifierState{}, err
		}
		if state.User.ID == "" {
			state.User, state.AuthorityVersion = user, authority
		} else if state.User != user || state.AuthorityVersion != authority || !present {
			return identity.IdentifierState{}, identity.UnavailableError{}
		}
		if present {
			if len(state.Identifiers) >= int(q.MaximumIdentifiers) || len(state.Identifiers) != 0 && identifier.ID <= state.Identifiers[len(state.Identifiers)-1].ID {
				return identity.IdentifierState{}, identity.UnavailableError{}
			}
			state.Identifiers = append(state.Identifiers, identifier)
			state.Verifications = append(state.Verifications, verification)
		}
	}
	if err := rows.Err(); err != nil {
		return identity.IdentifierState{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return identity.IdentifierState{}, readFailure(bounded, err)
	}
	if state.User.ID == "" {
		return identity.IdentifierState{}, identity.ErrUserAbsent
	}
	return state, nil
}

type identifierStorageRow struct {
	tenant, user, status, userVersion, authority               string
	now                                                        time.Time
	id, kind, canonical, display, version, verificationVersion pgtype.Text
	verified, primary                                          pgtype.Bool
	verificationState                                          pgtype.Int2
	verifiedAt                                                 pgtype.Timestamptz
}

func decodeIdentifierRow(q identity.IdentifierQuery, row identifierStorageRow) (identity.User, uint64, identity.Identifier, identity.Verification, bool, error) {
	fail := func() (identity.User, uint64, identity.Identifier, identity.Verification, bool, error) {
		return identity.User{}, 0, identity.Identifier{}, identity.Verification{}, false, identity.UnavailableError{}
	}
	version, err := strconv.ParseUint(row.userVersion, 10, 64)
	user := identity.User{ID: identity.UserID(row.user), TenantID: identity.TenantID(row.tenant), Status: identity.Status(row.status), Version: version}
	if err != nil || strconv.FormatUint(version, 10) != row.userVersion || user.ID != q.UserID || user.Validate(q.TenantID) != nil || row.now.IsZero() || row.now.Year() < 1 || row.now.Year() > 9999 {
		return fail()
	}
	authority, err := strconv.ParseUint(row.authority, 10, 64)
	if err != nil || authority == 0 || strconv.FormatUint(authority, 10) != row.authority {
		return fail()
	}
	if !row.id.Valid {
		if row.kind.Valid || row.canonical.Valid || row.display.Valid || row.verified.Valid || row.primary.Valid || row.version.Valid || row.verificationState.Valid || row.verificationVersion.Valid || row.verifiedAt.Valid {
			return fail()
		}
		return user, authority, identity.Identifier{}, identity.Verification{}, false, nil
	}
	if !row.kind.Valid || !row.canonical.Valid || !row.display.Valid || !row.verified.Valid || !row.primary.Valid || !row.version.Valid || !row.verificationState.Valid || !row.verificationVersion.Valid {
		return fail()
	}
	version, err = strconv.ParseUint(row.version.String, 10, 64)
	if err != nil || strconv.FormatUint(version, 10) != row.version.String {
		return fail()
	}
	identifier := identity.Identifier{ID: identity.IdentifierID(row.id.String), UserID: user.ID, Kind: identity.IdentifierKind(row.kind.String), CanonicalValue: row.canonical.String, DisplayValue: row.display.String, Verified: row.verified.Bool, Primary: row.primary.Bool, Version: version}
	verificationVersion, err := strconv.ParseUint(row.verificationVersion.String, 10, 64)
	if err != nil || strconv.FormatUint(verificationVersion, 10) != row.verificationVersion.String || row.verificationState.Int16 < 1 || row.verificationState.Int16 > 3 || row.verifiedAt.Valid && row.verifiedAt.InfinityModifier != pgtype.Finite {
		return fail()
	}
	verification := identity.Verification{IdentifierID: identifier.ID, State: identity.VerificationState(row.verificationState.Int16), Version: verificationVersion}
	if row.verifiedAt.Valid {
		verification.VerifiedAt = row.verifiedAt.Time
	}
	if identifier.Validate(user.ID) != nil || verification.Validate(identifier, row.now) != nil {
		return fail()
	}
	return user, authority, identifier, verification, true, nil
}

func invalidIdentifierQuery() error { return identity.InvalidInputError{Field: "identifier_query"} }
