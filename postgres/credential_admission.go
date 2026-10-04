package postgres

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// CredentialAdmission freezes the exact credential and three independently
// owned user security epochs. UserAuthorityVersion is not User.Version;
// IdentifierAuthorityVersion and CredentialAuthorityVersion cannot substitute
// for the exact credential record version. Zero is invalid. Native participants
// must bind every field into their immutable keyed command before reservation.
// This projection contains no proof and cannot grant authentication authority.
type CredentialAdmission struct {
	Credential                                                                   identity.CredentialRef
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
}

// Format omits correlated credential and authority scope from diagnostics.
func (CredentialAdmission) Format(s fmt.State, _ rune) {
	io.WriteString(s, "postgres.CredentialAdmission(redacted)")
}

// MarshalJSON rejects accidental export of correlated native admission input.
func (CredentialAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// RequireActiveCredential checks kernel-owned current eligibility only during
// this exact native participant's active invocation. It locks the primary user
// and credential rows until the coordinator ends Work, compares each expected
// epoch and reference, and samples primary time after acquiring both locks.
// Expiry is exclusive; blocked, disabled, absent, foreign and stale records deny
// uniformly with ForbiddenError and poison Work, preventing an ignored denial
// from committing. Malformed input or an unowned handle returns InvalidInput.
// Query/cancellation errors retain Work's redacted error semantics.
//
// It never refreshes versions, modifies rows, issues a session, consumes proof
// or opens/closes a transaction. Its returned clock sample is not a renewable
// validity lease. Global/tenant/authorization/optional owner checks, private
// proof provenance and one-time finalization are separate mandatory phases;
// success here alone must never admit session issuance or authenticate a bearer.
func (w Work) RequireActiveCredential(ctx context.Context, p FeatureExecutionContributor, expected CredentialAdmission) (time.Time, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil || ctx == nil {
		return time.Time{}, invalidWork()
	}
	c := expected.Credential
	if c.Validate(b.TenantID, b.UserID) != nil || expected.UserAuthorityVersion == 0 || expected.IdentifierAuthorityVersion == 0 || expected.CredentialAuthorityVersion == 0 {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	rows, err := w.Query(ctx, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at,u.authority_version::text,u.identifier_version::text
 FROM identity.users u JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3 FOR SHARE OF u,c`, string(b.TenantID), string(b.UserID), string(c.ID))
	if err != nil {
		return time.Time{}, err
	}
	var row credentialStorageRow
	var expiry *time.Time
	var userEpoch, identifierEpoch string
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return time.Time{}, err
		}
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	err = rows.Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.id, &row.kind, &row.owner, &row.version, &row.enabled, &expiry, &userEpoch, &identifierEpoch)
	if err != nil {
		rows.Close()
		return time.Time{}, err
	}
	if rows.Next() {
		rows.Close()
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return time.Time{}, err
	}
	if expiry != nil {
		row.expires = pgtype.Timestamptz{Time: *expiry, Valid: true}
	}
	current, err := decodeCredentialAuthority(identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: c.ID}, row)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	userVersion, ue := strconv.ParseUint(userEpoch, 10, 64)
	identifierVersion, ie := strconv.ParseUint(identifierEpoch, 10, 64)
	if ue != nil || ie != nil || userVersion == 0 || identifierVersion == 0 || strconv.FormatUint(userVersion, 10) != userEpoch || strconv.FormatUint(identifierVersion, 10) != identifierEpoch {
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	// An earlier statement time would incorrectly admit a credential expiring
	// while this read waited for a lifecycle writer's lock. Work's deadline is
	// unchanged by this fresh sample or by the lock wait.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if userVersion != expected.UserAuthorityVersion || identifierVersion != expected.IdentifierAuthorityVersion || identity.CheckCredentialAuthority(current, c, expected.CredentialAuthorityVersion, now) != nil {
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	return now, nil
}
