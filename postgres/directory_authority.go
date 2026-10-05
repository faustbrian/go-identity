package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// DirectoryAuthorityQuery selects an exact configured deployment authority and
// tenant. Both IDs follow the kernel's bounded opaque directory-ID policy; no
// normalization or caller identity inference occurs. Zero is invalid.
type DirectoryAuthorityQuery struct {
	GlobalAuthorityID string
	TenantID          identity.TenantID
}

// Validate rejects malformed scope before any primary read.
func (q DirectoryAuthorityQuery) Validate() error {
	if !queryScopeText(q.GlobalAuthorityID) || !queryScopeText(string(q.TenantID)) {
		return identity.InvalidInputError{Field: "directory_authority"}
	}
	return nil
}

// Format redacts correlation-bearing authority scope.
func (DirectoryAuthorityQuery) Format(s fmt.State, _ rune) {
	io.WriteString(s, "postgres.DirectoryAuthorityQuery(redacted)")
}

// MarshalJSON rejects accidental correlated scope export.
func (DirectoryAuthorityQuery) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// DirectoryAuthorityRecord is a structural primary projection, not validity
// evidence or authentication. Epochs are positive full-width counters. Enabled
// is current tenant state, independent of any user's aggregate/status. Missing
// authorities never acquire a default epoch during reads.
type DirectoryAuthorityRecord struct {
	Query                        DirectoryAuthorityQuery
	GlobalVersion, TenantVersion uint64
	Enabled                      bool
}

// Format hides internal authority scope and version correlation.
func (DirectoryAuthorityRecord) Format(s fmt.State, _ rune) {
	io.WriteString(s, "postgres.DirectoryAuthorityRecord(redacted)")
}

// MarshalJSON rejects accidental authority projection export.
func (DirectoryAuthorityRecord) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

const directoryAuthoritySelect = `SELECT g.authority_id,t.tenant_id,g.version::text,t.version::text,t.enabled
 FROM identity.global_authorities g CROSS JOIN identity.tenant_authorities t
 WHERE g.authority_id=$1 AND t.tenant_id=$2`

// GetDirectoryAuthority performs one bounded primary read of the exact scopes.
// Missing scope is redacted Forbidden; corrupt/missing schema is Unavailable.
// Disabled tenant state is returned, never restored. The read acquires no
// persistent lock, creates no validity lease, and supplies no issuance proof.
func (r *Repository) GetDirectoryAuthority(ctx context.Context, q DirectoryAuthorityQuery) (DirectoryAuthorityRecord, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || q.Validate() != nil {
		return DirectoryAuthorityRecord{}, identity.InvalidInputError{Field: "directory_authority"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	var globalID, tenantID, global, tenant string
	var enabled bool
	err := r.pool.Raw().QueryRow(bounded, directoryAuthoritySelect, q.GlobalAuthorityID, string(q.TenantID)).Scan(&globalID, &tenantID, &global, &tenant, &enabled)
	if err != nil {
		return DirectoryAuthorityRecord{}, directoryAuthorityReadFailure(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return DirectoryAuthorityRecord{}, readFailure(bounded, err)
	}
	return decodeDirectoryAuthority(q, globalID, tenantID, global, tenant, enabled)
}

func decodeDirectoryAuthority(q DirectoryAuthorityQuery, globalID, tenantID, global, tenant string, enabled bool) (DirectoryAuthorityRecord, error) {
	g, ge := strconv.ParseUint(global, 10, 64)
	t, te := strconv.ParseUint(tenant, 10, 64)
	if q.Validate() != nil || globalID != q.GlobalAuthorityID || tenantID != string(q.TenantID) || ge != nil || te != nil || g == 0 || t == 0 || strconv.FormatUint(g, 10) != global || strconv.FormatUint(t, 10) != tenant {
		return DirectoryAuthorityRecord{}, identity.UnavailableError{}
	}
	return DirectoryAuthorityRecord{Query: q, GlobalVersion: g, TenantVersion: t, Enabled: enabled}, nil
}

func directoryAuthorityReadFailure(ctx context.Context, err error) error {
	if ctx.Err() == nil && errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	return readFailure(ctx, err)
}

// DirectoryAuthorityAdmission freezes both exact scope and expected epochs.
// Native participants must bind every field into their immutable keyed command
// before reservation, deriving deployment scope from trusted composition. It
// carries no proof, authorization decision or complete session authority vector.
type DirectoryAuthorityAdmission struct {
	Query                        DirectoryAuthorityQuery
	GlobalVersion, TenantVersion uint64
}

// Format redacts correlated admission input.
func (DirectoryAuthorityAdmission) Format(s fmt.State, _ rune) {
	io.WriteString(s, "postgres.DirectoryAuthorityAdmission(redacted)")
}

// MarshalJSON prevents accidental admission export.
func (DirectoryAuthorityAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// RequireActiveDirectoryAuthority checks only kernel-owned global and tenant
// authority during the exact native participant invocation. Primary share locks
// remain until the original coordinator terminalizes Work. Missing, disabled,
// stale or regressed authority returns Forbidden and poisons Work; malformed
// input returns InvalidInput. No row or default version is created, no epoch is
// refreshed, and the original deadline is never extended. This neither checks
// credential/authorization/optional authority nor consumes an authenticated
// proof: success alone must not enable session issuance or bearer acceptance.
func (w Work) RequireActiveDirectoryAuthority(ctx context.Context, p FeatureExecutionContributor, expected DirectoryAuthorityAdmission) error {
	b, _, _, err := w.FeatureScope(p)
	if err != nil || ctx == nil {
		return invalidWork()
	}
	if expected.Query.Validate() != nil || expected.Query.TenantID != b.TenantID || expected.GlobalVersion == 0 || expected.TenantVersion == 0 {
		return w.fail(ctx, invalidWork())
	}
	rows, err := w.Query(ctx, directoryAuthoritySelect+" FOR SHARE OF g,t", expected.Query.GlobalAuthorityID, string(b.TenantID))
	if err != nil {
		return err
	}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return w.fail(ctx, identity.ForbiddenError{})
	}
	var globalID, tenantID, global, tenant string
	var enabled bool
	err = rows.Scan(&globalID, &tenantID, &global, &tenant, &enabled)
	if err != nil {
		rows.Close()
		return err
	}
	if rows.Next() {
		rows.Close()
		return w.fail(ctx, identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	current, err := decodeDirectoryAuthority(expected.Query, globalID, tenantID, global, tenant, enabled)
	if err != nil {
		return w.fail(ctx, err)
	}
	if !current.Enabled || current.GlobalVersion != expected.GlobalVersion || current.TenantVersion != expected.TenantVersion {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
