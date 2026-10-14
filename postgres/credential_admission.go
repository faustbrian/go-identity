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
	return w.requireActiveCredential(ctx, b, expected)
}

// RequireRecipientCredential fences the exact original email/phone recipient
// and its credential during this participant's active invocation. The snapshots
// must agree on tenant, selected user and every security epoch. Primary user,
// identifier and credential share locks remain held until Work ends; expiry is
// checked after lock acquisition. It never rewrites anonymous command scope,
// rediscovers a recipient or refreshes expected versions. Denials poison Work,
// including when ignored. Malformed/unowned input returns InvalidInput; current
// ineligibility returns Forbidden with the existing redacted query semantics.
// Password comparison, proof provenance, authorization, one-time consumption
// and session issuance remain separate. The returned time is not a validity lease.
func (w Work) RequireRecipientCredential(ctx context.Context, p FeatureExecutionContributor, recipient RecipientRecord, expected CredentialAdmission) (time.Time, error) {
	return w.requireRecipientCredential(ctx, p, recipient, expected, true)
}

// RequireResetRecipientCredential admits the original enabled/disabled password
// predecessor only for the exact anonymous native reset-request profile. It
// preserves primary recipient, status, expiry and independent epoch fences and
// poisons Work on denial. expectedEnabled is original trusted intent, never
// client input. This grants no authentication, factor bypass or reset completion.
// Locks, clock, lifetime and original anonymous-scope semantics match
// RequireRecipientCredential, which still requires an enabled reference.
func (w Work) RequireResetRecipientCredential(ctx context.Context, p FeatureExecutionContributor, recipient RecipientRecord, expected CredentialAdmission, expectedEnabled bool) (time.Time, error) {
	if w.state == nil {
		return time.Time{}, invalidWork()
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || !passwordResetRequestOperation(f.Operation) || b.UserID != "" || b.AnonymousFlowID == "" || f.Contributor.Owner != "identity/password/postgres" || f.Contributor.ContractID != "identity.password" || f.Contributor.Version != 1 || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != RecipientVerified || expected.Credential.Kind != identity.CredentialPassword || expected.Credential.Owner != "identity/password" {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	return w.requireRecipientCredential(ctx, p, recipient, expected, expectedEnabled)
}

func (w Work) requireRecipientCredential(ctx context.Context, p FeatureExecutionContributor, recipient RecipientRecord, expected CredentialAdmission, expectedEnabled bool) (time.Time, error) {
	if w.state == nil {
		return time.Time{}, invalidWork()
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	if recipient.Validate() != nil {
		return time.Time{}, w.fail(ctx, invalidRecipient())
	}
	if recipient.Suppressed {
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	if expected.Credential.Validate(b.TenantID, recipient.User.ID) != nil || expected.UserAuthorityVersion != recipient.UserAuthorityVersion || expected.IdentifierAuthorityVersion != recipient.IdentifierAuthorityVersion || expected.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	if err := w.RequireRecipient(ctx, p, recipient); err != nil {
		return time.Time{}, err
	}
	// Only this local eligibility query uses the selected identity. The frozen
	// command binding retains the originating anonymous flow for audit/replay.
	b.UserID = recipient.User.ID
	now, err := w.requireCredentialLock(ctx, b, expected, false, 0, expectedEnabled)
	if err == nil && w.state.feature != nil && passwordResetRequestOperation(w.state.feature.Operation) {
		// The command keeps its anonymous scope. Only this successful primary
		// fence can admit its selected recipient to later reset-token staging.
		if recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != RecipientVerified || expected.Credential.Kind != identity.CredentialPassword || expected.Credential.Owner != "identity/password" {
			return time.Time{}, w.fail(ctx, invalidWork())
		}
		w.state.resetRecipient = &resetRecipientAdmission{owner: p, recipient: recipient, credential: expected}
	}
	return now, err
}

func (w Work) requireActiveCredential(ctx context.Context, b identity.CommandBinding, expected CredentialAdmission) (time.Time, error) {
	return w.requireActiveCredentialLock(ctx, b, expected, false, 0)
}

func (w Work) requireActiveCredentialLock(ctx context.Context, b identity.CommandBinding, expected CredentialAdmission, exclusive bool, aggregate uint64) (time.Time, error) {
	return w.requireCredentialLock(ctx, b, expected, exclusive, aggregate, true)
}

func (w Work) requireCredentialLock(ctx context.Context, b identity.CommandBinding, expected CredentialAdmission, exclusive bool, aggregate uint64, expectedEnabled bool) (time.Time, error) {
	c := expected.Credential
	if c.Validate(b.TenantID, b.UserID) != nil || expected.UserAuthorityVersion == 0 || expected.IdentifierAuthorityVersion == 0 || expected.CredentialAuthorityVersion == 0 {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	lock := " FOR SHARE OF u,c"
	if exclusive {
		lock = " FOR UPDATE OF u,c"
	}
	rows, err := w.Query(ctx, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at,u.authority_version::text,u.identifier_version::text
 FROM identity.users u JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3`+lock, string(b.TenantID), string(b.UserID), string(c.ID))
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
	admission := identity.CheckCredentialAuthority(current, c, expected.CredentialAuthorityVersion, now)
	if !expectedEnabled {
		admission = identity.CheckPasswordRecoveryAuthority(current, c, expected.CredentialAuthorityVersion, false, now)
	}
	if aggregate != 0 && current.User.Version != aggregate || userVersion != expected.UserAuthorityVersion || identifierVersion != expected.IdentifierAuthorityVersion || admission != nil {
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	return now, nil
}
