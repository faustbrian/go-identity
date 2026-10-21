package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// AnonymousAuthorityRecord is one primary kernel snapshot of an actually created
// anonymous user and its reserved placeholder. CredentialAuthorityVersion is
// the user's aggregate epoch, not a fabricated credential reference. Status and
// versions are preserved, never defaulted or restored. This structural record
// carries no authentication, anonymous lifecycle/expiry or renewable validity.
type AnonymousAuthorityRecord struct {
	User                                                                         identity.User
	Placeholder                                                                  identity.Identifier
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
}

func (AnonymousAuthorityRecord) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousAuthorityRecord(redacted)"))
}
func (AnonymousAuthorityRecord) MarshalJSON() ([]byte, error) {
	return nil, invalidAnonymousAuthority()
}
func (AnonymousAuthorityRecord) MarshalText() ([]byte, error) {
	return nil, invalidAnonymousAuthority()
}

func invalidAnonymousAuthority() error {
	return identity.InvalidInputError{Field: "anonymous_authority"}
}

// Validate checks structure only. A blocked user's structurally valid record
// remains blocked; consumers must independently require active status, compare
// all original epochs and check the anonymous lifecycle, session and policy.
func (r AnonymousAuthorityRecord) Validate() error {
	if r.User.Validate(r.User.TenantID) != nil || r.Placeholder.Validate(r.User.ID) != nil || r.Placeholder.Kind != identity.IdentifierAnonymousPlaceholder || r.Placeholder.Version != 1 || r.Placeholder.CanonicalValue != string(r.User.ID)+"@anonymous.invalid" || r.UserAuthorityVersion == 0 || r.IdentifierAuthorityVersion == 0 || r.CredentialAuthorityVersion == 0 {
		return invalidAnonymousAuthority()
	}
	return nil
}

const anonymousAuthoritySelect = `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 u.authority_version::text,u.identifier_version::text,u.credential_version::text,
 i.identifier_id,i.canonical_value,i.version::text,
 i.display_value,i.verified,i.is_primary,i.normalization_profile,i.normalization_version::text,
 i.verification_state,i.verification_version::text,i.verified_at IS NULL,
 EXISTS(SELECT 1 FROM identity.credential_references c WHERE c.tenant_id=u.tenant_id AND c.user_id=u.user_id),
 EXISTS(SELECT 1 FROM identity.identifiers other WHERE other.tenant_id=u.tenant_id AND other.user_id=u.user_id AND other.identifier_id<>i.identifier_id)
 FROM identity.users u JOIN identity.anonymous_creation_bindings b ON b.tenant_id=u.tenant_id AND b.user_id=u.user_id
 JOIN identity.identifiers i ON i.tenant_id=u.tenant_id AND i.user_id=u.user_id AND i.identifier_id=b.identifier_id AND i.kind='anonymous-placeholder'
 WHERE u.tenant_id=$1 AND u.user_id=$2`

type anonymousAuthorityRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

// GetAnonymousAuthority performs one bounded primary read of kernel-owned
// anonymous creation and all independent user epochs. It never infers guest
// status merely from missing credentials. Additional contacts/credentials or a
// changed placeholder deny; missing scope returns the existing absence error.
// Blocked status is returned unchanged, not accepted as current authentication.
// Callers own the original positive-evidence deadline across every owner read.
func (r *Repository) GetAnonymousAuthority(ctx context.Context, q identity.UserStatusQuery) (AnonymousAuthorityRecord, error) {
	shape := identity.User{TenantID: q.TenantID, ID: q.UserID, Status: identity.StatusActive, Version: 1}
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || shape.Validate(q.TenantID) != nil {
		return AnonymousAuthorityRecord{}, invalidAnonymousAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return AnonymousAuthorityRecord{}, readFailure(bounded, err)
	}
	rows, err := r.pool.Raw().Query(bounded, anonymousAuthoritySelect, string(q.TenantID), string(q.UserID))
	if err != nil {
		return AnonymousAuthorityRecord{}, readFailure(bounded, err)
	}
	defer rows.Close()
	record, err := readAnonymousAuthority(q, rows)
	if err != nil {
		return AnonymousAuthorityRecord{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return AnonymousAuthorityRecord{}, readFailure(bounded, err)
	}
	return record, nil
}

func readAnonymousAuthority(q identity.UserStatusQuery, rows anonymousAuthorityRows) (AnonymousAuthorityRecord, error) {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return AnonymousAuthorityRecord{}, err
		}
		return AnonymousAuthorityRecord{}, pgx.ErrNoRows
	}
	var tenant, user, status, version, userEpoch, identifierEpoch, credentialEpoch string
	var placeholder, canonical, placeholderVersion, display, normalization, normalizationVersion, verificationVersion string
	var verified, primary, noVerifiedAt, hasCredential, hasOtherIdentifier bool
	var verificationState int16
	if err := rows.Scan(&tenant, &user, &status, &version, &userEpoch, &identifierEpoch, &credentialEpoch, &placeholder, &canonical, &placeholderVersion, &display, &verified, &primary, &normalization, &normalizationVersion, &verificationState, &verificationVersion, &noVerifiedAt, &hasCredential, &hasOtherIdentifier); err != nil {
		return AnonymousAuthorityRecord{}, err
	}
	if rows.Next() || rows.Err() != nil {
		return AnonymousAuthorityRecord{}, identity.UnavailableError{}
	}
	parse := func(text string) (uint64, bool) {
		value, err := strconv.ParseUint(text, 10, 64)
		return value, err == nil && value != 0 && strconv.FormatUint(value, 10) == text
	}
	v, validVersion := parse(version)
	u, validUser := parse(userEpoch)
	i, validIdentifier := parse(identifierEpoch)
	c, validCredential := parse(credentialEpoch)
	p, validPlaceholder := parse(placeholderVersion)
	record := AnonymousAuthorityRecord{
		User:                 identity.User{TenantID: identity.TenantID(tenant), ID: identity.UserID(user), Status: identity.Status(status), Version: v},
		Placeholder:          identity.Identifier{ID: identity.IdentifierID(placeholder), UserID: identity.UserID(user), Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: canonical, DisplayValue: display, Verified: verified, Primary: primary, Version: p},
		UserAuthorityVersion: u, IdentifierAuthorityVersion: i, CredentialAuthorityVersion: c,
	}
	if !validVersion || !validUser || !validIdentifier || !validCredential || !validPlaceholder || tenant != string(q.TenantID) || user != string(q.UserID) || normalization != "" || normalizationVersion != "0" || verificationState != int16(identity.VerificationPending) || verificationVersion != "1" || !noVerifiedAt || record.Validate() != nil {
		return AnonymousAuthorityRecord{}, identity.UnavailableError{}
	}
	if hasCredential || hasOtherIdentifier {
		return AnonymousAuthorityRecord{}, identity.ForbiddenError{}
	}
	return record, nil
}

// RequireAnonymousAuthority fences actual staged anonymous creation and its
// unchanged kernel epochs in the current native invocation's sole Work. It is
// not a credential check, risk decision or session/lifecycle admission. The
// exact creation owner/command must already have applied; final read-only commit
// checks may repeat it without renewing time. Any mismatch poisons Work.
func (w Work) RequireAnonymousAuthority(ctx context.Context, owner FeatureExecutionContributor, expected AnonymousAuthorityRecord) error {
	b, feature, _, err := w.FeatureScope(owner)
	if err != nil || ctx == nil {
		return invalidWork()
	}
	created := w.state.anonymousCreation
	if expected.Validate() != nil || expected.User.TenantID != b.TenantID || expected.User.Status != identity.StatusActive || created == nil || created.user != expected.User || created.placeholder != expected.Placeholder || feature.Operation != anonymousCreationOperation() || owner.Descriptor() != anonymousCreationDescriptor() {
		return w.fail(ctx, invalidAnonymousAuthority())
	}
	rows, err := w.Query(ctx, anonymousAuthoritySelect+" FOR SHARE OF u,i", string(b.TenantID), string(expected.User.ID))
	if err != nil {
		return err
	}
	current, err := readAnonymousAuthority(identity.UserStatusQuery{TenantID: b.TenantID, UserID: expected.User.ID}, rows)
	rows.Close()
	if err != nil || current != expected {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
