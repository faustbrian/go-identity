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

// UsernameQuery discovers one exact canonical username and its stored comparison
// identity. CanonicalValue is already normalized by the workflow owner; this
// port never folds, trims or migrates it. UserID optionally restricts discovery.
// Username ownership is not email/phone verification or authentication.
type UsernameQuery struct {
	TenantID             identity.TenantID
	UserID               identity.UserID
	CanonicalValue       string
	NormalizationProfile string
	NormalizationVersion uint32
}

// Validate bounds the lookup and requires an explicit nonzero comparison pair.
// It does not apply syntax, reserved-name, custom enrollment or access policy.
func (q UsernameQuery) Validate() error {
	u := identity.User{ID: "username-lookup", TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if q.UserID != "" {
		u.ID = q.UserID
	}
	i := identity.Identifier{ID: "username-lookup", UserID: u.ID, Kind: identity.IdentifierUsername, CanonicalValue: q.CanonicalValue, NormalizationProfile: q.NormalizationProfile, NormalizationVersion: q.NormalizationVersion, Version: 1}
	if u.Validate(q.TenantID) != nil || i.Validate(u.ID) != nil || q.NormalizationProfile == "" || q.NormalizationVersion == 0 {
		return invalidUsernameLookup()
	}
	return nil
}

// Format redacts the correlated lookup for every formatting verb.
func (UsernameQuery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.UsernameQuery(redacted)")
}

// MarshalJSON rejects implicit export of correlated lookup data.
func (UsernameQuery) MarshalJSON() ([]byte, error) { return nil, invalidUsernameLookup() }

// MarshalText rejects implicit text and map-key export.
func (UsernameQuery) MarshalText() ([]byte, error) { return nil, invalidUsernameLookup() }

// UsernameRecord is an explicit primary snapshot, not authentication, channel
// verification or a renewable validity lease. Pending username state may be
// selected: a required verified-email login must separately admit its actual
// email recipient. Suppressed uniformly covers absent, inactive, revoked,
// wrong-subject and differently bound historical names without selected data.
// Copies own scalar values; retain the original and fence it with RequireUsername.
type UsernameRecord struct {
	Query                                                                        UsernameQuery
	Suppressed                                                                   bool
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	ObservedAt                                                                   time.Time
}

// Validate checks complete structure, not current ownership or permission.
func (r UsernameRecord) Validate() error {
	if r.Query.Validate() != nil {
		return invalidUsernameLookup()
	}
	if r.Suppressed {
		if r.User != (identity.User{}) || r.Identifier != (identity.Identifier{}) || r.Verification != (identity.Verification{}) || r.UserAuthorityVersion != 0 || r.IdentifierAuthorityVersion != 0 || r.CredentialAuthorityVersion != 0 || !r.ObservedAt.IsZero() {
			return invalidUsernameLookup()
		}
		return nil
	}
	i, q := r.Identifier, r.Query
	if r.User.Validate(q.TenantID) != nil || r.User.Status != identity.StatusActive || q.UserID != "" && q.UserID != r.User.ID || i.Validate(r.User.ID) != nil || i.Kind != identity.IdentifierUsername || i.CanonicalValue != q.CanonicalValue || i.NormalizationProfile != q.NormalizationProfile || i.NormalizationVersion != q.NormalizationVersion || !postgresExactTime(r.ObservedAt) || r.Verification.Validate(i, r.ObservedAt) != nil || !recipientEligible(RecipientPendingOrVerified, r.Verification.State) || r.UserAuthorityVersion == 0 || r.IdentifierAuthorityVersion == 0 || r.CredentialAuthorityVersion == 0 {
		return invalidUsernameLookup()
	}
	return nil
}

// Format redacts the correlated primary record for every formatting verb.
func (UsernameRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.UsernameRecord(redacted)")
}

// MarshalJSON rejects implicit record export.
func (UsernameRecord) MarshalJSON() ([]byte, error) { return nil, invalidUsernameLookup() }

// MarshalText rejects implicit text and map-key export.
func (UsernameRecord) MarshalText() ([]byte, error) { return nil, invalidUsernameLookup() }

func invalidUsernameLookup() error { return identity.InvalidInputError{Field: "username_lookup"} }

// The existing tenant/kind/canonical unique index bounds discovery to one row.
// Optional normalization columns remain fail-closed on older installed histories;
// an unbound historical name is never silently assigned the requested profile.
const usernameSelect = `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 u.identifier_version::text,clock_timestamp(),
 i.identifier_id,i.kind,i.canonical_value,i.display_value,i.verified,i.is_primary,
 i.version::text,i.verification_state,i.verification_version::text,i.verified_at,
 to_jsonb(i)->>'normalization_profile',to_jsonb(i)->>'normalization_version',
 u.authority_version::text,u.credential_version::text
 FROM identity.identifiers i JOIN identity.users u
 ON u.tenant_id=i.tenant_id AND u.user_id=i.user_id
 WHERE i.tenant_id=$1 AND i.kind='username' AND i.canonical_value=$2 LIMIT 2`

// ResolveUsername performs one exact bounded primary read with no mutation,
// callback, lock, password work or freshness renewal. Unknown/ineligible names
// return Suppressed, while corrupt/unavailable storage returns Unavailable and
// no partial result. The earlier caller deadline bounds the repository budget.
// The returned snapshot must be admitted again in the protected transaction.
// Install status and credential-authority histories as well as identifiers;
// missing authority storage cannot be replaced with inferred epoch defaults.
func (r *Repository) ResolveUsername(ctx context.Context, q UsernameQuery) (UsernameRecord, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || q.Validate() != nil {
		return UsernameRecord{}, invalidUsernameLookup()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return UsernameRecord{}, readFailure(bounded, err)
	}
	rows, err := r.pool.Raw().Query(bounded, usernameSelect, string(q.TenantID), q.CanonicalValue)
	if err != nil {
		return UsernameRecord{}, readFailure(bounded, err)
	}
	defer rows.Close()
	record, err := readUsername(q, rows)
	if err != nil {
		return UsernameRecord{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return UsernameRecord{}, readFailure(bounded, err)
	}
	return record, nil
}

func readUsername(q UsernameQuery, rows recipientRows) (UsernameRecord, error) {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return UsernameRecord{}, err
		}
		return UsernameRecord{Query: q, Suppressed: true}, nil
	}
	var row identifierStorageRow
	var id, kind, canonical, display, version, verificationVersion, userAuthority, credentialAuthority string
	var verified, primary bool
	var state int16
	var at *time.Time
	var profile, normalizationVersion *string
	if err := rows.Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.now, &id, &kind, &canonical, &display, &verified, &primary, &version, &state, &verificationVersion, &at, &profile, &normalizationVersion, &userAuthority, &credentialAuthority); err != nil {
		return UsernameRecord{}, err
	}
	text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	row.id, row.kind, row.canonical, row.display = text(id), text(kind), text(canonical), text(display)
	row.version, row.verificationVersion = text(version), text(verificationVersion)
	row.verified, row.primary, row.verificationState = pgtype.Bool{Bool: verified, Valid: true}, pgtype.Bool{Bool: primary, Valid: true}, pgtype.Int2{Int16: state, Valid: true}
	if at != nil {
		row.verifiedAt = pgtype.Timestamptz{Time: at.UTC(), Valid: true}
	}
	if profile != nil {
		row.normalizationProfile = text(*profile)
	}
	if normalizationVersion != nil {
		row.normalizationVersion = text(*normalizationVersion)
	}
	if rows.Next() {
		return UsernameRecord{}, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return UsernameRecord{}, err
	}
	return decodeUsername(q, row, userAuthority, credentialAuthority)
}

func decodeUsername(q UsernameQuery, row identifierStorageRow, userAuthority, credentialAuthority string) (UsernameRecord, error) {
	bad := func() (UsernameRecord, error) { return UsernameRecord{}, identity.UnavailableError{} }
	if q.Validate() != nil || row.tenant != string(q.TenantID) || row.kind.String != "username" || row.canonical.String != q.CanonicalValue {
		return bad()
	}
	u, authority, i, verification, present, err := decodeIdentifierRow(identity.IdentifierQuery{TenantID: q.TenantID, UserID: identity.UserID(row.user), MaximumIdentifiers: 1}, row)
	ua, ue := strconv.ParseUint(userAuthority, 10, 64)
	ca, ce := strconv.ParseUint(credentialAuthority, 10, 64)
	if err != nil || !present || ue != nil || ce != nil || ua == 0 || ca == 0 || strconv.FormatUint(ua, 10) != userAuthority || strconv.FormatUint(ca, 10) != credentialAuthority {
		return bad()
	}
	if u.Status != identity.StatusActive || q.UserID != "" && q.UserID != u.ID || i.NormalizationProfile != q.NormalizationProfile || i.NormalizationVersion != q.NormalizationVersion || !recipientEligible(RecipientPendingOrVerified, verification.State) {
		return UsernameRecord{Query: q, Suppressed: true}, nil
	}
	verification.VerifiedAt = verification.VerifiedAt.UTC()
	record := UsernameRecord{Query: q, User: u, Identifier: i, Verification: verification, UserAuthorityVersion: ua, IdentifierAuthorityVersion: authority, CredentialAuthorityVersion: ca, ObservedAt: row.now.UTC()}
	if record.Validate() != nil {
		return bad()
	}
	return record, nil
}

// RequireUsername fences the exact original primary username during the current
// native feature invocation. User then identifier share locks last until the
// existing coordinator commits or aborts. Any failure poisons live Work, including
// when ignored. It does not admit a password, verified address, policy or session.
func (w Work) RequireUsername(ctx context.Context, owner FeatureExecutionContributor, expected UsernameRecord) error {
	if w.state == nil || w.state.featureInvocation == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidUsernameLookup())
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	if expected.Validate() != nil || expected.Query.TenantID != b.TenantID || expected.Query.UserID != b.UserID || b.UserID != "" && expected.User.ID != b.UserID {
		return w.fail(ctx, invalidUsernameLookup())
	}
	if expected.Suppressed {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	selected := b
	selected.UserID = expected.User.ID
	if err := w.requireActiveUserAuthority(ctx, selected, UserAuthorityAdmission{UserAuthorityVersion: expected.UserAuthorityVersion, IdentifierAuthorityVersion: expected.IdentifierAuthorityVersion, CredentialAuthorityVersion: expected.CredentialAuthorityVersion}); err != nil {
		return w.fail(ctx, err)
	}
	rows, err := w.Query(ctx, usernameSelect+" FOR SHARE OF i", string(b.TenantID), expected.Query.CanonicalValue)
	if err != nil {
		return w.fail(ctx, err)
	}
	current, err := readUsername(expected.Query, rows)
	rows.Close()
	if err != nil {
		return w.fail(ctx, readFailure(ctx, err))
	}
	if current.Suppressed || current.User != expected.User || current.Identifier != expected.Identifier || current.Verification != expected.Verification || current.UserAuthorityVersion != expected.UserAuthorityVersion || current.IdentifierAuthorityVersion != expected.IdentifierAuthorityVersion || current.CredentialAuthorityVersion != expected.CredentialAuthorityVersion {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
