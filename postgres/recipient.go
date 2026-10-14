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

// RecipientEligibility is a closed, trusted workflow selection, not request
// permission. Verification/change workflows may select pending identifiers;
// signin/reset must require verified identifiers. Revoked is never eligible.
type RecipientEligibility uint8

const (
	RecipientVerified RecipientEligibility = iota + 1
	RecipientPendingOrVerified
)

// RecipientQuery selects exactly one owner-canonical channel identifier in one
// tenant. UserID optionally restricts the original known subject. Empty UserID
// permits discovery without retargeting the command's anonymous flow. Values
// are already canonical under the email/phone owner's versioned policy; this
// storage port does not normalize input or grant authentication/authorization.
type RecipientQuery struct {
	TenantID       identity.TenantID
	UserID         identity.UserID
	Kind           identity.IdentifierKind
	CanonicalValue string
	Eligibility    RecipientEligibility
}

// Validate bounds input before SQL. Only email/phone channel identifiers are
// accepted; username/provider subjects are not delivery addresses.
func (q RecipientQuery) Validate() error {
	user := identity.User{ID: "recipient-scope", TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if q.UserID != "" {
		user.ID = q.UserID
	}
	i := identity.Identifier{ID: "recipient-scope", UserID: user.ID, Kind: q.Kind, CanonicalValue: q.CanonicalValue, Version: 1}
	if user.Validate(q.TenantID) != nil || i.Validate(user.ID) != nil || q.Kind != identity.IdentifierEmail && q.Kind != identity.IdentifierPhone || q.Eligibility != RecipientVerified && q.Eligibility != RecipientPendingOrVerified {
		return invalidRecipient()
	}
	return nil
}

func (RecipientQuery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.RecipientQuery(redacted)")
}
func (RecipientQuery) MarshalJSON() ([]byte, error) { return nil, invalidRecipient() }
func (RecipientQuery) MarshalText() ([]byte, error) { return nil, invalidRecipient() }

// RecipientRecord is an explicit primary snapshot, never a clearance/proof or
// public response. Suppressed covers absent, foreign-subject, inactive and
// ineligible records uniformly and carries no resolved identity or versions.
// A selected record freezes exact identifier/verification/security versions;
// bind it into original workflow custody and recheck via RequireRecipient.
// ObservedAt is database observation time, not a renewable validity lease.
// Copies own scalar values; do not concurrently mutate an input record.
type RecipientRecord struct {
	Query                                                                        RecipientQuery
	Suppressed                                                                   bool
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	ObservedAt                                                                   time.Time
}

func (RecipientRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.RecipientRecord(redacted)")
}
func (RecipientRecord) MarshalJSON() ([]byte, error) { return nil, invalidRecipient() }
func (RecipientRecord) MarshalText() ([]byte, error) { return nil, invalidRecipient() }

// Validate checks structure only; manually populated records confer no current
// authority. Suppressed records must omit all selected fields.
func (r RecipientRecord) Validate() error {
	if r.Query.Validate() != nil {
		return invalidRecipient()
	}
	if r.Suppressed {
		if r.User != (identity.User{}) || r.Identifier != (identity.Identifier{}) || r.Verification != (identity.Verification{}) || r.UserAuthorityVersion != 0 || r.IdentifierAuthorityVersion != 0 || r.CredentialAuthorityVersion != 0 || !r.ObservedAt.IsZero() {
			return invalidRecipient()
		}
		return nil
	}
	if r.User.Validate(r.Query.TenantID) != nil || r.User.Status != identity.StatusActive || r.Query.UserID != "" && r.User.ID != r.Query.UserID || r.Identifier.Validate(r.User.ID) != nil || r.Identifier.Kind != r.Query.Kind || r.Identifier.CanonicalValue != r.Query.CanonicalValue || !postgresExactTime(r.ObservedAt) || r.Verification.Validate(r.Identifier, r.ObservedAt) != nil || !recipientEligible(r.Query.Eligibility, r.Verification.State) || r.UserAuthorityVersion == 0 || r.IdentifierAuthorityVersion == 0 || r.CredentialAuthorityVersion == 0 {
		return invalidRecipient()
	}
	return nil
}

func invalidRecipient() error { return identity.InvalidInputError{Field: "recipient"} }
func recipientEligible(policy RecipientEligibility, state identity.VerificationState) bool {
	return state == identity.VerificationVerified || policy == RecipientPendingOrVerified && state == identity.VerificationPending
}

// The unique tenant/kind/canonical index bounds this read independently of user
// directory size. Explicit columns preserve populated-schema compatibility.
const recipientColumns = `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 u.identifier_version::text,clock_timestamp(),
 i.identifier_id,i.kind,i.canonical_value,i.display_value,i.verified,i.is_primary,
 i.version::text,i.verification_state,i.verification_version::text,i.verified_at,
 u.authority_version::text,u.credential_version::text
 FROM identity.identifiers i JOIN identity.users u
 ON u.tenant_id=i.tenant_id AND u.user_id=i.user_id`

const recipientSelect = recipientColumns + ` WHERE i.tenant_id=$1 AND i.kind=$2 AND i.canonical_value=$3 LIMIT 2`

type recipientRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

// ResolveRecipient performs one bounded exact primary read. Missing/inactive or
// ineligible selection returns a suppressed record, never an existence error.
// Infrastructure/corrupt-state failures return Unavailable, not suppression.
// No lock, mutation, delivery, freshness renewal or ownership proof is created.
// Install the kernel identifier/status/credential-authority migrations first.
func (r *Repository) ResolveRecipient(ctx context.Context, q RecipientQuery) (RecipientRecord, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || q.Validate() != nil {
		return RecipientRecord{}, invalidRecipient()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return RecipientRecord{}, readFailure(bounded, err)
	}
	rows, err := r.pool.Raw().Query(bounded, recipientSelect, string(q.TenantID), string(q.Kind), q.CanonicalValue)
	if err != nil {
		return RecipientRecord{}, readFailure(bounded, err)
	}
	defer rows.Close()
	record, err := readRecipient(q, rows)
	if err != nil {
		return RecipientRecord{}, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return RecipientRecord{}, readFailure(bounded, err)
	}
	return record, nil
}

func readRecipient(q RecipientQuery, rows recipientRows) (RecipientRecord, error) {
	return readRecipientSelection(q, rows, false)
}

func readRecipientSelection(q RecipientQuery, rows recipientRows, discoverCanonical bool) (RecipientRecord, error) {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return RecipientRecord{}, err
		}
		return RecipientRecord{Query: q, Suppressed: true}, nil
	}
	var row identifierStorageRow
	var user, credential string
	var id, kind, canonical, display, version, verificationVersion string
	var verified, primary bool
	var verificationState int16
	var verifiedAt *time.Time
	// Work deliberately excludes driver scanner callbacks. The inner join and
	// schema make all identifier columns except verified_at non-null; decode
	// through its closed scalar profile before constructing the shared row.
	if err := rows.Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.now, &id, &kind, &canonical, &display, &verified, &primary, &version, &verificationState, &verificationVersion, &verifiedAt, &user, &credential); err != nil {
		return RecipientRecord{}, err
	}
	text := func(v string) pgtype.Text { return pgtype.Text{String: v, Valid: true} }
	row.id, row.kind, row.canonical, row.display = text(id), text(kind), text(canonical), text(display)
	row.version, row.verificationVersion = text(version), text(verificationVersion)
	row.verified, row.primary = pgtype.Bool{Bool: verified, Valid: true}, pgtype.Bool{Bool: primary, Valid: true}
	row.verificationState = pgtype.Int2{Int16: verificationState, Valid: true}
	if verifiedAt != nil {
		row.verifiedAt = pgtype.Timestamptz{Time: *verifiedAt, Valid: true}
	}
	if rows.Next() {
		return RecipientRecord{}, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return RecipientRecord{}, err
	}
	if discoverCanonical {
		q.CanonicalValue = canonical
	}
	return decodeRecipient(q, row, user, credential)
}

func decodeRecipient(q RecipientQuery, row identifierStorageRow, userAuthority, credentialAuthority string) (RecipientRecord, error) {
	bad := func() (RecipientRecord, error) { return RecipientRecord{}, identity.UnavailableError{} }
	if q.Validate() != nil || row.tenant != string(q.TenantID) || row.kind.String != string(q.Kind) || row.canonical.String != q.CanonicalValue {
		return bad()
	}
	u, authority, i, v, present, err := decodeIdentifierRow(identity.IdentifierQuery{TenantID: q.TenantID, UserID: identity.UserID(row.user), MaximumIdentifiers: 1}, row)
	ua, ue := strconv.ParseUint(userAuthority, 10, 64)
	ca, ce := strconv.ParseUint(credentialAuthority, 10, 64)
	if err != nil || !present || ue != nil || ce != nil || ua == 0 || ca == 0 || strconv.FormatUint(ua, 10) != userAuthority || strconv.FormatUint(ca, 10) != credentialAuthority {
		return bad()
	}
	if u.Status != identity.StatusActive || q.UserID != "" && u.ID != q.UserID || !recipientEligible(q.Eligibility, v.State) {
		return RecipientRecord{Query: q, Suppressed: true}, nil
	}
	// Pool and fixed transaction codecs can use different location pointers
	// for the same PostgreSQL instant. Freeze UTC, not driver representation.
	v.VerifiedAt = v.VerifiedAt.UTC()
	r := RecipientRecord{Query: q, User: u, Identifier: i, Verification: v, UserAuthorityVersion: ua, IdentifierAuthorityVersion: authority, CredentialAuthorityVersion: ca, ObservedAt: row.now.UTC()}
	if r.Validate() != nil {
		return bad()
	}
	return r, nil
}

// RequireRecipient fences a selected original record during the exact native
// feature invocation. It holds primary user then identifier share locks until
// the existing coordinator commits/aborts. Changed address, ownership,
// verification or security versions deny and poison Work even if ignored.
// Suppressed selection never becomes real delivery; callers must keep their
// original no-op branch. Anonymous discovery remains separate from UserID in
// the command binding. This does not authenticate the flow or decide risk.
func (w Work) RequireRecipient(ctx context.Context, p FeatureExecutionContributor, expected RecipientRecord) error {
	if w.state == nil || w.state.featureInvocation == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidRecipient())
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.requireRecipient(ctx, b, expected)
}

func (w Work) requireRecipient(ctx context.Context, b identity.CommandBinding, expected RecipientRecord) error {
	if expected.Validate() != nil || expected.Query.TenantID != b.TenantID || expected.Query.UserID != b.UserID || b.UserID != "" && expected.User.ID != b.UserID {
		return w.fail(ctx, invalidRecipient())
	}
	if expected.Suppressed {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	selected := b
	selected.UserID = expected.User.ID
	if err := w.requireActiveUserAuthority(ctx, selected, UserAuthorityAdmission{UserAuthorityVersion: expected.UserAuthorityVersion, IdentifierAuthorityVersion: expected.IdentifierAuthorityVersion, CredentialAuthorityVersion: expected.CredentialAuthorityVersion}); err != nil {
		// A cursor precondition may reject before SQL and before the low-level
		// reader poisons Work. Cleanup must not erase this denied admission.
		return w.fail(ctx, err)
	}
	rows, err := w.Query(ctx, recipientSelect+" FOR SHARE OF i", string(b.TenantID), string(expected.Query.Kind), expected.Query.CanonicalValue)
	if err != nil {
		return w.fail(ctx, err)
	}
	current, err := readRecipient(expected.Query, rows)
	rows.Close()
	if err != nil {
		return w.fail(ctx, readFailure(ctx, err))
	}
	if current.Suppressed || current.User.ID != expected.User.ID || current.Identifier != expected.Identifier || current.Verification != expected.Verification || current.UserAuthorityVersion != expected.UserAuthorityVersion || current.IdentifierAuthorityVersion != expected.IdentifierAuthorityVersion || current.CredentialAuthorityVersion != expected.CredentialAuthorityVersion {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
