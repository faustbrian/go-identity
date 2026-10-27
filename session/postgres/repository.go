package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ErrRecordAbsent reports no structurally matching record in the exact tenant.
// These trusted storage reads are not a public enumeration or login endpoint.
var ErrRecordAbsent = errors.New("session/postgres: record absent")

// Config selects the migrated dedicated Schema and a finite primary read
// budget, positive and at most one minute. An earlier caller deadline wins.
// Zero is invalid. Schema must match MigrationSource permanently.
type Config struct {
	Schema          string
	MaximumDuration time.Duration
}

// StoredSession is a structural primary projection, NOT proof of authentication
// or current authority. Session retains its original authority snapshot;
// CurrentFamilyVersion and tombstones are separately read current family facts.
// Callers must deny revoked families/records and perform every online authority,
// scope, expiry and bounded-validity check before accepting a credential. No
// method here mints a bearer, renews evidence, or changes the stored vector.
type StoredSession struct {
	Session                session.Session
	Revoked, FamilyRevoked bool
	CurrentFamilyVersion   uint64
}

// Repository owns no pool, transaction, cache or background goroutine. It reads
// one atomic joined record from the caller-owned PRIMARY pool; never configure
// replicas. It is safe for concurrent reads. The caller closes the pool after
// all operations finish. Zero is invalid. Native family revocation writes use
// only the active shared-coordinator invocation. Explicitly configured native
// issuance checks current owners and uses the protected proof-bearing profile;
// complete bearer delivery and rotation remain pending.
type Repository struct {
	pool                       *database.Pool
	schema                     string
	maximumDuration            time.Duration
	identifierAdmission        *IdentifierAdmissionConfig
	privacyAdmission           *PrivacyExportAdmissionConfig
	issueAdmission             *IssueAdmissionConfig
	cleanupBatch               uint32
	preAuthIssue               *preAuthIssueProfile
	cookieRevoke               *revokeCSRFInput
	revokeAdmission            *SingleFactorSessionAdmissionConfig
	revokeMFAMagicLink         *MagicLinkAdmissionConfig
	revokeMFAPassword          *IdentifierAdmissionConfig
	revokePasskey              *passkeySessionSelection
	revokeMFAPasskey           *mfaPasskeySessionSelection
	revokeOrganizationPassword *OrganizationPasswordSessionAdmission
}

// NewRepository validates configuration without IO. The database must already
// have its kernel and adapter migrations applied. It accepts no coordinator,
// transaction, Work, carrier or registry and does not manufacture domain stores.
func NewRepository(pool *database.Pool, c Config) (*Repository, error) {
	if pool == nil || pool.Raw() == nil || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, identity.InvalidInputError{Field: "session_postgres_configuration"}
	}
	return &Repository{pool: pool, schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, nil
}

// Get reads the exact tenant/session ID, including retained revocation state.
// It is structural inspection only. It cannot certify live authority, emit a
// credential or disclose another tenant's record. Errors are redacted typed
// identity cancellation/deadline/unavailable errors or ErrRecordAbsent.
func (r *Repository) Get(ctx context.Context, tenant identity.TenantID, id string) (StoredSession, error) {
	if !scopeID(string(tenant)) || !scopeID(id) {
		return StoredSession{}, identity.InvalidInputError{Field: "session_scope"}
	}
	return r.read(ctx, tenant, id, nil)
}

// Lookup performs one bounded indexed tenant/key-version/digest lookup, never
// a prefix scan or plaintext comparison. It verifies all 32 returned bytes in
// constant work and reconstructs the original complete record. Finding a row
// does not authenticate the bearer or imply expiry/revocation/authority approval.
// Digest is not an alternate client credential and must never be logged.
func (r *Repository) Lookup(ctx context.Context, tenant identity.TenantID, digest session.TokenDigest) (StoredSession, error) {
	if !scopeID(string(tenant)) || digest.KeyVersion == 0 || digest.Sum == ([32]byte{}) {
		return StoredSession{}, identity.InvalidInputError{Field: "session_lookup"}
	}
	return r.read(ctx, tenant, "", &digest)
}

func (r *Repository) read(ctx context.Context, tenant identity.TenantID, id string, digest *session.TokenDigest) (StoredSession, error) {
	if ctx == nil || r == nil || r.pool == nil || r.maximumDuration <= 0 {
		return StoredSession{}, identity.InvalidInputError{Field: "session_postgres_configuration"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return StoredSession{}, readError(bounded, err)
	}
	conn, err := r.pool.Acquire(bounded)
	if err != nil {
		return StoredSession{}, readError(bounded, err)
	}
	defer conn.Release()
	sql := `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest FROM ` + r.schema + `.sessions s JOIN ` + r.schema + `.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND `
	args := []any{string(tenant), id}
	if digest == nil {
		sql += `s.session_id=$2`
	} else {
		sql += `s.digest_version=$2 AND s.digest=$3`
		args = []any{string(tenant), int64(digest.KeyVersion), digest.Sum[:]}
	}
	row := primaryStoredRow{}
	err = row.scan(conn.QueryRow(bounded, sql, args...))
	if err != nil {
		return StoredSession{}, readError(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return StoredSession{}, readError(bounded, err)
	}
	return row.decode(tenant, id, digest)
}

// One decoder owns all indexed-column/immutable-record consistency checks,
// including structural page reads. A page cannot weaken digest or version checks.
type primaryStoredRow struct {
	payload, storedDigest                                                                                   []byte
	state, familyState, familyCurrent, expiry, storedTenant, storedID, user, family, version, familyVersion string
	digestVersion                                                                                           int64
}

func (r *primaryStoredRow) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&r.payload, &r.state, &r.familyState, &r.familyCurrent, &r.expiry, &r.storedTenant, &r.storedID, &r.user, &r.family, &r.version, &r.familyVersion, &r.digestVersion, &r.storedDigest)
}

func (r primaryStoredRow) decode(tenant identity.TenantID, id string, digest *session.TokenDigest) (StoredSession, error) {
	s, err := decodeRecord(r.payload)
	if err != nil {
		return StoredSession{}, ErrInvalidRecord
	}
	spec, err := s.Bindings()
	if err != nil {
		return StoredSession{}, ErrInvalidRecord
	}
	current, err := strconv.ParseUint(r.familyCurrent, 10, 64)
	if err != nil || current == 0 || strconv.FormatUint(current, 10) != r.familyCurrent || (r.state != "active" && r.state != "revoked") || (r.familyState != "active" && r.familyState != "revoked") {
		return StoredSession{}, ErrInvalidRecord
	}
	lifetime, err := s.Lifetime(spec.LastActivityAt)
	if err != nil || r.expiry != lifetime.ExpiresAt.UTC().Format(storedTimeLayout) || r.storedTenant != string(tenant) || spec.TenantID != tenant || r.storedID != spec.SessionID || (id != "" && r.storedID != id) || r.user != string(spec.UserID) || r.family != spec.FamilyID || r.version != strconv.FormatUint(spec.Version, 10) || r.familyVersion != strconv.FormatUint(spec.FamilyVersion, 10) || r.digestVersion != int64(spec.Lookup.KeyVersion) || subtle.ConstantTimeCompare(r.storedDigest, spec.Lookup.Sum[:]) != 1 {
		return StoredSession{}, ErrInvalidRecord
	}
	if digest != nil && (digest.KeyVersion != spec.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:]) != 1) {
		return StoredSession{}, ErrInvalidRecord
	}
	return StoredSession{Session: s, Revoked: r.state == "revoked", FamilyRevoked: r.familyState == "revoked", CurrentFamilyVersion: current}, nil
}

func scopeID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func readError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return identity.CancelledError{}
	case errors.Is(err, context.DeadlineExceeded):
		return identity.DeadlineExceededError{}
	case errors.Is(err, pgx.ErrNoRows):
		return ErrRecordAbsent
	default:
		return identity.UnavailableError{}
	}
}
