// Package postgres implements the authoritative PostgreSQL identity store.
// It includes owned forward-only migrations and structural creation execution;
// complete commands, attributes and recovery remain under development.
package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Config defines finite per-read budgets. MaximumDuration must be positive and
// at most one minute; an earlier caller deadline always wins. Zero is invalid.
type Config struct{ MaximumDuration time.Duration }

// Repository reads from a caller-owned primary pool and applies structural
// creation only through exact enlisted Coordinator Work. It never closes that pool,
// starts background work or caches authority. Configure the pool with primary
// endpoints only: replica reads cannot satisfy this repository's consistency
// contract. A read is a snapshot, not authorization or revocation evidence.
// Values are safe for concurrent calls; the zero value is invalid.
type Repository struct {
	maximumDuration time.Duration
	read            func(context.Context, identity.TenantID, identity.UserID) pgx.Row
}

var _ identity.UserQueryRepository = (*Repository)(nil)

// NewRepository constructs the primary read adapter without I/O. The caller
// must migrate the database before use and keep the pool alive until all reads
// finish. Reads support UserQueryRepository; ApplyUserCreation participates in
// the creation-only coordinator profile. Attribute projections, listing and
// complete domain writes remain under development.
func NewRepository(pool *database.Pool, config Config) (*Repository, error) {
	if pool == nil || pool.Raw() == nil || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute {
		return nil, identity.InvalidInputError{Field: "postgres_configuration"}
	}
	return &Repository{maximumDuration: config.MaximumDuration, read: func(ctx context.Context, tenant identity.TenantID, user identity.UserID) pgx.Row {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return storedRow{err: err}
		}
		defer conn.Release()
		var result storedRow
		result.err = conn.QueryRow(ctx, `SELECT tenant_id, user_id, status, version::text
FROM identity.users WHERE tenant_id = $1 AND user_id = $2`, string(tenant), string(user)).Scan(&result.tenant, &result.user, &result.status, &result.version)
		return result
	}}, nil
}

// Get performs one bounded exact tenant/user lookup. Fields may select only
// id, tenant_id, status and version without duplicates; empty selects these
// structural fields. Typed attributes are not implemented by this adapter.
// Missing records return identity.ErrUserAbsent; invalid input, cancellation,
// deadline and unavailable failures use identity's redacted typed errors.
// No partial projection or driver diagnostics escape a failed read.
func (r *Repository) Get(ctx context.Context, q identity.GetUserQuery) (identity.User, error) {
	if r == nil || r.read == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute || ctx == nil {
		return identity.User{}, identity.InvalidInputError{Field: "postgres_configuration"}
	}
	shape := identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if err := shape.Validate(q.TenantID); err != nil {
		return identity.User{}, err
	}
	if !validFields(q.Fields) {
		return identity.User{}, identity.InvalidInputError{Field: "fields"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.User{}, readFailure(bounded, err)
	}
	var tenant, user, status, version string
	err := r.read(bounded, q.TenantID, q.UserID).Scan(&tenant, &user, &status, &version)
	if err != nil {
		return identity.User{}, readFailure(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return identity.User{}, readFailure(bounded, err)
	}
	// Decimal roundtrip rejects noncanonical or lossy conversion. Versions use
	// the entire uint64 range, not PostgreSQL's signed bigint subset.
	number, err := strconv.ParseUint(version, 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != version {
		return identity.User{}, identity.UnavailableError{}
	}
	result := identity.User{ID: identity.UserID(user), TenantID: identity.TenantID(tenant), Status: identity.Status(status), Version: number}
	if result.ID != q.UserID || result.Validate(q.TenantID) != nil {
		return identity.User{}, identity.UnavailableError{}
	}
	return result, nil
}

func validFields(fields []identity.FieldName) bool {
	if len(fields) > 4 {
		return false
	}
	seen := uint8(0)
	for _, field := range fields {
		var bit uint8
		switch field.Value {
		case "id":
			bit = 1
		case "tenant_id":
			bit = 2
		case "status":
			bit = 4
		case "version":
			bit = 8
		default:
			return false
		}
		if seen&bit != 0 {
			return false
		}
		seen |= bit
	}
	return true
}

func readFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return identity.DeadlineExceededError{}
	case errors.Is(err, context.Canceled):
		return identity.CancelledError{}
	case errors.Is(err, pgx.ErrNoRows):
		return identity.ErrUserAbsent
	default:
		return identity.UnavailableError{}
	}
}

// Keep driver errors private even to errors.As and formatting of returned errors.
type storedRow struct {
	tenant, user, status, version string
	err                           error
}

func (r storedRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, value := range []string{r.tenant, r.user, r.status, r.version} {
		*dest[i].(*string) = value
	}
	return nil
}
