package anonymouspostgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Config selects an installed dedicated schema and positive primary IO budget
// of at most one minute. The caller owns pool lifetime and all migration IO.
type Config struct {
	Schema          string
	MaximumDuration time.Duration
}

// Repository owns only anonymous lifecycle metadata. It borrows a PRIMARY pool,
// opens no transaction and has no goroutines or mutable global state. Read is
// concurrent-safe; borrowed Work and command custody remain serial-use.
type Repository struct {
	pool    *database.Pool
	schema  string
	maximum time.Duration
}

var _ anonymous.Store = (*Repository)(nil)

// NewRepository freezes explicit configuration without IO or state creation.
// This is neither an anonymous signin service nor session authority.
func NewRepository(pool *database.Pool, c Config) (*Repository, error) {
	if pool == nil || pool.Raw() == nil || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, anonymous.ErrInvalidInput
	}
	return &Repository{pool: pool, schema: pgx.Identifier{strings.Clone(c.Schema)}.Sanitize(), maximum: c.MaximumDuration}, nil
}

func validSchema(s string) bool {
	if len(s) == 0 || len(s) > 63 || s == "public" || s == "identity" || s == "information_schema" || strings.HasPrefix(s, "pg_") {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_' || i > 0 && s[i] >= '0' && s[i] <= '9') {
			return false
		}
	}
	return true
}

// Read returns an exact primary lifecycle projection, preserving terminal states
// and original expiry/version. No credential is accepted and no positive lease
// is issued. A session consumer must check all owners under its original bounded
// read window; absence cannot prove noncommit or authorize recreation.
func (r *Repository) Read(ctx context.Context, q anonymous.SubjectQuery) (anonymous.AnonymousSubject, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximum <= 0 || q.Validate() != nil {
		return anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := r.pool.Raw().Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2", string(q.TenantID), string(q.UserID))
	if err != nil {
		return anonymous.AnonymousSubject{}, readError(bounded, err)
	}
	defer rows.Close()
	subject, err := readSubject(rows)
	if err != nil {
		return anonymous.AnonymousSubject{}, readError(bounded, err)
	}
	spec, _ := subject.Record()
	if spec.TenantID != q.TenantID || spec.UserID != q.UserID {
		return anonymous.AnonymousSubject{}, identity.UnavailableError{}
	}
	if bounded.Err() != nil {
		return anonymous.AnonymousSubject{}, readError(bounded, bounded.Err())
	}
	return subject, nil
}

func subjectSelect(schema string) string {
	return `SELECT subject_id,tenant_id,user_id,created_at,expires_at,state,version::text,cleanup FROM ` + schema + `.subjects`
}

type subjectRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func readSubject(rows subjectRows) (anonymous.AnonymousSubject, error) {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return anonymous.AnonymousSubject{}, err
		}
		return anonymous.AnonymousSubject{}, anonymous.ErrSubjectAbsent
	}
	var id, tenant, user, version string
	var created, expires time.Time
	var state, cleanup int16
	if err := rows.Scan(&id, &tenant, &user, &created, &expires, &state, &version, &cleanup); err != nil {
		return anonymous.AnonymousSubject{}, err
	}
	if rows.Next() || rows.Err() != nil {
		return anonymous.AnonymousSubject{}, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != version || state < 1 || state > 6 || cleanup < 1 || cleanup > 3 {
		return anonymous.AnonymousSubject{}, identity.UnavailableError{}
	}
	subject, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: identity.SubjectID(id), TenantID: identity.TenantID(tenant), UserID: identity.UserID(user), CreatedAt: created, ExpiresAt: expires, State: anonymous.State(state), Version: v, Cleanup: anonymous.CleanupPolicy(cleanup)})
	if err != nil {
		return anonymous.AnonymousSubject{}, identity.UnavailableError{}
	}
	return subject, nil
}

func readError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return identity.CancelledError{}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return identity.DeadlineExceededError{}
	}
	if errors.Is(err, anonymous.ErrSubjectAbsent) {
		return anonymous.ErrSubjectAbsent
	}
	return identity.UnavailableError{}
}

func (*Repository) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.Repository(redacted)"))
}
func (*Repository) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (*Repository) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
