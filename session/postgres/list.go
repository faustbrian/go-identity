package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// ListServiceConfig composes the owned primary authentication reader and page
// reader with the existing authorization engine. Sessions owns the sole schema,
// audience, clock and authority profile. Listing selects an explicit policy
// revision and whole-call budget; its budget must cover the repository read
// budget. Configuration/dependencies must remain immutable during calls.
type ListServiceConfig struct {
	Sessions SessionServiceConfig
	Listing  session.ListConfig
}

// Format redacts keys, authority and policy configuration.
func (ListServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ListServiceConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (ListServiceConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewListService composes credential authentication, current self-list policy
// and bounded primary metadata reads without IO, writes or application stores.
// Apply kernel/authorization/session migrations first, including ListMigrationSource
// for indexed audience-scoped traversal. Borrow the PRIMARY pool until calls
// finish; never configure replicas. No goroutines, transactions or journals are
// created. Native authentication retains its documented single-factor profile;
// metadata rows are structural observations, not permission or live authority.
func NewListService(pool *database.Pool, c ListServiceConfig) (*session.ListService, error) {
	if c.Sessions.Repository.MaximumDuration > c.Listing.MaximumDuration {
		return nil, session.ErrInvalidInput
	}
	reader, err := NewSessionService(pool, c.Sessions)
	if err != nil {
		return nil, err
	}
	pages, err := NewRepository(pool, c.Sessions.Repository)
	if err != nil {
		return nil, err
	}
	return session.NewListService(reader, pages, c.Listing)
}

var _ session.SessionPageReader = (*Repository)(nil)

// ReadSessionPage reads at most Limit+1 exact tenant/user/audience rows from
// PRIMARY in one joined statement and returns at most Limit caller-owned records.
// It includes tombstones and expired records; core owns exact lifetime filtering.
// AfterSessionID is an exclusive bytewise marker, never authorization. The
// method is structural, not a public enumeration endpoint or authentication.
// Labels are empty until the owned device-metadata writer is implemented.
// Corrupt rows, interrupted reads and store failures return no partial page.
func (r *Repository) ReadSessionPage(ctx context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
	if r == nil || r.pool == nil || r.maximumDuration <= 0 || ctx == nil || !scopeID(string(q.TenantID)) || !scopeID(string(q.UserID)) || !pageAudience(q.Audience) || q.Limit < 1 || q.Limit > 100 || q.AfterSessionID != "" && !scopeID(q.AfterSessionID) {
		return session.SessionPage{}, identity.InvalidInputError{Field: "session_page"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return session.SessionPage{}, readError(bounded, err)
	}
	conn, err := r.pool.Acquire(bounded)
	if err != nil {
		return session.SessionPage{}, readError(bounded, err)
	}
	defer conn.Release()
	sql := `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest FROM ` + r.schema + `.sessions s JOIN ` + r.schema + `.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND s.user_id=$2 AND (s.record->>'Audience') COLLATE "C"=$3 AND s.session_id>$4 ORDER BY s.session_id LIMIT $5`
	rows, err := conn.Query(bounded, sql, string(q.TenantID), string(q.UserID), q.Audience, q.AfterSessionID, int(q.Limit)+1)
	if err != nil {
		return session.SessionPage{}, readError(bounded, err)
	}
	defer rows.Close()
	page := session.SessionPage{Entries: make([]session.SessionListEntry, 0, int(q.Limit))}
	last := q.AfterSessionID
	for rows.Next() {
		row := primaryStoredRow{}
		if err = row.scan(rows); err != nil {
			return session.SessionPage{}, readError(bounded, err)
		}
		stored, e := row.decode(q.TenantID, "", nil)
		if e != nil {
			return session.SessionPage{}, e
		}
		spec, e := stored.Session.Bindings()
		if e != nil || spec.UserID != q.UserID || spec.Audience != q.Audience || spec.SessionID <= last {
			return session.SessionPage{}, ErrInvalidRecord
		}
		last = spec.SessionID
		if len(page.Entries) == int(q.Limit) {
			if page.HasMore {
				return session.SessionPage{}, ErrInvalidRecord
			}
			page.HasMore = true
			continue
		}
		page.Entries = append(page.Entries, session.SessionListEntry{Session: stored.Session, Revoked: stored.Revoked, FamilyRevoked: stored.FamilyRevoked})
	}
	if err = rows.Err(); err != nil {
		return session.SessionPage{}, readError(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return session.SessionPage{}, readError(bounded, err)
	}
	return page, nil
}

func pageAudience(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
