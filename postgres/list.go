package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// UserListSnapshotConfig bounds durable structural directory snapshots per
// tenant. Zero selects 10,000 users and 32 snapshots. Otherwise both fields
// must be positive: MaxUsers <= 100,000 and MaxSnapshots <= 32. Oversized
// results or exhausted quota fail without partial pages or storage. Lowered
// limits affect new snapshots, not existing retained continuations.
type UserListSnapshotConfig struct {
	MaxUsers     uint32
	MaxSnapshots uint32
}

func listSnapshotConfig(c UserListSnapshotConfig) (UserListSnapshotConfig, error) {
	if c == (UserListSnapshotConfig{}) {
		c = UserListSnapshotConfig{MaxUsers: 10000, MaxSnapshots: 32}
	}
	if c.MaxUsers == 0 || c.MaxUsers > 100000 || c.MaxSnapshots == 0 || c.MaxSnapshots > 32 {
		return UserListSnapshotConfig{}, identity.InvalidInputError{Field: "list_configuration"}
	}
	return c, nil
}

// List implements identity.UserListRepository using retained structural rows,
// not a live OFFSET query or an authority cache. New snapshots are atomically
// selected in bytewise ID order with exact status filters; continuations bind
// tenant, the canonical status set and original nanosecond expiry. IDs and all
// uint64 versions remain unchanged across live updates/deletion or process
// replacement. Pages contain at most 100 users. Empty means terminal; capacity
// failures are Unavailable, never silent truncation. Expired/mismatched cursors
// are InvalidInput. Cancellation/deadline retain their classifications.
//
// Only structural fields and status filters are implemented in this development
// profile. Identifier filtering requires the remaining owned identifier store
// and fails closed; arbitrary attribute search is unsupported. The public core
// service must authorize collection and each row on every call. A snapshot's
// historical status/version grants no current identity authority. No caller
// callback runs under a transaction. The caller retains pool ownership.
func (r *Repository) List(ctx context.Context, q identity.ListUsersQuery) (page identity.UserPage, err error) {
	if !r.listReady() || ctx == nil {
		return page, invalidList()
	}
	statuses, err := listQuery(q)
	if err != nil {
		return page, err
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return page, listFailure(bounded, err)
	}
	tx, err := r.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return page, listFailure(bounded, err)
	}
	defer rollbackList(tx, r.maximumDuration)
	snapshot := q.Cursor.SnapshotID()
	if snapshot == "" {
		key := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-user-list-quota-v1"), "tenant": cborText(string(q.TenantID))}))
		if _, err := tx.Exec(bounded, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(key[:8]))); err != nil {
			return page, listFailure(bounded, err)
		}
	}
	// Capture a primary clock boundary conservatively: elapsed local work can
	// only shorten the lifetime, never renew copied or continued evidence.
	boundary := time.Now()
	var now int64
	if err := tx.QueryRow(bounded, `SELECT (extract(epoch FROM clock_timestamp())*1000000000)::bigint`).Scan(&now); err != nil {
		return page, listFailure(bounded, err)
	}
	if now <= 0 {
		return page, identity.UnavailableError{}
	}
	expires := q.ExpiresAt.UnixNano()
	if expires <= now || snapshot == "" && expires-now > int64(15*time.Minute) {
		return page, invalidList()
	}
	bounded, stop := context.WithTimeout(bounded, time.Duration(expires-now)-time.Since(boundary))
	defer stop()
	if err := bounded.Err(); err != nil {
		return page, listFailure(bounded, err)
	}
	var count int64
	if snapshot == "" {
		// A single expired removal per admitted attempt keeps storage work finite.
		// Explicit maintenance can drain inactive tenants independently.
		if _, err := pruneList(bounded, tx, q.TenantID, 1); err != nil {
			return page, listFailure(bounded, err)
		}
		if err := tx.QueryRow(bounded, `SELECT count(*) FROM identity.user_list_snapshots WHERE tenant_id=$1`, string(q.TenantID)).Scan(&count); err != nil {
			return page, listFailure(bounded, err)
		}
		if count >= int64(r.listConfig.MaxSnapshots) {
			return page, identity.UnavailableError{}
		}
		snapshot, err = identity.NewSubjectID()
		if err != nil {
			return page, identity.UnavailableError{}
		}
		if _, err := tx.Exec(bounded, `INSERT INTO identity.user_list_snapshots(snapshot_id,tenant_id,statuses,expires_at_ns,row_count) VALUES($1,$2,$3,$4,0)`, string(snapshot), string(q.TenantID), statuses, expires); err != nil {
			return page, listFailure(bounded, err)
		}
		statement, args := listMaterialization(snapshot, q.TenantID, statuses, r.listConfig.MaxUsers)
		var stored int64
		if err := tx.QueryRow(bounded, statement, args...).Scan(&count, &stored); err != nil {
			return page, listFailure(bounded, err)
		}
		if count > int64(r.listConfig.MaxUsers) || count != stored {
			return page, identity.UnavailableError{}
		}
		if _, err := tx.Exec(bounded, `UPDATE identity.user_list_snapshots SET row_count=$2 WHERE snapshot_id=$1`, string(snapshot), count); err != nil {
			return page, listFailure(bounded, err)
		}
	} else {
		var storedStatuses []string
		var storedExpiry int64
		err := tx.QueryRow(bounded, `SELECT statuses,expires_at_ns,row_count FROM identity.user_list_snapshots WHERE snapshot_id=$1 AND tenant_id=$2 FOR SHARE`, string(snapshot), string(q.TenantID)).Scan(&storedStatuses, &storedExpiry, &count)
		if errors.Is(err, pgx.ErrNoRows) {
			return page, invalidList()
		}
		if err != nil {
			return page, listFailure(bounded, err)
		}
		if storedExpiry != expires || !slices.Equal(storedStatuses, statuses) || q.Cursor.Position() >= uint64(count) {
			return page, invalidList()
		}
	}
	position := q.Cursor.Position()
	rows, err := tx.Query(bounded, `SELECT position,user_id,status,version::text FROM identity.user_list_rows WHERE snapshot_id=$1 AND position>$2 ORDER BY position LIMIT $3`, string(snapshot), int64(position), int32(q.Limit))
	if err != nil {
		return page, listFailure(bounded, err)
	}
	defer rows.Close()
	users := make([]identity.User, 0, q.Limit)
	for rows.Next() {
		var rowPosition int64
		var id, status, version string
		if err := rows.Scan(&rowPosition, &id, &status, &version); err != nil {
			return page, listFailure(bounded, err)
		}
		number, err := strconv.ParseUint(version, 10, 64)
		user := identity.User{ID: identity.UserID(id), TenantID: q.TenantID, Status: identity.Status(status), Version: number}
		if err != nil || strconv.FormatUint(number, 10) != version || user.Validate(q.TenantID) != nil || rowPosition != int64(position)+int64(len(users))+1 || !slices.Contains(statuses, status) || len(users) > 0 && users[len(users)-1].ID >= user.ID {
			return page, identity.UnavailableError{}
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return page, listFailure(bounded, err)
	}
	rows.Close()
	remaining := count - int64(position)
	expected := min(remaining, int64(q.Limit))
	if int64(len(users)) != expected {
		return page, identity.UnavailableError{}
	}
	var next identity.Cursor
	if int64(position)+expected < count {
		next, err = identity.NewCursor(snapshot, position+uint64(len(users)))
		if err != nil {
			return page, identity.UnavailableError{}
		}
	}
	if err := tx.Commit(bounded); err != nil {
		// An unobserved snapshot commit never becomes a disclosed continuation.
		return page, listFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return page, listFailure(bounded, err)
	}
	return identity.UserPage{Users: users, Next: next}, nil
}

func (r *Repository) listReady() bool {
	return r != nil && r.pool != nil && r.pool.Raw() != nil && r.maximumDuration > 0 && r.maximumDuration <= time.Minute && r.listConfig.MaxUsers > 0 && r.listConfig.MaxUsers <= 100000 && r.listConfig.MaxSnapshots > 0 && r.listConfig.MaxSnapshots <= 32
}

func listQuery(q identity.ListUsersQuery) ([]string, error) {
	shape := identity.User{ID: "list", TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if shape.Validate(q.TenantID) != nil || q.Limit == 0 || q.Limit > 100 || !validFields(q.Fields) || len(q.Filters.Statuses) == 0 || len(q.Filters.Statuses) > 5 || q.Filters.IdentifierKind != "" || q.Filters.CanonicalIdentifier != "" || q.ExpiresAt.IsZero() || q.ExpiresAt.UnixNano() <= 0 || !time.Unix(0, q.ExpiresAt.UnixNano()).Equal(q.ExpiresAt) {
		return nil, invalidList()
	}
	statuses := make([]string, len(q.Filters.Statuses))
	for i, status := range q.Filters.Statuses {
		if !status.Valid() || slices.Contains(q.Filters.Statuses[:i], status) {
			return nil, invalidList()
		}
		statuses[i] = string(status)
	}
	slices.Sort(statuses)
	if q.Cursor != (identity.Cursor{}) {
		if _, err := identity.NewCursor(q.Cursor.SnapshotID(), q.Cursor.Position()); err != nil {
			return nil, invalidList()
		}
	}
	return statuses, nil
}

// Each closed status uses the existing (tenant,status,user) index independently.
// The merge reads at most five*(MaxUsers+1) structural candidates. A limit is
// applied before row numbering/storage; overflow admits no rows, never a prefix.
func listMaterialization(snapshot identity.SubjectID, tenant identity.TenantID, statuses []string, maximum uint32) (string, []any) {
	args := []any{string(snapshot), string(tenant), int32(maximum)}
	parts := make([]string, len(statuses))
	for i, status := range statuses {
		args = append(args, status)
		parts[i] = fmt.Sprintf(`(SELECT user_id,status,version FROM identity.users WHERE tenant_id=$2 AND status=$%d ORDER BY user_id LIMIT ($3::integer+1))`, i+4)
	}
	return `WITH candidates AS (` + strings.Join(parts, " UNION ALL ") + `),
 selected AS MATERIALIZED (SELECT user_id,status,version FROM candidates ORDER BY user_id LIMIT ($3::integer+1)),
 stored AS (INSERT INTO identity.user_list_rows(snapshot_id,position,user_id,status,version)
 SELECT $1,row_number() OVER (ORDER BY user_id),user_id,status,version FROM selected
 WHERE (SELECT count(*) FROM selected)<=$3 RETURNING position)
 SELECT (SELECT count(*) FROM selected),(SELECT count(*) FROM stored)`, args
}

// PruneUserListSnapshots removes at most maximum (1..32) expired snapshots for
// one exact tenant, including their rows, using primary time and SKIP LOCKED.
// This trusted maintenance storage seam grants no caller permission. Run it
// regularly for inactive tenants; no internal goroutine or pool ownership is
// created. Active/locked snapshots are never removed. Earlier deadlines win;
// errors return zero count, redacted and classified, without claiming cleanup.
func (r *Repository) PruneUserListSnapshots(ctx context.Context, tenant identity.TenantID, maximum uint32) (uint32, error) {
	if !r.listReady() || ctx == nil || maximum == 0 || maximum > 32 || (identity.User{ID: "list", TenantID: tenant, Status: identity.StatusActive, Version: 1}).Validate(tenant) != nil {
		return 0, invalidList()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	tx, err := r.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return 0, listFailure(bounded, err)
	}
	defer rollbackList(tx, r.maximumDuration)
	count, err := pruneList(bounded, tx, tenant, maximum)
	if err != nil {
		return 0, listFailure(bounded, err)
	}
	if err := tx.Commit(bounded); err != nil {
		return 0, listFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return 0, listFailure(bounded, err)
	}
	return uint32(count), nil
}

func pruneList(ctx context.Context, tx pgx.Tx, tenant identity.TenantID, maximum uint32) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM identity.user_list_snapshots s USING (
 SELECT snapshot_id FROM identity.user_list_snapshots
 WHERE tenant_id=$1 AND expires_at_ns<=(extract(epoch FROM clock_timestamp())*1000000000)::bigint
 ORDER BY expires_at_ns,snapshot_id LIMIT $2 FOR UPDATE SKIP LOCKED
) expired WHERE s.snapshot_id=expired.snapshot_id`, string(tenant), int32(maximum))
	return tag.RowsAffected(), err
}

func rollbackList(tx pgx.Tx, maximum time.Duration) {
	cleanup, stop := context.WithTimeout(context.Background(), maximum)
	defer stop()
	_ = tx.Rollback(cleanup)
}

func invalidList() error { return identity.InvalidInputError{Field: "list_query"} }
func listFailure(ctx context.Context, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.UnavailableError{}
	}
	return readFailure(ctx, err)
}
