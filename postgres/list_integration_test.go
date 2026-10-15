//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testUserListing(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users VALUES
 ('list-main','a','active',1),('list-main','b','active',18446744073709551615),
 ('list-main','c','active',3),('list-other','a','active',4)`); err != nil {
		t.Fatal(err)
	}
	query := identity.ListUsersQuery{TenantID: "list-main", Filters: identity.UserListFilters{Statuses: []identity.Status{identity.StatusActive}}, Limit: 1, ExpiresAt: time.Now().Add(10 * time.Second)}
	first, err := repo.List(ctx, query)
	if err != nil || len(first.Users) != 1 || first.Users[0].ID != "a" || first.Next.Position() != 1 {
		t.Fatal("stable listing did not start", err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned',version=2 WHERE tenant_id='list-main' AND user_id='b';
 DELETE FROM identity.users WHERE tenant_id='list-main' AND user_id='c';
 INSERT INTO identity.users VALUES('list-main','aa','active',1)`); err != nil {
		t.Fatal(err)
	}
	other, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query.Cursor = first.Next
	second, err := other.List(ctx, query)
	if err != nil || len(second.Users) != 1 || second.Users[0].ID != "b" || second.Users[0].Version != math.MaxUint64 || second.Users[0].Status != identity.StatusActive || second.Next.Position() != 2 || second.Next.SnapshotID() != first.Next.SnapshotID() {
		t.Fatal("live changes or repository replacement changed snapshot", err)
	}
	query.Cursor = second.Next
	last, err := repo.List(ctx, query)
	if err != nil || len(last.Users) != 1 || last.Users[0].ID != "c" || last.Next != (identity.Cursor{}) {
		t.Fatal("snapshot lost deleted row or failed to end", err)
	}
	t.Run("scope and original expiry cannot change", func(t *testing.T) {
		for _, change := range []func(*identity.ListUsersQuery){
			func(q *identity.ListUsersQuery) { q.TenantID = "list-other" },
			func(q *identity.ListUsersQuery) {
				q.Filters = identity.UserListFilters{Statuses: []identity.Status{identity.StatusBanned}}
			},
			func(q *identity.ListUsersQuery) { q.ExpiresAt = q.ExpiresAt.Add(time.Nanosecond) },
			func(q *identity.ListUsersQuery) { q.Cursor, _ = identity.NewCursor(q.Cursor.SnapshotID(), 4) },
		} {
			changed := query
			change(&changed)
			page, err := repo.List(ctx, changed)
			if err == nil || len(page.Users) != 0 || page.Next != (identity.Cursor{}) {
				t.Fatal("changed snapshot scope returned data")
			}
		}
	})
	t.Run("invalid queries fail without snapshot effects", func(t *testing.T) {
		for _, change := range []func(*identity.ListUsersQuery){
			func(q *identity.ListUsersQuery) { q.Limit = 0 },
			func(q *identity.ListUsersQuery) { q.Limit = 101 },
			func(q *identity.ListUsersQuery) { q.TenantID = "" },
			func(q *identity.ListUsersQuery) { q.Filters.Statuses = nil },
			func(q *identity.ListUsersQuery) {
				q.Filters.Statuses = []identity.Status{identity.StatusActive, identity.StatusActive}
			},
			func(q *identity.ListUsersQuery) { q.Filters.Statuses = []identity.Status{"unknown"} },
			func(q *identity.ListUsersQuery) { q.Fields = []identity.FieldName{{Value: "password"}} },
			func(q *identity.ListUsersQuery) { q.ExpiresAt = time.Time{} },
			func(q *identity.ListUsersQuery) { q.ExpiresAt = time.Now().Add(16 * time.Minute) },
			func(q *identity.ListUsersQuery) {
				q.Filters.IdentifierKind, q.Filters.CanonicalIdentifier = identity.IdentifierEmail, "synthetic@example.test"
			},
		} {
			changed := query
			changed.Cursor = identity.Cursor{}
			change(&changed)
			page, err := repo.List(ctx, changed)
			if err == nil || len(page.Users) != 0 {
				t.Fatal("invalid or unsupported query was admitted")
			}
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_list_snapshots WHERE tenant_id='list-main'`).Scan(&count); err != nil || count != 1 {
			t.Fatal("invalid query allocated snapshots", count, err)
		}
	})
	t.Run("snapshot capacity aborts without partial storage", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users VALUES('list-size','size-a','active',1),('list-size','size-b','active',2)`); err != nil {
			t.Fatal(err)
		}
		small, err := NewRepository(pool, Config{MaximumDuration: time.Second, ListSnapshots: UserListSnapshotConfig{MaxUsers: 1, MaxSnapshots: 1}})
		if err != nil {
			t.Fatal(err)
		}
		q := query
		q.TenantID = "list-size"
		q.Cursor = identity.Cursor{}
		page, err := small.List(ctx, q)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || len(page.Users) != 0 {
			t.Fatal("oversized snapshot was silently truncated", err)
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_list_snapshots WHERE tenant_id='list-size'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed snapshot left partial storage", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_list_rows WHERE user_id IN ('size-a','size-b')`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed snapshot retained rows", err)
		}
		atLimit, err := NewRepository(pool, Config{MaximumDuration: time.Second, ListSnapshots: UserListSnapshotConfig{MaxUsers: 2, MaxSnapshots: 1}})
		if err != nil {
			t.Fatal(err)
		}
		q.Limit = 2
		page, err = atLimit.List(ctx, q)
		if err != nil || len(page.Users) != 2 || page.Users[0].ID != "size-a" || page.Users[1].ID != "size-b" || page.Next != (identity.Cursor{}) {
			t.Fatal("exact capacity or rolled-back quota was lost", err)
		}
	})
	t.Run("concurrent quota has one owner", func(t *testing.T) {
		limited, err := NewRepository(pool, Config{MaximumDuration: time.Second, ListSnapshots: UserListSnapshotConfig{MaxUsers: 10, MaxSnapshots: 1}})
		if err != nil {
			t.Fatal(err)
		}
		q := query
		q.TenantID, q.Cursor = "list-quota", identity.Cursor{}
		var group sync.WaitGroup
		results := make(chan error, 4)
		for range 4 {
			group.Go(func() { _, err := limited.List(ctx, q); results <- err })
		}
		group.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else {
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) {
					t.Fatal("quota failure escaped classification", err)
				}
			}
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_list_snapshots WHERE tenant_id='list-quota'`).Scan(&count); err != nil || count != 1 || successes != 1 {
			t.Fatal("concurrent snapshots exceeded quota", successes, count, err)
		}
	})
	t.Run("primary expiry and bounded pruning", func(t *testing.T) {
		q := query
		q.TenantID, q.Cursor, q.ExpiresAt = "list-expiry", identity.Cursor{}, time.Now().Add(250*time.Millisecond)
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users VALUES('list-expiry','a','active',1),('list-expiry','b','active',1)`); err != nil {
			t.Fatal(err)
		}
		page, err := repo.List(ctx, q)
		if err != nil || page.Next == (identity.Cursor{}) {
			t.Fatal("expiring snapshot did not start", err)
		}
		q.Cursor = page.Next
		if count, err := repo.PruneUserListSnapshots(ctx, q.TenantID, 1); err != nil || count != 0 {
			t.Fatal("cleanup deleted active snapshot", err)
		}
		wait, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var expired bool
			if err := pool.Raw().QueryRow(wait, `SELECT expires_at_ns <= (extract(epoch FROM clock_timestamp())*1000000000)::bigint FROM identity.user_list_snapshots WHERE snapshot_id=$1`, string(q.Cursor.SnapshotID())).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired {
				break
			}
			select {
			case <-ticker.C:
			case <-wait.Done():
				t.Fatal("primary expiry was not reached")
			}
		}
		if result, err := repo.List(ctx, q); err == nil || len(result.Users) != 0 {
			t.Fatal("expired snapshot was renewed")
		}
		if count, err := repo.PruneUserListSnapshots(ctx, q.TenantID, 1); err != nil || count != 1 {
			t.Fatal("expired cleanup failed", count, err)
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_list_rows WHERE snapshot_id=$1`, string(q.Cursor.SnapshotID())).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired snapshot rows leaked", count, err)
		}
	})
	t.Run("deadline rolls back and releases pool", func(t *testing.T) {
		lock, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, "LOCK TABLE identity.users IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
		q := query
		q.Cursor = identity.Cursor{}
		short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		page, err := repo.List(short, q)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) || len(page.Users) != 0 {
			t.Fatal("blocked listing ignored cancellation", err)
		}
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := pool.Ping(ctx); err != nil {
			t.Fatal("listing leaked pool ownership", err)
		}
	})
	t.Run("public service scans denied rows without cursor leakage", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users VALUES('list-policy','a','active',1),('list-policy','b','active',1),('list-policy','c','active',1)`); err != nil {
			t.Fatal(err)
		}
		authorize, err := authorization.NewDecisionService(listingAuthorizer{})
		if err != nil {
			t.Fatal(err)
		}
		service, err := identity.NewUserDirectoryService(repo, authorize, func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "list", PolicyVersion: 1, Reason: "visible"}, nil
		}, identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "list", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, identity.UserListConfig{CursorKey: [32]byte{1}, CursorTTL: time.Minute, ValidateCanonicalIdentifier: func(context.Context, identity.IdentifierKind, string) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		req := identity.UserListRequest{TenantID: "list-policy", Filters: query.Filters, Limit: 2, Context: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "viewer"}, Tenant: "list-policy", Action: "identity.user.list", Resource: authorization.Resource{Type: "identity.user.collection", ID: "list-policy"}}}}
		first, err := service.UserList(ctx, req)
		if err != nil || len(first.Users) != 1 || first.Users[0].ID != "a" || first.NextCursor == "" {
			t.Fatal("directory composition did not omit denied row", err)
		}
		req.Cursor = first.NextCursor
		last, err := service.UserList(ctx, req)
		if err != nil || len(last.Users) != 1 || last.Users[0].ID != "c" || last.NextCursor != "" {
			t.Fatal("omission prevented stable advancement", err)
		}
	})
	t.Run("multiple statuses merge through bounded indexes", func(t *testing.T) {
		q := query
		q.Cursor, q.Limit = identity.Cursor{}, 100
		q.Filters.Statuses = []identity.Status{identity.StatusBanned, identity.StatusActive}
		page, err := repo.List(ctx, q)
		if err != nil || len(page.Users) != 3 || page.Users[0].ID != "a" || page.Users[1].ID != "aa" || page.Users[2].ID != "b" || page.Users[2].Version != 2 || page.Next != (identity.Cursor{}) {
			t.Fatal("status merge order or projection failed", err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users
 SELECT 'list-scale',lpad(i::text,6,'0'),CASE WHEN i%2=0 THEN 'active' ELSE 'banned' END,1
 FROM generate_series(1,20000) i; ANALYZE identity.users`); err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		statement, args := listMaterialization(id, "list-scale", []string{"active", "banned"}, 100)
		var encoded []byte
		if err := pool.Raw().QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+statement, args...).Scan(&encoded); err != nil {
			t.Fatal("production materialization plan unavailable", err)
		}
		var plan any
		if err := json.Unmarshal(encoded, &plan); err != nil {
			t.Fatal(err)
		}
		indexed := 0
		var inspect func(any)
		inspect = func(node any) {
			switch value := node.(type) {
			case map[string]any:
				if value["Relation Name"] == "users" {
					kind, _ := value["Node Type"].(string)
					if !strings.Contains(kind, "Index") || value["Index Name"] != "identity_users_status_order" {
						t.Fatal("status lookup lost its tenant/status/order index")
					}
					indexed++
				}
				for _, child := range value {
					inspect(child)
				}
			case []any:
				for _, child := range value {
					inspect(child)
				}
			}
		}
		inspect(plan)
		if indexed != 2 {
			t.Fatal("not every status branch has an indexed bounded source")
		}
	})
	t.Run("corrupt retained rows return no prefix", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.user_list_rows WHERE snapshot_id=$1 AND position=3`, string(query.Cursor.SnapshotID())); err != nil {
			t.Fatal(err)
		}
		page, err := repo.List(ctx, query)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || len(page.Users) != 0 || page.Next != (identity.Cursor{}) {
			t.Fatal("corrupt snapshot became terminal success", err)
		}
	})
}

type listingAuthorizer struct{}

func (listingAuthorizer) Decide(ctx context.Context, req authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	outcome := authorization.Deny
	if req.Subject.ID == "viewer" && req.Tenant == "list-policy" && req.Action == "identity.user.list" && req.Resource.ID != "b" {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, nil
}
