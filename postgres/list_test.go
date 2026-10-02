package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

var _ identity.UserDirectoryRepository = (*Repository)(nil)

func TestUserListZeroRepository(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		if page, err := repo.List(context.Background(), identity.ListUsersQuery{}); err == nil || len(page.Users) != 0 || page.Next != (identity.Cursor{}) {
			t.Fatal("invalid repository returned listing")
		}
		if count, err := repo.PruneUserListSnapshots(context.Background(), "tenant-a", 1); err == nil || count != 0 {
			t.Fatal("invalid repository pruned snapshots")
		}
	}
}

func TestUserListConfigurationAndQueryBounds(t *testing.T) {
	if defaults, err := listSnapshotConfig(UserListSnapshotConfig{}); err != nil || defaults != (UserListSnapshotConfig{MaxUsers: 10000, MaxSnapshots: 32}) {
		t.Fatal("missing finite snapshot defaults")
	}
	for _, invalid := range []UserListSnapshotConfig{{MaxUsers: 1}, {MaxSnapshots: 1}, {MaxUsers: 100001, MaxSnapshots: 1}, {MaxUsers: 1, MaxSnapshots: 33}} {
		if _, err := listSnapshotConfig(invalid); err == nil {
			t.Fatal("invalid capacity admitted")
		}
	}
	statuses := []identity.Status{identity.StatusBanned, identity.StatusActive}
	q := identity.ListUsersQuery{TenantID: "tenant-a", Filters: identity.UserListFilters{Statuses: statuses}, Limit: 100, ExpiresAt: time.Now().Add(time.Minute)}
	if got, err := listQuery(q); err != nil || len(got) != 2 || got[0] != "active" || statuses[0] != identity.StatusBanned {
		t.Fatal("query canonicalization retained or changed caller state")
	}
}
