package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type row struct {
	tenant, user, status, version string
	err                           error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range []string{r.tenant, r.user, r.status, r.version} {
		*dest[i].(*string) = v
	}
	return nil
}

func TestGetPrimaryProjection(t *testing.T) {
	q := identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a"}
	for _, status := range []identity.Status{identity.StatusActive, identity.StatusBanned, identity.StatusSuspended, identity.StatusDeleted, identity.StatusAnonymized} {
		t.Run(string(status), func(t *testing.T) {
			r := &Repository{maximumDuration: time.Second, read: func(ctx context.Context, tenant identity.TenantID, user identity.UserID) pgx.Row {
				if tenant != q.TenantID || user != q.UserID {
					t.Fatal("scope changed")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded database read")
				}
				return row{"tenant-a", "user-a", string(status), "18446744073709551615", nil}
			}}
			got, err := r.Get(context.Background(), q)
			if err != nil || got.Version != math.MaxUint64 || got.Status != status || got.ID != q.UserID || got.TenantID != q.TenantID {
				t.Fatalf("unexpected projection: %v", err)
			}
		})
	}
}

func TestGetAcceptsCoreProjection(t *testing.T) {
	r := &Repository{maximumDuration: time.Second, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row {
		return row{"tenant-a", "user-a", "active", "1", nil}
	}}
	_, err := r.Get(context.Background(), identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a", Fields: []identity.FieldName{{Value: "id"}, {Value: "tenant_id"}, {Value: "status"}, {Value: "version"}}})
	if err != nil {
		t.Fatalf("core query cannot compose: %v", err)
	}
}

func TestGetRejectsInvalidInputBeforeIO(t *testing.T) {
	for _, q := range []identity.GetUserQuery{
		{}, {TenantID: "tenant-a"}, {TenantID: "bad tenant", UserID: "user-a"},
		{TenantID: "tenant-a", UserID: identity.UserID(strings.Repeat("x", 129))},
		{TenantID: "tenant-a", UserID: "user-a", Fields: []identity.FieldName{{Value: "undeclared"}}},
	} {
		r := &Repository{maximumDuration: time.Second, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row {
			t.Fatal("invalid query reached storage")
			return nil
		}}
		_, err := r.Get(context.Background(), q)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Fatalf("expected invalid input, got %v", err)
		}
	}
}

func TestGetRejectsCorruptOrWrongScopeRows(t *testing.T) {
	for _, value := range []row{
		{"tenant-b", "user-a", "active", "1", nil},
		{"tenant-a", "user-b", "active", "1", nil},
		{"tenant-a", "user-a", "unknown", "1", nil},
		{"tenant-a", "user-a", "active", "0", nil},
		{"tenant-a", "user-a", "active", "18446744073709551616", nil},
		{"tenant-a", "user-a", "active", "+1", nil},
		{"tenant-a", "user-a", "active", "01", nil},
	} {
		r := &Repository{maximumDuration: time.Second, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row { return value }}
		got, err := r.Get(context.Background(), identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a"})
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || got != (identity.User{}) {
			t.Fatalf("corrupt row escaped: %v", err)
		}
	}
}

func TestGetErrorsAreRedacted(t *testing.T) {
	for _, cause := range []error{pgx.ErrNoRows, errors.New("private-database-detail"), context.Canceled, context.DeadlineExceeded} {
		r := &Repository{maximumDuration: time.Second, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row { return row{err: cause} }}
		got, err := r.Get(context.Background(), identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a"})
		if err == nil || got != (identity.User{}) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), "private-database-detail") {
			t.Fatal("unsafe error")
		}
		if cause == pgx.ErrNoRows && !errors.Is(err, identity.ErrUserAbsent) {
			t.Fatal("absence lost")
		}
		if errors.Is(cause, context.Canceled) && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
		if errors.Is(cause, context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("deadline lost")
		}
	}
}

func TestCancelledReadDoesNotTouchStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &Repository{maximumDuration: time.Second, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row {
		t.Fatal("cancelled read reached storage")
		return nil
	}}
	_, err := r.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a"})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestNewRepositoryRejectsInvalidComposition(t *testing.T) {
	if _, err := NewRepository(nil, Config{MaximumDuration: time.Second}); err == nil {
		t.Fatal("nil pool admitted")
	}
	if _, err := (&Repository{}).Get(context.Background(), identity.GetUserQuery{TenantID: "tenant-a", UserID: "user-a"}); err == nil {
		t.Fatal("zero repository admitted")
	}
}
