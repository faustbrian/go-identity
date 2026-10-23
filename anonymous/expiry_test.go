package anonymous_test

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
)

func TestAbandonedSubjectRequiresExactExpiredActiveLifecycle(t *testing.T) {
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	spec := anonymous.SubjectSpec{ID: id, TenantID: "tenant-a", UserID: identity.UserID(id), CreatedAt: created, ExpiresAt: created.Add(time.Hour), State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupAnonymize}
	subject, err := anonymous.NewAnonymousSubject(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond, time.Hour} {
		at := spec.ExpiresAt.Add(offset)
		err := subject.RequireExpired(spec.TenantID, at)
		if offset < 0 && err != anonymous.ErrInactive || offset >= 0 && err != nil {
			t.Fatalf("exclusive original expiry changed at offset %s: %v", offset, err)
		}
		// Becoming cleanup-eligible must never restore browser authority.
		if offset >= 0 && subject.RequireActive(spec.TenantID, at) != anonymous.ErrInactive {
			t.Fatal("expired maintenance candidate became active again")
		}
	}
	for _, test := range []struct {
		tenant identity.TenantID
		at     time.Time
	}{{"tenant-b", spec.ExpiresAt}, {spec.TenantID, created.Add(-time.Hour)}, {spec.TenantID, time.Time{}}, {spec.TenantID, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if subject.RequireExpired(test.tenant, test.at) != anonymous.ErrInactive {
			t.Fatal("foreign tenant or invalid time admitted for cleanup")
		}
	}
	for _, state := range []anonymous.State{anonymous.StateUpgraded, anonymous.StateDeleted, anonymous.StateExpired, anonymous.StateAnonymized, anonymous.StateRetained} {
		terminal := spec
		terminal.State, terminal.Version = state, 2
		s, err := anonymous.NewAnonymousSubject(terminal)
		if err != nil {
			t.Fatal(err)
		}
		if s.RequireExpired(spec.TenantID, spec.ExpiresAt) != anonymous.ErrInactive {
			t.Fatal("terminal or upgraded guest selected for another disposal")
		}
	}
	if (anonymous.AnonymousSubject{}).RequireExpired(spec.TenantID, spec.ExpiresAt) != anonymous.ErrInvalidInput {
		t.Fatal("zero lifecycle admitted for cleanup")
	}
	if got, err := subject.Record(); err != nil || got != spec {
		t.Fatal("expiry inspection renewed or mutated lifecycle metadata", err)
	}
}
