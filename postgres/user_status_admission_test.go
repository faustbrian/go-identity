package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestUserStatusAdmissionRejectsUnownedAndMalformedWithoutSQL(t *testing.T) {
	for _, mode := range []string{"zero-work", "zero-epoch", "zero-version", "foreign-user", "foreign-tenant", "inactive", "foreign-owner", "nil-owner", "nil-context", "canceled", "returned", "open-cursor"} {
		t.Run(mode, func(t *testing.T) {
			w, _, returned := otpUserCheck(t, context.Background(), "feature", "")
			owner := w.state.featureInvocation.(FeatureExecutionContributor)
			b := w.state.binding
			expected := identity.UserStatusRecord{User: identity.User{TenantID: b.TenantID, ID: b.UserID, Version: 101, Status: identity.StatusActive}, AuthorityVersion: 13}
			ctx := context.Background()
			switch mode {
			case "zero-work":
				if (Work{}).RequireActiveUserStatus(ctx, owner, expected) == nil {
					t.Fatal("zero Work admitted current-owner status")
				}
				return
			case "zero-epoch":
				expected.AuthorityVersion = 0
			case "zero-version":
				expected.User.Version = 0
			case "foreign-user":
				expected.User.ID = "foreign"
			case "foreign-tenant":
				expected.User.TenantID = "foreign"
			case "inactive":
				expected.User.Status = identity.StatusSuspended
			case "foreign-owner":
				owner = &scopeFeatureParticipant{}
			case "nil-owner":
				owner = nil
			case "nil-context":
				ctx = nil
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "returned":
				returned()
			case "open-cursor":
				w.state.rows = &WorkRows{}
			}
			if err := w.RequireActiveUserStatus(ctx, owner, expected); err == nil || w.state.sqlStarted {
				t.Fatal("unowned or malformed admission reached primary")
			}
			w.state.rows = nil
			if mode == "returned" {
				if w.state.failed != nil || w.usable() != nil {
					t.Fatal("returned invocation poisoned another call")
				}
			} else if w.state.failed == nil || w.usable() == nil {
				t.Fatal("ignored live failure left transaction usable")
			}
		})
	}
}
