package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/username"
)

func TestUsernameRenameRequiresNativeOwnersAndOriginalCustody(t *testing.T) {
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	if service, err := NewUsernameRenameService(nil, p, UsernameRenameConfig{}, nil); service != nil || err == nil {
		t.Fatal("missing native owners advertised rename")
	}
	for _, s := range []*UsernameRenameService{nil, {}} {
		if result, err := s.Rename(context.Background(), username.RenameRequest{}); err == nil || result != (identity.CommandResult{}) {
			t.Fatal("zero service supplied rename")
		}
		if user, err := s.RenameRateSource(context.Background(), username.RenameRequest{}); err == nil || user != "" {
			t.Fatal("zero service supplied rate authority")
		}
		if result, err := s.RenameRecover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || result != (identity.CommandResult{}) {
			t.Fatal("zero service supplied original outcome")
		}
	}
}
