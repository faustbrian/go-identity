package passwordpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/username"
)

func TestUsernameAvailabilityRequiresNativeRateAndDirectoryOwners(t *testing.T) {
	policy, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	if service, err := NewUsernameAvailabilityService(nil, policy, UsernameAvailabilityConfig{}); err == nil || service != nil {
		t.Fatal("missing native owners supplied availability")
	}
	for _, service := range []*UsernameAvailabilityService{nil, {}} {
		result, err := service.Available(context.Background(), username.AvailabilityRequest{TenantID: "tenant", Username: "candidate", Network: "2001:db8::1"})
		if err == nil || result.Available {
			t.Fatal("unselected native service promised availability")
		}
	}
}
