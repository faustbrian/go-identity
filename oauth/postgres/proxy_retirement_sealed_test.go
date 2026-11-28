package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestSealedProxyRetirementAuthorityRequiresTrustedOwner(t *testing.T) {
	source := ProxyCustodyFenceSealRequest{
		TenantID: "tenant-a", SourceCommandID: "AQEBAQEBAQEBAQEBAQEBAQ",
		CascadeID: "AgICAgICAgICAgICAgICAg", Generation: 1,
	}
	for _, owner := range []*ProxyCustodyFenceOperator{nil, {}} {
		a, err := NewSealedProxyRetirementAuthority(owner, source)
		var invalid identity.InvalidInputError
		if a != nil || !errors.As(err, &invalid) {
			t.Fatalf("unconfigured owner supplied sealed retirement authority: %v", err)
		}
	}
}
