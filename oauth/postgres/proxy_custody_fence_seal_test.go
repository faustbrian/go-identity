package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyCustodyFenceSealRequiresExactGenerationSelector(t *testing.T) {
	good := ProxyCustodyFenceSealRequest{
		TenantID: "tenant-a", SourceCommandID: "AQEBAQEBAQEBAQEBAQEBAQ",
		CascadeID: "AgICAgICAgICAgICAgICAg", Generation: 1,
	}
	if err := validateProxyCustodyFenceSealRequest(good); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ProxyCustodyFenceSealRequest){
		func(r *ProxyCustodyFenceSealRequest) { r.TenantID = "" },
		func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = "not-a-command" },
		func(r *ProxyCustodyFenceSealRequest) { r.CascadeID = "AAAAAAAAAAAAAAAAAAAAAA" },
		func(r *ProxyCustodyFenceSealRequest) { r.Generation = 0 },
		func(r *ProxyCustodyFenceSealRequest) { r.Generation = 2 },
	} {
		bad := good
		change(&bad)
		var invalid identity.InvalidInputError
		if err := validateProxyCustodyFenceSealRequest(bad); !errors.As(err, &invalid) {
			t.Fatalf("wanted typed selector error, got %v", err)
		}
	}
}
