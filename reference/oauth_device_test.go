package reference_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferenceDeviceRoutesRequireNativeSelection(t *testing.T) {
	_, err := reference.ComposeStores(reference.StoreConfiguration{
		HTTPOAuthDevice: &reference.HTTPOAuthDeviceConfiguration{Namespace: "device-transport"},
	}, reference.ReferenceDependencies{})
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field != "reference_oauth_device" {
		t.Fatal("device HTTP without its native owner must be rejected before constructing stores", err)
	}
}
