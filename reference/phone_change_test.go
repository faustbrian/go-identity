package reference_test

import (
	"testing"

	"github.com/faustbrian/go-identity/reference"
)

func TestPhoneChangeRequiresSelectedGraph(t *testing.T) {
	if owner, err := (reference.FeatureSet{}).PhoneChange(); err == nil || owner != nil {
		t.Fatal("unselected graph exposed phone replacement")
	}
}

func TestPhoneChangeHTTPRequiresNativeOwner(t *testing.T) {
	_, err := reference.ComposeStores(reference.StoreConfiguration{
		HTTPPhoneChange: &reference.HTTPPhoneChangeConfiguration{Origin: "https://identity.example"},
	}, reference.ReferenceDependencies{})
	if err == nil {
		t.Fatal("HTTP phone replacement selected without its native dependencies")
	}
}
