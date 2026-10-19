package reference_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/reference"
)

func TestPhoneRemovalGraphZeroDenies(t *testing.T) {
	if _, err := (reference.FeatureSet{}).PhoneRemoval(); err == nil {
		t.Fatal("zero graph exposed removal")
	}
	var owner reference.PhoneRemovalService
	if _, err := owner.Remove(context.Background(), phone.RemoveRequest{}); err == nil {
		t.Fatal("zero retained handle allowed removal")
	}
}
