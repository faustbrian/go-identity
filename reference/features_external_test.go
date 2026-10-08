package reference_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/reference"
)

// NATIVE-06: a zero or incomplete graph never exposes an executable feature,
// starts work, or manufactures a provider/worker owner.
func TestUnconfiguredFeatureGraphCannotAdmitWork(t *testing.T) {
	var stores reference.StoreSet
	providers, err := reference.ComposeProviders(stores)
	if err == nil {
		t.Fatal("zero stores produced providers")
	}
	workers, err := reference.ComposeWorkers(stores, providers)
	if err == nil {
		t.Fatal("zero graph produced workers")
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err == nil {
		t.Fatal("zero graph produced features")
	}
	if service, err := features.OTP(); err == nil || service != nil {
		t.Fatal("zero graph exposed OTP")
	}
	if err := features.Initialize(context.Background()); err == nil {
		t.Fatal("zero graph initialized")
	}
	if _, err := workers.ProcessDeliveryOne(context.Background(), 0); err == nil {
		t.Fatal("zero graph admitted delivery work")
	}
}
