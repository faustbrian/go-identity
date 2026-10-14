package postgres

import (
	"testing"
)

func TestMagicLinkConsumptionCannotBeManufacturedFromMetadata(t *testing.T) {
	reader, ok := any(Work{}).(interface {
		MagicLinkConsumption(FeatureExecutionContributor) (CapabilityReservationBinding, error)
	})
	if !ok {
		t.Fatal("session effect cannot observe same-transaction consuming custody")
	}
	if got, err := reader.MagicLinkConsumption(nil); err == nil || got != (CapabilityReservationBinding{}) {
		t.Fatal("zero invocation obtained consumption")
	}
}
