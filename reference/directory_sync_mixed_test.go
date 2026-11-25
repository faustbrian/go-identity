package reference

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestDirectoryMixedApplyRequiresExplicitLiveSelection(t *testing.T) {
	t.Parallel()
	if worker, err := (FeatureSet{}).DirectoryMixedApply(); worker != nil || !errors.As(err, new(identity.InvalidInputError)) {
		t.Fatal("zero feature set must not expose a mixed worker", err)
	}
	source := &directoryGroupSource{executor: new(ssopg.DirectoryGroupSyncService), roles: &directoryGroupRoleSource{}}
	state := &storeState{features: &featureState{composed: true, directorySync: &directorySyncState{groups: source}}}
	features := FeatureSet{state: state}
	for _, selected := range []*directoryMixedSource{nil, {}} {
		source.mixed = selected
		if worker, err := features.DirectoryMixedApply(); worker != nil || !errors.As(err, new(identity.UnavailableError)) {
			t.Fatal("Group Apply or schema-only selection must not expose mixed execution", err)
		}
	}
	source.mixed = &directoryMixedSource{executor: new(ssopg.DirectoryMixedSyncService)}
	worker, err := features.DirectoryMixedApply()
	if err != nil || worker == nil {
		t.Fatal("explicit live selection must expose the mixed worker", err)
	}
	state.closed = true
	if _, err := worker.Apply(t.Context(), ssopg.DirectoryMixedApplyRequest{}); !errors.As(err, new(identity.UnavailableError)) {
		t.Fatal("previously obtained handle must respect graph shutdown", err)
	}
}
