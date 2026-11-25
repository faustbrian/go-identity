package reference

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestDirectoryGroupRoleApplyRequiresExplicitLiveSelection(t *testing.T) {
	t.Parallel()
	if role, err := (FeatureSet{}).DirectoryGroupRoleApply(); role != nil || !errors.As(err, new(identity.InvalidInputError)) {
		t.Fatal("zero feature set must not expose a role worker", err)
	}
	source := &directoryGroupSource{}
	state := &storeState{features: &featureState{composed: true, directorySync: &directorySyncState{groups: source}}}
	features := FeatureSet{state: state}
	for _, selected := range []*directoryGroupRoleSource{nil, {}} {
		source.roles = selected
		if role, err := features.DirectoryGroupRoleApply(); role != nil || !errors.As(err, new(identity.UnavailableError)) {
			t.Fatal("source or schema selection alone must not expose a role worker", err)
		}
	}
	source.roles = &directoryGroupRoleSource{executor: new(ssopg.DirectoryGroupRoleSyncService)}
	if role, err := features.DirectoryGroupRoleApply(); err != nil || role == nil {
		t.Fatal("explicit live role selection must expose its worker", err)
	}
	state.closed = true
	if role, err := features.DirectoryGroupRoleApply(); role != nil || !errors.As(err, new(identity.UnavailableError)) {
		t.Fatal("closed graph must not expose a role worker", err)
	}
}
