package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOIDCEndSessionAdmitsOnlyItsActualClosedNativeOwner(t *testing.T) {
	op := identity.FeatureOperation{Owner: "oauth-server/oidc", OperationID: "identity.oauth-server.end-session", SchemaID: "identity.oauth-server.end-session.native-rp-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	d := ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
	if !featureContributorOwns(d, op) {
		t.Fatal("actual native OAuth owner cannot compose OIDC logout")
	}
	for name, change := range map[string]func(*identity.FeatureOperation, *ContributorDescriptor){
		"generic schema": func(op *identity.FeatureOperation, _ *ContributorDescriptor) { op.SchemaID = "generic" },
		"future version": func(op *identity.FeatureOperation, _ *ContributorDescriptor) { op.SchemaVersion++ },
		"no target": func(op *identity.FeatureOperation, _ *ContributorDescriptor) {
			op.RecordRequirement = identity.FeatureRecordOmitted
		},
		"anonymous subject": func(op *identity.FeatureOperation, _ *ContributorDescriptor) {
			op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
		"root owner alias":      func(op *identity.FeatureOperation, _ *ContributorDescriptor) { op.Owner = "oauth-server" },
		"other native contract": func(_ *identity.FeatureOperation, d *ContributorDescriptor) { d.ContractID = "different" },
		"generic child owner":   func(_ *identity.FeatureOperation, d *ContributorDescriptor) { d.Owner = "oauth-server/oidc/postgres" },
	} {
		t.Run(name, func(t *testing.T) {
			operation, owner := op, d
			change(&operation, &owner)
			if featureContributorOwns(owner, operation) {
				t.Fatal("closed logout registration was bypassed")
			}
		})
	}
}
