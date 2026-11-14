package postgres

import (
	"slices"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestOrganizationReductionDecisionRetainsNonhumanOwner(t *testing.T) {
	p, configuration, record := organizationVerificationFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	d := apikey.PermissionReductionDecision{CommandID: id, KeyID: record.ID, Owner: record.Owner, ExpectedKeyVersion: record.Version, ExpectedAuthorityVersion: record.AuthorityVersion, PolicyVersion: p.service.config().PolicyVersion, PriorGrant: slices.Clone(record.Grant), EffectiveCurrentGrant: []string{}, Grant: []string{}, Disposition: apikey.PermissionReductionNarrow, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: record.Owner.Spec().TenantID, ConfigurationID: configuration.Spec().ID, Version: 1}}
	if err := d.Validate(); err != nil {
		t.Fatal("valid strict organization decision fixture rejected", err)
	}
	store := &PermissionReductionStore{primary: p.service, config: PermissionReductionStoreConfig{TenantID: record.Owner.Spec().TenantID, ActorID: "maintenance", ActorPolicyNamespace: "maintenance"}, organizationID: record.Owner.Spec().OrganizationID}
	if err := store.validateDecision(d); err != nil {
		t.Fatal("real organization reduction cannot retain its distinct nonhuman owner", err)
	}
	op := store.operation()
	if op.SchemaID != "apikey-permission-reduction-organization-v1" || op.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || op.RecordRequirement != identity.FeatureRecordRequired {
		t.Fatal("organization reduction used USER subject/original schema")
	}
	other := d.Owner.Spec()
	other.OrganizationID = "other-organization"
	d.Owner, err = apikey.NewOwner(other)
	if err != nil {
		t.Fatal(err)
	}
	if store.validateDecision(d) == nil {
		t.Fatal("organization maintenance admitted a different fixed owner")
	}
}
