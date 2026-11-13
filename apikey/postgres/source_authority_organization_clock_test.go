package postgres

import (
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	organization "github.com/faustbrian/go-organization"
)

// This counterexample uses only the real public owner validator. It changes no
// system/database clock and claims no bearer authentication or storage proof.
func TestOrganizationSourceClockBudgetPreservesOriginalOwnerProjection(t *testing.T) {
	configuration, record := recordFixture(t)
	spec := configuration.Spec()
	spec.ClockUncertainty = time.Second
	configuration, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal("supported clock uncertainty profile rejected", err)
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: record.Owner.Spec().TenantID, Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	record.Owner = owner
	wall := record.CreatedAt.Add(time.Second)
	orgRead := organization.CredentialAuthorityObservation{TenantID: owner.Spec().TenantID, OrganizationID: organization.ID(owner.Spec().OrganizationID), Version: 7, CredentialVersion: owner.Version(), ReadStartedAt: wall.Add(-2 * time.Millisecond), VerifiedAt: wall.Add(-time.Millisecond), ValidUntil: wall.Add(10 * time.Second)}
	query := organization.CredentialAuthorityQuery{TenantID: orgRead.TenantID, OrganizationID: orgRead.OrganizationID}
	if err := orgRead.Validate(query, wall); err != nil {
		t.Fatal("original native owner projection rejected", err)
	}
	// The selected profile permits this relative offset. Its conservative source
	// deadline is still earlier than either owner's expiry; no clock is changed.
	dbOffset := 250 * time.Millisecond
	if dbOffset >= configuration.Spec().ClockUncertainty {
		t.Fatal("counterexample exceeds the supported clock budget")
	}
	dbNow := wall.Add(dbOffset)
	binding := apikey.OrganizationSourceAuthorityBinding{ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: owner.Spec().TenantID, ConfigurationID: spec.ID, Version: 1}, ConfigurationRevision: spec.Revision, KeyID: record.ID, Owner: owner, AuthorityVersion: record.AuthorityVersion, RootID: record.RootID, RootVersion: record.RootVersion, Issuer: record.Issuer, Environment: record.Environment, Audience: record.Audience, Grant: slices.Clone(record.Grant), ExpiresAt: record.ExpiresAt}
	observed := apikey.OrganizationSourceAuthorityObservation{Binding: binding, Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 9, ConfigurationAuthority: binding.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, OrganizationVersion: orgRead.Version, OrganizationCredentialVersion: orgRead.CredentialVersion, ReadStartedAt: dbNow.Add(-2 * time.Millisecond), VerifiedAt: dbNow.Add(-time.Millisecond), ValidUntil: orgRead.ValidUntil}
	observed.OrganizationReadStartedAt, observed.OrganizationVerifiedAt, observed.OrganizationValidUntil = orgRead.ReadStartedAt, orgRead.VerifiedAt, orgRead.ValidUntil
	if err := observed.Validate(binding, configuration, dbNow); err != nil {
		t.Fatal("source rejected the otherwise-supported bounded clock profile", err)
	}
	fenced := sourceOrganizationAuthority(observed)
	if err := fenced.Validate(query, wall); err != nil {
		t.Fatal("source fence retimed valid owner evidence under supported DB clock uncertainty", err)
	}
	if fenced != orgRead {
		t.Fatal("source fence changed original owner projection timestamps")
	}
}
