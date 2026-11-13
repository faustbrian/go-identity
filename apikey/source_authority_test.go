package apikey_test

import (
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func TestSourceAuthorityPreservesAuthenticatedRootAndSeparateObservation(t *testing.T) {
	c := configuration(t)
	now := time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
	record := apikey.Record{ID: "key-a", Owner: owner, Version: 3, AuthorityVersion: 2, RootID: "key-a", RootVersion: 2, ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Name: "source", Status: apikey.KeyActive, Grant: []string{"invoice.read", "invoice.write"}, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	verified := apikey.VerificationResult{Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: c.Spec().ID, Version: 7}, ReadStartedAt: now, VerifiedAt: now.Add(time.Millisecond), ValidUntil: now.Add(10 * time.Second)}
	binding, err := apikey.NewSourceAuthorityBinding(verified, c, now.Add(time.Second))
	if err != nil || binding.Validate(c) != nil || binding.Owner != owner || binding.KeyID != record.ID || binding.RootVersion != record.RootVersion || binding.AuthorityVersion != record.AuthorityVersion || !binding.ExpiresAt.Equal(record.ExpiresAt) || !slices.Equal(binding.Grant, verified.Grant) {
		t.Fatal("fresh verified user key did not retain its exact source binding", err)
	}
	verified.Grant[0] = "changed"
	if !slices.Equal(binding.Grant, record.Grant) {
		t.Fatal("source binding borrowed mutable verification grant")
	}
	verified.Grant = slices.Clone(record.Grant)
	if _, err := apikey.NewSourceAuthorityBinding(verified, c, now.Add(11*time.Second)); err == nil {
		t.Fatal("expired bearer observation became a new authenticated source")
	}
	// A genuinely later primary read is separately represented. It neither
	// replaces the old bearer observation nor extends the credential's expiry.
	start := now.Add(30 * time.Second)
	current := apikey.SourceAuthorityObservation{Binding: binding, Record: record, Owner: owner, Grant: []string{"invoice.read"}, PolicyVersion: 4, ConfigurationAuthority: binding.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, UserVersion: 3, UserAuthorityVersion: 2, AuthorizationVersion: 1, ReadStartedAt: start, VerifiedAt: start.Add(time.Millisecond), ValidUntil: start.Add(10 * time.Second)}
	if err := current.Validate(binding, c, start.Add(time.Second)); err != nil {
		t.Fatal("distinct current source observation rejected", err)
	}
	// Existing name-only management may adopt a newer current user epoch
	// without advancing the independent key-security/root version.
	advanced := current
	advanced.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 3})
	advanced.Record.Owner = advanced.Owner
	advanced.Record.Version++
	advanced.UserAuthorityVersion = 3
	if err := advanced.Validate(binding, c, start.Add(time.Second)); err != nil {
		t.Fatal("current owner epoch adoption converted a metadata update into key revocation", err)
	}
	for _, change := range []func(*apikey.SourceAuthorityObservation){
		func(o *apikey.SourceAuthorityObservation) { o.Binding.RootVersion++ },
		func(o *apikey.SourceAuthorityObservation) { o.Record.AuthorityVersion++ },
		func(o *apikey.SourceAuthorityObservation) { o.Record.Status = apikey.KeyRevoked },
		func(o *apikey.SourceAuthorityObservation) { o.Grant = []string{"unissued"} },
		func(o *apikey.SourceAuthorityObservation) { o.ConfigurationAuthority.Version-- },
		func(o *apikey.SourceAuthorityObservation) { o.ValidUntil = start.Add(21 * time.Second) },
		func(o *apikey.SourceAuthorityObservation) { o.UserAuthorityVersion = 0 },
	} {
		invalid := current
		change(&invalid)
		if invalid.Validate(binding, c, start.Add(time.Second)) == nil {
			t.Fatal("changed root, authority, grant or deadline passed structural validation")
		}
	}
	if current.Validate(binding, c, current.ValidUntil) == nil {
		t.Fatal("expired current observation remained valid")
	}
	organization, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 2})
	binding.Owner = organization
	if binding.Validate(c) == nil {
		t.Fatal("user-only source binding selected an organization variant")
	}
}
