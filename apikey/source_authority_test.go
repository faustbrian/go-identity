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

func TestLegacySourceAuthorityPreservesSelectedExpiryAndFreshness(t *testing.T) {
	for _, absentExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "historical-expiry", true: "explicitly-absent-expiry"}[absentExpiry], func(t *testing.T) {
			modern := configuration(t)
			spec := modern.Spec()
			spec.ID, spec.Algorithm, spec.State = "legacy-source", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
			spec.AllowLegacyNoExpiry = absentExpiry
			legacy, err := apikey.NewConfiguration(spec)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)
			expires := now.Add(time.Hour)
			if absentExpiry {
				expires = time.Time{}
			}
			owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
			record := apikey.Record{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Owner: owner, Version: 3, AuthorityVersion: 2, RootID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", RootVersion: 2, ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: now.Add(-500 * 24 * time.Hour), ExpiresAt: expires, Issuer: spec.Issuer, Environment: spec.Environment, Audience: spec.Audience}
			verified := apikey.VerificationResult{Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: spec.ID, Version: 7}, ReadStartedAt: now, VerifiedAt: now.Add(time.Millisecond), ValidUntil: now.Add(10 * time.Second)}
			if verified.ValidateAt(legacy, now.Add(time.Second)) != nil {
				t.Fatal("existing legacy verification shape rejected before source binding")
			}
			binding, err := apikey.NewSourceAuthorityBinding(verified, legacy, now.Add(time.Second))
			if err != nil || binding.KeyID != record.ID || binding.Owner != owner || !binding.ExpiresAt.Equal(expires) {
				t.Fatal("legacy source binding changed exact imported identity or expiry", err)
			}
			current := apikey.SourceAuthorityObservation{Binding: binding, Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: binding.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, UserVersion: 3, UserAuthorityVersion: 2, AuthorizationVersion: 1, ReadStartedAt: now, VerifiedAt: now.Add(time.Millisecond), ValidUntil: now.Add(10 * time.Second)}
			if current.Validate(binding, legacy, now.Add(time.Second)) != nil {
				t.Fatal("selected legacy expiry prevented a bounded independent observation")
			}
			current.ValidUntil = now.Add(21 * time.Second)
			if current.Validate(binding, legacy, now.Add(time.Second)) == nil {
				t.Fatal("absent or historical expiry extended the twenty-second source window")
			}
			if binding.Validate(modern) == nil {
				t.Fatal("legacy source selected the modern configuration implicitly")
			}
			if absentExpiry {
				spec.AllowLegacyNoExpiry = false
				finite, _ := apikey.NewConfiguration(spec)
				if binding.Validate(finite) == nil {
					t.Fatal("unselected absent-expiry policy admitted the source")
				}
			}
		})
	}
}
