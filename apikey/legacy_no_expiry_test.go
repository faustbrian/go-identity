package apikey_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestExplicitLegacyNoExpiryPreservesImportAndBoundedAuthority(t *testing.T) {
	spec := legacyConfiguration(t).Spec()
	spec.AllowLegacyNoExpiry = true
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal("explicit no-expiry legacy profile rejected", err)
	}
	if c.AllowsIssuance() || !c.AllowsVerification() {
		t.Fatal("historical expiry policy enabled issuance")
	}
	for _, kind := range []apikey.OwnerKind{apikey.OwnerUser, apikey.OwnerOrganization} {
		ownerSpec := apikey.OwnerSpec{TenantID: "tenant-a", Kind: kind, Version: 4}
		if kind == apikey.OwnerUser {
			ownerSpec.UserID = "user-a"
		} else {
			ownerSpec.OrganizationID = "organization-a"
		}
		owner, err := apikey.NewOwner(ownerSpec)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
		record := apikey.Record{ID: "historical-key", Owner: owner, Version: 3, AuthorityVersion: 2,
			RootID: "historical-key", RootVersion: 2, ConfigurationID: spec.ID,
			ConfigurationRevision: spec.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read"},
			CreatedAt: start.Add(-500 * 24 * time.Hour), Issuer: spec.Issuer, Environment: spec.Environment, Audience: spec.Audience}
		key, _ := identity.NewIdempotencyKey([]byte("exact-no-expiry-import"))
		digest, _ := apikey.NewLegacyDigest(sha256.Sum256([]byte("unchanged-bare-historical-credential")))
		request := apikey.ImportRequest{Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")},
			IdempotencyKey: key, Record: record, Digest: digest, SourceID: "source", SourceVersion: 9, Network: "192.0.2.1"}
		if err := request.Validate(c); err != nil {
			t.Fatal("no-expiry historical metadata rejected", err)
		}
		if !request.Record.ExpiresAt.IsZero() || !request.Record.CreatedAt.Equal(record.CreatedAt) || request.Record.Owner != owner {
			t.Fatal("import invented an expiry or changed source metadata")
		}
		if !errors.Is(request.Validate(legacyConfiguration(t)), apikey.ErrInvalid) {
			t.Fatal("unselected legacy profile admitted absent expiry")
		}
		current := apikey.CurrentAuthority{Owner: owner, OwnerActive: true, TenantActive: true,
			Permissions: []string{"invoice.read"}, PolicyVersion: 7,
			ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: spec.ID, Version: 3},
			ReadStartedAt:          start, VerifiedAt: start.Add(time.Second), ValidUntil: start.Add(20 * time.Second)}
		policy := apikey.ScopePolicy{}
		grant, err := policy.Authorize(record, current, c, []string{"invoice.read"}, start.Add(2*time.Second))
		if err != nil || len(grant) != 1 || grant[0] != "invoice.read" {
			t.Fatal("no-expiry key cannot use current authority", err)
		}
		verified := apikey.VerificationResult{Record: record, Owner: owner, Grant: grant, PolicyVersion: current.PolicyVersion,
			ConfigurationAuthority: current.ConfigurationAuthority, ReadStartedAt: current.ReadStartedAt, VerifiedAt: current.VerifiedAt, ValidUntil: current.ValidUntil}
		if err := verified.ValidateAt(c, start.Add(19*time.Second)); err != nil {
			t.Fatal("original unexpired evidence denied", err)
		}
		if err := verified.ValidateAt(c, start.Add(20*time.Second)); !errors.Is(err, apikey.ErrDenied) {
			t.Fatal("absent credential expiry renewed authoritative freshness")
		}
		if _, err := policy.Authorize(record, current, c, []string{"invoice.read"}, start.Add(20*time.Second)); !errors.Is(err, apikey.ErrDenied) {
			t.Fatal("scope authorization retained stale authority")
		}
		for _, change := range []func(*apikey.Record, *apikey.CurrentAuthority){
			func(r *apikey.Record, _ *apikey.CurrentAuthority) { r.Status = apikey.KeyRevoked },
			func(_ *apikey.Record, a *apikey.CurrentAuthority) { a.OwnerActive = false },
			func(_ *apikey.Record, a *apikey.CurrentAuthority) { a.TenantActive = false },
			func(_ *apikey.Record, a *apikey.CurrentAuthority) { a.Permissions = []string{} },
			func(r *apikey.Record, _ *apikey.CurrentAuthority) { r.ExpiresAt = start.Add(-time.Second) },
		} {
			r, a := record, current
			change(&r, &a)
			if _, err := policy.Authorize(r, a, c, []string{"invoice.read"}, start.Add(2*time.Second)); !errors.Is(err, apikey.ErrDenied) {
				t.Fatal("no-expiry profile bypassed present expiry or current eligibility")
			}
		}
		for _, at := range []time.Time{record.CreatedAt, record.CreatedAt.Add(-time.Second), start.Add(time.Nanosecond)} {
			r := request
			r.Record.ExpiresAt = at
			if !errors.Is(r.Validate(c), apikey.ErrInvalid) {
				t.Fatal("explicit no-expiry option weakened present-time validation")
			}
		}
	}
}

func TestLegacyNoExpiryCannotSelectModernIssuanceOrWeakenItsRecord(t *testing.T) {
	spec := configuration(t).Spec()
	spec.AllowLegacyNoExpiry = true
	if _, err := apikey.NewConfiguration(spec); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("legacy option enabled unbounded modern issuance")
	}
	r, c, _ := organizationVerificationResult(t)
	r.Result.Record.ExpiresAt = time.Time{}
	if err := r.Result.Record.Validate(c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("modern record lost its required expiry")
	}
}
