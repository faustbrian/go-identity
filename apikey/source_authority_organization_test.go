package apikey_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func TestOrganizationSourceAuthorityRetainsIntegrationOwnerWithoutHumanEpochs(t *testing.T) {
	c := configuration(t)
	now := time.Date(2026, 11, 13, 18, 0, 0, 0, time.UTC)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	record := apikey.Record{ID: "organization-key", Owner: owner, Version: 3, AuthorityVersion: 2, RootID: "organization-key", RootVersion: 2, ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Name: "integration", Status: apikey.KeyActive, Grant: []string{"invoice.read", "invoice.write"}, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	verified := apikey.VerificationResult{Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: c.Spec().ID, Version: 7}, ReadStartedAt: now, VerifiedAt: now.Add(time.Millisecond), ValidUntil: now.Add(10 * time.Second)}
	if verified.ValidateAt(c, now.Add(time.Second)) != nil {
		t.Fatal("existing organization verification contract rejected actual owner shape")
	}
	binding, err := apikey.NewOrganizationSourceAuthorityBinding(verified, c, now.Add(time.Second))
	if err != nil || binding.Validate(c) != nil || binding.Owner != owner || binding.KeyID != record.ID || binding.RootVersion != record.RootVersion || !slices.Equal(binding.Grant, record.Grant) {
		t.Fatal("organization source lost the authenticated root or owner", err)
	}
	verified.Grant[0] = "changed"
	if !slices.Equal(binding.Grant, record.Grant) {
		t.Fatal("organization binding borrowed mutable verifier output")
	}
	verified.Grant = slices.Clone(record.Grant)
	if _, err := apikey.NewOrganizationSourceAuthorityBinding(verified, c, verified.ValidUntil); err == nil {
		t.Fatal("expired verifier output became an authenticated source")
	}
	if _, err := apikey.NewSourceAuthorityBinding(verified, c, now.Add(time.Second)); err == nil {
		t.Fatal("new organization branch changed the existing USER-only API")
	}
	for _, test := range []struct {
		name   string
		change func(*apikey.OrganizationSourceAuthorityBinding)
	}{
		{"user-owner", func(b *apikey.OrganizationSourceAuthorityBinding) {
			b.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "creator", Version: 2})
		}},
		{"missing-expiry", func(b *apikey.OrganizationSourceAuthorityBinding) { b.ExpiresAt = time.Time{} }},
		{"wrong-configuration", func(b *apikey.OrganizationSourceAuthorityBinding) { b.ConfigurationRevision++ }},
		{"wrong-audience", func(b *apikey.OrganizationSourceAuthorityBinding) { b.Audience = "another-resource" }},
		{"wrong-security-root", func(b *apikey.OrganizationSourceAuthorityBinding) { b.RootVersion++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := binding
			test.change(&invalid)
			if invalid.Validate(c) == nil {
				t.Fatal("organization binding accepted an unrelated owner/profile/root")
			}
		})
	}
	legacySpec := c.Spec()
	legacySpec.ID, legacySpec.Algorithm, legacySpec.State = "legacy-organization", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	legacy, err := apikey.NewConfiguration(legacySpec)
	if err != nil {
		t.Fatal(err)
	}
	legacyBinding := binding
	legacyBinding.ConfigurationAuthority.ConfigurationID = legacySpec.ID
	if legacyBinding.Validate(legacy) == nil {
		t.Fatal("modern organization source silently selected a legacy profile")
	}
	start := now.Add(30 * time.Second)
	current := apikey.OrganizationSourceAuthorityObservation{Binding: binding, Record: record, Owner: owner, Grant: []string{"invoice.read"}, PolicyVersion: 4, ConfigurationAuthority: binding.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, OrganizationVersion: 3, OrganizationCredentialVersion: 2, ReadStartedAt: start, VerifiedAt: start.Add(time.Millisecond), ValidUntil: start.Add(10 * time.Second)}
	current.OrganizationReadStartedAt, current.OrganizationVerifiedAt, current.OrganizationValidUntil = start, start.Add(time.Millisecond), start.Add(10*time.Second)
	if err := current.Validate(binding, c, start.Add(time.Second)); err != nil {
		t.Fatal("current organization source required a creator or user epoch", err)
	}
	// Member/role changes advance aggregate version, not credential epoch.
	// A genuinely later owner observation can survive removal of its creator.
	memberChanged := current
	memberChanged.OrganizationVersion++
	if err := memberChanged.Validate(binding, c, start.Add(time.Second)); err != nil {
		t.Fatal("organization aggregate update revoked independent integration authority", err)
	}
	for _, test := range []struct {
		name   string
		change func(*apikey.OrganizationSourceAuthorityObservation)
	}{
		{"wrong-root", func(o *apikey.OrganizationSourceAuthorityObservation) { o.Binding.RootVersion++ }},
		{"revoked-key", func(o *apikey.OrganizationSourceAuthorityObservation) { o.Record.Status = apikey.KeyRevoked }},
		{"key-security-change", func(o *apikey.OrganizationSourceAuthorityObservation) { o.Record.AuthorityVersion++ }},
		{"owner-revocation", func(o *apikey.OrganizationSourceAuthorityObservation) { o.OrganizationCredentialVersion++ }},
		{"missing-owner", func(o *apikey.OrganizationSourceAuthorityObservation) { o.OrganizationVersion = 0 }},
		{"missing-directory", func(o *apikey.OrganizationSourceAuthorityObservation) { o.TenantVersion = 0 }},
		{"expanded-grant", func(o *apikey.OrganizationSourceAuthorityObservation) { o.Grant = []string{"unissued"} }},
		{"regressed-config", func(o *apikey.OrganizationSourceAuthorityObservation) { o.ConfigurationAuthority.Version-- }},
		{"renewed-freshness", func(o *apikey.OrganizationSourceAuthorityObservation) { o.ValidUntil = start.Add(21 * time.Second) }},
		{"missing-owner-window", func(o *apikey.OrganizationSourceAuthorityObservation) { o.OrganizationReadStartedAt = time.Time{} }},
		{"renewed-owner-window", func(o *apikey.OrganizationSourceAuthorityObservation) {
			o.OrganizationValidUntil = start.Add(21 * time.Second)
		}},
		{"lost-owner-deadline", func(o *apikey.OrganizationSourceAuthorityObservation) {
			o.OrganizationValidUntil = o.ValidUntil.Add(-time.Millisecond)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := current
			test.change(&invalid)
			if invalid.Validate(binding, c, start.Add(time.Second)) == nil {
				t.Fatal("changed source authority or original freshness was accepted")
			}
		})
	}
	if current.Validate(binding, c, current.ValidUntil) == nil {
		t.Fatal("copied organization source renewed the original deadline")
	}
	if wire, err := json.Marshal(binding); err == nil || len(wire) != 0 {
		t.Fatal("organization source binding disclosed authority metadata")
	}
	if wire, err := json.Marshal(current); err == nil || len(wire) != 0 {
		t.Fatal("organization observation disclosed authority metadata")
	}
	if fmt.Sprint(binding) != "apikey.OrganizationSourceAuthorityBinding(redacted)" || fmt.Sprint(current) != "apikey.OrganizationSourceAuthorityObservation(redacted)" {
		t.Fatal("organization source formatting lost redaction")
	}
}
