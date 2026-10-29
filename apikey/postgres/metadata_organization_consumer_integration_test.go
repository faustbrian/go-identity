//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	organization "github.com/faustbrian/go-organization"
)

func TestGenuineMetadataSeparatesOrganizationAndLegacyOwners(t *testing.T) {
	f := setupNativeConsumer(t)
	self, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := self.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	selfRecord := metadataIssue(t, f, self, f.caller, "self-before-organization-metadata")
	installOrganizationKeyOwners(t, f)
	installMetadataPages(t, f, false)
	installMetadataPages(t, f, true)
	orgID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(orgID))
	legacy := config.LegacyConfiguration.Spec()
	legacy.AllowLegacyNoExpiry = true
	config.LegacyConfiguration, err = apikey.NewConfiguration(legacy)
	if err != nil {
		t.Fatal(err)
	}
	config.ValidateCanonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id != "01ARZ3NDEKTSV4RRFFQ69G5FAZ" && id != "01ARZ3NDEKTSV4RRFFQ69G5FAY" && id != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
			return apikey.ErrInvalid
		}
		return nil
	}
	config = metadataPolicy(t, config, metadataConsumerPolicy{base: organizationKeyConsumerPolicy{base: &baselineEvaluator{}, org: organization.ID(orgID)}})
	service, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeLegacyConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	actualOrgAuthentication := func(a apikey.Authentication) organization.Authentication {
		return organization.Authentication{TenantID: a.TenantID, Bearer: a.Bearer}
	}
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: actualOrgAuthentication(f.caller), CommandID: commandID(t), ID: organization.ID(orgID), Slug: "metadata-owner", Name: "Metadata owner", CorrelationID: "metadata-actual-org-create"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, create); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual metadata organization creation", err)
	}
	createKey, _ := identity.NewIdempotencyKey([]byte("metadata-organization-modern"))
	issued, err := service.CreateOrganization(f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: createKey, Name: "organization metadata", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.44"}, OrganizationID: apikey.OrganizationID(orgID)})
	if err != nil {
		t.Fatal("actual modern organization metadata specimen", err)
	}
	orgRecord, ok := issued.Record()
	if !ok {
		t.Fatal("actual organization key record absent")
	}
	importedRecords := []apikey.Record{orgRecord, orgRecord, selfRecord}
	ids := []apikey.KeyID{"01ARZ3NDEKTSV4RRFFQ69G5FAZ", "01ARZ3NDEKTSV4RRFFQ69G5FAY", "01ARZ3NDEKTSV4RRFFQ69G5FAV"}
	for i := range importedRecords {
		r := &importedRecords[i]
		r.ID, r.RootID, r.RootVersion = ids[i], ids[i], r.AuthorityVersion
		r.ConfigurationID, r.ConfigurationRevision = legacy.ID, legacy.Revision
		r.CreatedAt, r.ExpiresAt = time.Now().UTC().Add(-500*24*time.Hour).Truncate(time.Microsecond), time.Time{}
		if i == 1 {
			r.Status, r.Grant = apikey.KeyRevoked, []string{}
			r.ExpiresAt = r.CreatedAt.Add(24 * time.Hour)
		}
		key, _ := identity.NewIdempotencyKey([]byte("metadata-import-" + string(r.ID)))
		digest, _ := apikey.NewLegacyDigest(sha256.Sum256([]byte("source-digest-" + string(r.ID))))
		out, err := service.Import(f.ctx, apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: key, Record: *r, Digest: digest, SourceID: "authenticated-source", SourceVersion: 7, Network: "192.0.2.44"})
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual authorized digest-only metadata import", err)
		}
	}
	reader := metadataReader(t, service)
	second, secondID := f.register()
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: second, OrganizationID: apikey.OrganizationID(orgID), KeyID: orgRecord.ID}); !errors.Is(err, apikey.ErrDenied) || out.Record.ID != "" {
		t.Fatal("nonmember human obtained explicit organization metadata", err)
	}
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: actualOrgAuthentication(f.caller), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: secondID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "metadata-actual-add-owner"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual metadata membership admission", err)
	}
	before := metadataState(t, f)
	for i, expected := range importedRecords {
		request := apikey.GetRequest{Authentication: f.caller, KeyID: expected.ID}
		if i < 2 {
			request.OrganizationID = apikey.OrganizationID(orgID)
		}
		got, err := reader.Get(f.ctx, request)
		if err != nil || got.Record.ID != expected.ID || got.Record.Owner != expected.Owner || got.Record.Status != expected.Status || !got.Record.ExpiresAt.Equal(expected.ExpiresAt) {
			t.Fatal("stored legacy terminal/no-expiry metadata changed or disappeared", err)
		}
	}
	selfPage, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Limit: 200})
	if err != nil || len(selfPage.Records) != 2 || selfPage.NextCursor != "" {
		t.Fatal("self metadata mixed organization ownership or lost legacy profile", err)
	}
	for _, r := range selfPage.Records {
		if r.Owner.Spec().Kind != apikey.OwnerUser || r.Owner.Spec().UserID != f.user {
			t.Fatal("organization key appeared in implicit self-owner list")
		}
	}
	request := apikey.ListRequest{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), Limit: 1}
	var seen []apikey.KeyID
	var firstCursor string
	for page := 0; page < 4; page++ {
		restarted, err := apikeypg.NewOrganizationService(f.pool, config, repository)
		if err != nil {
			t.Fatal(err)
		}
		out, err := metadataReader(t, restarted).List(f.ctx, request)
		if err != nil || len(out.Records) != 1 || out.Records[0].Owner != orgRecord.Owner {
			t.Fatal("actual organization metadata page/reconstruction", err)
		}
		seen = append(seen, out.Records[0].ID)
		if page == 0 {
			firstCursor = out.NextCursor
		}
		if out.NextCursor == "" {
			break
		}
		request.Cursor = out.NextCursor
	}
	expectedIDs := []apikey.KeyID{orgRecord.ID, ids[0], ids[1]}
	slices.Sort(expectedIDs)
	if !slices.Equal(seen, expectedIDs) || firstCursor == "" {
		t.Fatal("organization modern/legacy page was not stable and complete")
	}
	filtered := apikey.ListRequest{Authentication: second, OrganizationID: apikey.OrganizationID(orgID), ConfigurationIDs: []string{legacy.ID}, Limit: 200}
	if out, err := reader.List(f.ctx, filtered); err != nil || len(out.Records) != 2 || out.NextCursor != "" {
		t.Fatal("current second owner could not filter selected legacy metadata", err)
	}
	filtered.Cursor, filtered.Authentication = firstCursor, f.caller
	if out, err := reader.List(f.ctx, filtered); !errors.Is(err, apikey.ErrInvalid) || len(out.Records) != 0 {
		t.Fatal("cursor escaped its exact selected configuration scope", err)
	}
	for _, request := range []apikey.GetRequest{
		{Authentication: f.caller, KeyID: orgRecord.ID},
		{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), KeyID: selfRecord.ID},
		{Authentication: f.caller, OrganizationID: "foreign-organization", KeyID: orgRecord.ID},
	} {
		if out, err := reader.Get(f.ctx, request); err == nil || out.Record.ID != "" {
			t.Fatal("explicit organization and self owner arms were interchangeable")
		}
	}
	unselected, err := apikeypg.NewService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := metadataReader(t, unselected).List(f.ctx, apikey.ListRequest{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), Limit: 1}); !errors.Is(err, apikey.ErrDenied) || len(out.Records) != 0 {
		t.Fatal("unselected organization composition acquired metadata authority", err)
	}
	if after := metadataState(t, f); after != before {
		t.Fatal("user/organization metadata reads mutated keys, configuration or verification attempts")
	}
	remove, err := org.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: actualOrgAuthentication(second), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: f.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "metadata-remove-creator"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, remove); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual metadata creator membership removal", err)
	}
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), KeyID: orgRecord.ID}); !errors.Is(err, apikey.ErrDenied) || out.Record.ID != "" {
		t.Fatal("removed creator retained organization metadata disclosure", err)
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), Cursor: firstCursor, Limit: 1}); !errors.Is(err, apikey.ErrDenied) || len(out.Records) != 0 {
		t.Fatal("retained cursor bypassed actual current membership removal", err)
	}
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: second, OrganizationID: apikey.OrganizationID(orgID), KeyID: orgRecord.ID}); err != nil || out.Record.ID != orgRecord.ID {
		t.Fatal("creator removal denied the independent current owner", err)
	}
	metadataOrganizationPlan(t, f, config, selfRecord, orgRecord)
}
