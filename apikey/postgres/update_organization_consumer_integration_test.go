//go:build integration

package postgres_test

import (
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

func TestGenuineKeyUpdateOrganizationAndLegacySurviveCreatorRemoval(t *testing.T) {
	f := setupNativeConsumer(t)
	self, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := self.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	selfRecord := metadataIssue(t, f, self, f.caller, "self-before-organization-update")
	installOrganizationKeyOwners(t, f)
	orgID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(orgID))
	spec := config.LegacyConfiguration.Spec()
	spec.AllowLegacyNoExpiry = true
	config.LegacyConfiguration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	service, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeLegacyConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	authentication := func(a apikey.Authentication) organization.Authentication {
		return organization.Authentication{TenantID: a.TenantID, Bearer: a.Bearer}
	}
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: authentication(f.caller), CommandID: commandID(t), ID: organization.ID(orgID), Slug: "update-owner", Name: "Update owner", CorrelationID: "update-create-organization"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, create); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual Update organization creation", err)
	}
	issued, err := service.CreateOrganization(f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "organization-update-create"), Name: "organization automation", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.44"}, OrganizationID: apikey.OrganizationID(orgID)})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("organization key metadata absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal("original organization credential unavailable")
	}
	legacy := record
	legacy.ID, legacy.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ", "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	legacy.Version, legacy.AuthorityVersion, legacy.RootVersion = 7, 4, 4
	legacy.ConfigurationID, legacy.ConfigurationRevision = spec.ID, spec.Revision
	legacy.CreatedAt, legacy.ExpiresAt = time.Now().UTC().Add(-500*24*time.Hour).Truncate(time.Microsecond), time.Time{}
	legacyWire := "unchanged historical organization update credential"
	digest, err := apikey.NewLegacyDigest(sha256.Sum256([]byte(legacyWire)))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Import(f.ctx, apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "organization-update-import"), Record: legacy, Digest: digest, SourceID: "authenticated-source", SourceVersion: 9, Network: "192.0.2.44"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual no-expiry organization import", err)
	}
	expired := legacy
	expired.ID, expired.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAY", "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	expiredDigest, err := apikey.NewLegacyDigest(sha256.Sum256([]byte("expired public update specimen")))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Import(f.ctx, apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "expired-organization-update-import"), Record: expired, Digest: expiredDigest, SourceID: "authenticated-source", SourceVersion: 9, Network: "192.0.2.44"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual preserved expired source key", err)
	}
	request := apikey.UpdateRequest{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), IdempotencyKey: updateKey(t, "organization-update-first"), KeyID: record.ID, ExpectedVersion: record.Version, Name: "organization rename", Permissions: slices.Clone(record.Grant), Network: "192.0.2.44"}
	first, err := keyUpdater(t, service).Update(f.ctx, request)
	if err != nil || first.Record == nil || first.Record.Owner != record.Owner || first.Record.AuthorityVersion != record.AuthorityVersion {
		t.Fatal("actual organization name-only Update", err)
	}
	for _, bad := range []apikey.UpdateRequest{
		{Authentication: f.caller, IdempotencyKey: updateKey(t, "implicit-org-update"), KeyID: record.ID, ExpectedVersion: first.Record.Version, Name: "implicit owner", Permissions: record.Grant, Network: "192.0.2.44"},
		{Authentication: f.caller, OrganizationID: apikey.OrganizationID(orgID), IdempotencyKey: updateKey(t, "wrong-org-update"), KeyID: selfRecord.ID, ExpectedVersion: selfRecord.Version, Name: "wrong owner", Permissions: selfRecord.Grant, Network: "192.0.2.44"},
	} {
		if out, err := keyUpdater(t, service).Update(f.ctx, bad); !errors.Is(err, apikey.ErrDenied) || out.Record != nil {
			t.Fatal("Update silently exchanged self and explicit organization targets", err)
		}
	}
	second, secondID := f.register()
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: authentication(f.caller), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: secondID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "update-add-owner"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual Update second owner admission", err)
	}
	remove, err := org.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: authentication(second), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: f.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "update-remove-creator"}, "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, remove); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual Update creator removal", err)
	}
	if out, err := keyUpdater(t, service).Update(f.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Record != nil {
		t.Fatal("removed creator replayed original Update as management authority", err)
	}
	b := first.Receipt.Binding
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	if out, err := service.RecoverOrganization(f.ctx, apikey.OrganizationID(orgID), apikey.RecoveryRequest{Authentication: f.caller, Query: q}); !errors.Is(err, apikey.ErrDenied) || out.Binding.CommandID != "" {
		t.Fatal("removed creator recovered organization Update metadata", err)
	}
	expiredRequest := request
	expiredRequest.Authentication, expiredRequest.KeyID, expiredRequest.ExpectedVersion = second, expired.ID, expired.Version
	expiredRequest.IdempotencyKey = updateKey(t, "expired-organization-update-denied")
	beforeExpired := metadataState(t, f)
	if out, err := keyUpdater(t, service).Update(f.ctx, expiredRequest); !errors.Is(err, apikey.ErrDenied) || out.Record != nil || out.ConfigurationAuthority != nil || metadataState(t, f) != beforeExpired {
		t.Fatal("authorized surviving owner changed an expired source key", err)
	}
	for i, prior := range []apikey.Record{*first.Record, legacy} {
		credential := keyCredentialState(t, f, prior.ID)
		request.Authentication, request.KeyID, request.ExpectedVersion = second, prior.ID, prior.Version
		request.IdempotencyKey, request.Permissions = updateKey(t, "surviving-owner-update-"+string(prior.ID)), []string{"invoice.read"}
		out, err := keyUpdater(t, service).Update(f.ctx, request)
		profile := config.Configuration
		if i == 1 {
			profile = config.LegacyConfiguration
		}
		if err != nil || out.Validate(profile) != nil || out.Record == nil || out.Record.Owner != prior.Owner || !out.Record.ExpiresAt.Equal(prior.ExpiresAt) || out.Record.RootID != prior.RootID || out.Record.AuthorityVersion != prior.AuthorityVersion+1 || keyCredentialState(t, f, prior.ID) != credential {
			t.Fatal("surviving owner Update changed credential ownership, lineage or expiry", err)
		}
		verification := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: profile.Spec().ID, ConfigurationRevision: profile.Spec().Revision, RequiredPermissions: []string{"invoice.read"}}
		if i == 0 {
			verification.Secret, err = apikey.ParseSecret(wire)
		} else {
			verification.LegacySecret, err = apikey.ParseLegacySecret(legacyWire)
		}
		if err != nil {
			t.Fatal(err)
		}
		verified, err := service.VerifyAndConsume(f.ctx, verification)
		if err != nil || verified.Result == nil || verified.Result.Record.Owner != prior.Owner || !slices.Equal(verified.Result.Grant, []string{"invoice.read"}) {
			t.Fatal("creator removal or Update disabled independently owned narrowed credential", err)
		}
	}
}
