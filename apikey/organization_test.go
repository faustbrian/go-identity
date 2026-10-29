package apikey_test

import (
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestOrganizationCreateRequiresExplicitOwnerAndActualHumanBearer(t *testing.T) {
	key, _ := identity.NewIdempotencyKey([]byte("organization-key-create-original"))
	r := apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{
		Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")},
		IdempotencyKey: key, Name: "organization automation", Permissions: []string{"invoice.read"},
		ExpiresAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Network: "192.0.2.1",
	}, OrganizationID: "organization-a"}
	if err := r.Validate(); err != nil {
		t.Fatal("explicit organization target with real bearer shape rejected", err)
	}
	for _, change := range []func(*apikey.OrganizationCreateRequest){
		func(r *apikey.OrganizationCreateRequest) { r.OrganizationID = "" },
		func(r *apikey.OrganizationCreateRequest) { r.OrganizationID = "not an id" },
		func(r *apikey.OrganizationCreateRequest) { r.Authentication.Bearer = auth.BearerCredential{} },
		func(r *apikey.OrganizationCreateRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
	} {
		bad := r
		change(&bad)
		if !errors.Is(bad.Validate(), apikey.ErrInvalid) {
			t.Fatal("organization target bypassed bounded management shape")
		}
	}
}

func TestOrganizationIssuanceSeparatesOwnerFromManagerAndPreservesRevealOnce(t *testing.T) {
	verified, c, _ := organizationVerificationResult(t)
	record := verified.Result.Record
	record.ID, record.RootID = "AQEBAQEBAQEBAQEBAQEBAQ", "AQEBAQEBAQEBAQEBAQEBAQ"
	record.Version, record.AuthorityVersion, record.RootVersion = 1, 1, 1
	receipt := issuanceReceipt(identity.CommitOutcomeCommitted)
	receipt.Binding.SchemaID = "apikey-create-organization-v1"
	receipt.Feature.Operation.SchemaID = receipt.Binding.SchemaID
	secret, err := apikey.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	result, err := apikey.NewIssuanceResult(c, receipt, &record, secret)
	if err != nil {
		t.Fatal("organization key issuance borrowed manager as owner", err)
	}
	got, ok := result.Record()
	if !ok || got.Owner != record.Owner || got.Owner.Spec().UserID != "" || got.Owner.Spec().Kind != apikey.OwnerOrganization {
		t.Fatal("organization ownership lost from committed result")
	}
	if _, err := result.Reveal(); err != nil {
		t.Fatal("original committed organization invocation cannot reveal", err)
	}
	if _, err := result.Reveal(); !errors.Is(err, apikey.ErrAlreadyRevealed) {
		t.Fatal("organization credential revealed twice")
	}
	rotated := receipt
	rotationFeature := *receipt.Feature
	rotated.Feature = &rotationFeature
	rotated.Binding.OperationID, rotated.Feature.Operation.OperationID = "identity.apikey.rotate", "identity.apikey.rotate"
	rotated.Binding.SchemaID, rotated.Feature.Operation.SchemaID = "apikey-rotate-organization-v1", "apikey-rotate-organization-v1"
	recovered, err := apikey.NewIssuanceResult(c, rotated, &record, apikey.Secret{})
	if err != nil || recovered.DeliveryOutcome() != apikey.IssuanceCommittedDeliveryUnknown {
		t.Fatal("organization rotation status cannot preserve committed custody", err)
	}
	if _, err := recovered.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("organization rotation recovery reconstructed material")
	}
	unknown := receipt
	unknownFeature := *receipt.Feature
	unknown.Feature = &unknownFeature
	unknown.Outcome, unknown.Feature.AfterVersion, unknown.AuditEventID = identity.CommitOutcomeUnknown, 0, ""
	uncertain, err := apikey.NewIssuanceResult(c, unknown, nil, secret)
	if err != nil || uncertain.DeliveryOutcome() != apikey.IssuanceCommitUnknown {
		t.Fatal("organization issuance ambiguity lost original state", err)
	}
	if _, err := uncertain.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("organization unknown commit exposed invocation secret")
	}
	for _, variant := range []string{"user-schema", "wrong-operation", "human-actor-mismatch", "nonhuman-manager", "missing-manager", "foreign-tenant", "other-version", "user-owner", "foreign-flow"} {
		t.Run(variant, func(t *testing.T) {
			bad := receipt
			feature := *receipt.Feature
			bad.Feature = &feature
			switch variant {
			case "user-schema":
				bad.Binding.SchemaID, bad.Feature.Operation.SchemaID = "apikey-create-v1", "apikey-create-v1"
			case "wrong-operation":
				bad.Binding.OperationID, bad.Feature.Operation.OperationID = "identity.apikey.import", "identity.apikey.import"
			case "human-actor-mismatch":
				bad.Binding.ActorID = "another-manager"
			case "nonhuman-manager":
				bad.Binding.ActorKind = authorization.SubjectAPIKey
			case "missing-manager":
				bad.Binding.UserID = ""
			case "foreign-tenant":
				bad.Binding.TenantID = "other"
			case "other-version":
				bad.Binding.SchemaVersion, bad.Feature.Operation.SchemaVersion = 2, 2
			case "user-owner":
				userRecord := record
				userRecord.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
				if _, err := apikey.NewIssuanceResult(c, bad, &userRecord, apikey.Secret{}); err == nil {
					t.Fatal("organization schema silently issued a self-owned key")
				}
				return
			case "foreign-flow":
				bad.Binding.AnonymousFlowID = string(bad.Binding.CommandID)
			}
			if _, err := apikey.NewIssuanceResult(c, bad, &record, apikey.Secret{}); err == nil {
				t.Fatal("organization issuance accepted an unselected or foreign manager profile")
			}
		})
	}
}
