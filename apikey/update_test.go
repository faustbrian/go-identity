package apikey_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func updateRequest(t *testing.T) apikey.UpdateRequest {
	t.Helper()
	idempotency, err := identity.NewIdempotencyKey([]byte("original-bounded-update"))
	if err != nil {
		t.Fatal(err)
	}
	return apikey.UpdateRequest{
		Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")},
		IdempotencyKey: idempotency, KeyID: "retained-record", ExpectedVersion: 3,
		Name: "renamed automation", Permissions: []string{"invoice.read"}, Network: "192.0.2.44",
	}
}

func TestUpdateRequestRequiresExplicitBoundedReplacement(t *testing.T) {
	r := updateRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid explicit name/grant update was rejected", err)
	}
	r.Permissions = []string{}
	if err := r.Validate(); err != nil {
		t.Fatal("explicit deny-all grant was confused with omission", err)
	}
	r.OrganizationID = "organization-a"
	if err := r.Validate(); err != nil {
		t.Fatal("explicit organization update target was rejected", err)
	}
	for _, change := range []func(*apikey.UpdateRequest){
		func(r *apikey.UpdateRequest) { r.Authentication = apikey.Authentication{} },
		func(r *apikey.UpdateRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *apikey.UpdateRequest) { r.KeyID = "" },
		func(r *apikey.UpdateRequest) { r.KeyID = "invalid key" },
		func(r *apikey.UpdateRequest) { r.ExpectedVersion = 0 },
		func(r *apikey.UpdateRequest) { r.ExpectedVersion = ^uint64(0) },
		func(r *apikey.UpdateRequest) { r.Name = "" },
		func(r *apikey.UpdateRequest) { r.Name = strings.Repeat("n", 129) },
		func(r *apikey.UpdateRequest) { r.Name = string([]byte{0xff}) },
		func(r *apikey.UpdateRequest) { r.Permissions = nil },
		func(r *apikey.UpdateRequest) { r.Permissions = []string{"invoice.read", "invoice.read"} },
		func(r *apikey.UpdateRequest) { r.Permissions = []string{"invoice.write", "invoice.read"} },
		func(r *apikey.UpdateRequest) { r.Permissions = []string{""} },
		func(r *apikey.UpdateRequest) { r.Permissions = make([]string, 65) },
		func(r *apikey.UpdateRequest) { r.OrganizationID = "invalid organization" },
		func(r *apikey.UpdateRequest) { r.CorrelationID = strings.Repeat("c", 129) },
		func(r *apikey.UpdateRequest) { r.Network = "::ffff:192.0.2.44" },
		func(r *apikey.UpdateRequest) { r.Network = "" },
	} {
		bad := r
		change(&bad)
		if !errors.Is(bad.Validate(), apikey.ErrInvalid) {
			t.Fatal("ambiguous or unbounded keyed update was accepted")
		}
	}
}

func updateReceipt(outcome identity.CommitOutcome) identity.CommandResult {
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: "apikey-update-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "api-key", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "retained-record"}
	r := identity.CommandResult{Binding: b, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}
	if outcome == identity.CommitOutcomeCommitted {
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 3, 4
		r.AuditEventID = "audit"
	}
	if outcome == identity.CommitOutcomeInProgress {
		r.RetryAfter = time.Second
	}
	return r
}

func updateResult(t *testing.T) (apikey.UpdateResult, apikey.Configuration) {
	t.Helper()
	c := configuration(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	r := &apikey.Record{ID: "retained-record", Owner: owner, Version: 4, AuthorityVersion: 2, RootID: "retained-record", RootVersion: 2, Name: "renamed automation", Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	return apikey.UpdateResult{Receipt: updateReceipt(identity.CommitOutcomeCommitted), Record: r, ConfigurationAuthority: &apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: c.Spec().ID, Version: 5}}, c
}

func TestUpdateResultRequiresExactCommittedOutcomeAndOriginalRecord(t *testing.T) {
	r, c := updateResult(t)
	if err := r.Validate(c); err != nil {
		t.Fatal("exact committed update snapshot was rejected", err)
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		safe := apikey.UpdateResult{Receipt: updateReceipt(outcome)}
		if err := safe.Validate(c); err != nil {
			t.Fatal("original unresolved/noncommit receipt was discarded", err)
		}
		safe.Record, safe.ConfigurationAuthority = r.Record, r.ConfigurationAuthority
		if !errors.Is(safe.Validate(c), apikey.ErrInvalid) {
			t.Fatal("unproved commitment carried an authoritative update snapshot")
		}
	}
	for _, change := range []func(*apikey.UpdateResult){
		func(r *apikey.UpdateResult) { r.Record = nil },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority = nil },
		func(r *apikey.UpdateResult) { r.Record.Version++ },
		func(r *apikey.UpdateResult) { r.Record.ID = "foreign-record" },
		func(r *apikey.UpdateResult) { r.Record.Status = apikey.KeyRevoked },
		func(r *apikey.UpdateResult) { r.Record.Name = "" },
		func(r *apikey.UpdateResult) { r.Record.Name = string([]byte{0xff}) },
		func(r *apikey.UpdateResult) { r.Record.RootVersion++ },
		func(r *apikey.UpdateResult) { r.Receipt.Feature = nil },
		func(r *apikey.UpdateResult) {
			r.Receipt.Feature.BeforeVersion = 0
			r.Receipt.Feature.AfterVersion = 1
			r.Record.Version = 1
		},
		func(r *apikey.UpdateResult) { r.Receipt.Feature.Operation.SchemaVersion++ },
		func(r *apikey.UpdateResult) { r.Receipt.Binding.SchemaID = "other-schema" },
		func(r *apikey.UpdateResult) { r.Receipt.Outcome = identity.CommitOutcomeInvalid },
		func(r *apikey.UpdateResult) { r.Receipt.Binding.ActorID = "foreign-actor" },
		func(r *apikey.UpdateResult) { r.Receipt.Binding.OperationID = "identity.apikey.rotate" },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority.TenantID = "foreign" },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority.ConfigurationID = "other" },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority.Version = 0 },
	} {
		bad, c := updateResult(t)
		change(&bad)
		if !errors.Is(bad.Validate(c), apikey.ErrInvalid) {
			t.Fatal("foreign, malformed or unbound update result was accepted")
		}
	}
}

func TestUpdateResultSeparatesHumanManagerFromOrganizationOwner(t *testing.T) {
	r, c := updateResult(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	r.Record.Owner = owner
	if !errors.Is(r.Validate(c), apikey.ErrInvalid) {
		t.Fatal("self update schema silently accepted an organization-owned result")
	}
	r.Receipt.Binding.SchemaID = "apikey-update-organization-v1"
	r.Receipt.Feature.Operation.SchemaID = r.Receipt.Binding.SchemaID
	if err := r.Validate(c); err != nil {
		t.Fatal("separate organization owner and genuine human manager rejected", err)
	}
	other, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "other-tenant", Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	r.Record.Owner = other
	if !errors.Is(r.Validate(c), apikey.ErrInvalid) {
		t.Fatal("organization update snapshot crossed its original tenant")
	}
	r, c = updateResult(t)
	r.Receipt.Binding.SchemaID = "apikey-update-organization-v1"
	r.Receipt.Feature.Operation.SchemaID = r.Receipt.Binding.SchemaID
	if !errors.Is(r.Validate(c), apikey.ErrInvalid) {
		t.Fatal("organization schema silently accepted self ownership")
	}
}

func TestUpdateResultPreservesSelectedLegacyAbsentExpiryAndNameOnlyEpoch(t *testing.T) {
	r, _ := updateResult(t)
	spec := legacyConfiguration(t).Spec()
	spec.AllowLegacyNoExpiry = true
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Record.ConfigurationID, r.Record.ConfigurationRevision = spec.ID, spec.Revision
	r.Record.Issuer, r.Record.Environment, r.Record.Audience = spec.Issuer, spec.Environment, spec.Audience
	r.ConfigurationAuthority.ConfigurationID = spec.ID
	r.Record.ExpiresAt = time.Time{}
	r.Record.AuthorityVersion, r.Record.RootVersion = 1, 1
	if err := r.Validate(c); err != nil {
		t.Fatal("name-only legacy result invented an expiry or required a security-epoch change", err)
	}
	if !r.Record.ExpiresAt.IsZero() || r.Record.AuthorityVersion != 1 || r.Record.RootVersion != 1 {
		t.Fatal("structural validation mutated retained credential metadata")
	}
	if !errors.Is(r.Validate(legacyConfiguration(t)), apikey.ErrInvalid) {
		t.Fatal("absent legacy expiry was accepted without explicit selection")
	}
	if !errors.Is((apikey.UpdateResult{}).Validate(c), apikey.ErrInvalid) || !errors.Is(r.Validate(apikey.Configuration{}), apikey.ErrInvalid) {
		t.Fatal("zero result/configuration was accepted")
	}
}

func TestUpdateRequestAndResultKeepDiagnosticsRedacted(t *testing.T) {
	r, c := updateResult(t)
	request := updateRequest(t)
	for _, value := range []any{request, r} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, value)
			if strings.Contains(printed, "AAAA") || strings.Contains(printed, "tenant-a") || strings.Contains(printed, "renamed automation") || strings.Contains(printed, "invoice.read") {
				t.Fatal("update diagnostics disclosed credential or bounded private metadata")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, apikey.ErrDisclosure) {
			t.Fatal("implicit update serialization was accepted")
		}
	}
	if r.Validate(c) != nil {
		t.Fatal("diagnostics altered the original committed snapshot")
	}
}

func TestUpdateRecoveryAdmitsOnlyOriginalUpdateScope(t *testing.T) {
	b := updateReceipt(identity.CommitOutcomeUnknown).Binding
	r := apikey.RecoveryRequest{Authentication: updateRequest(t).Authentication, Query: identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}}
	if err := r.Validate(); err != nil {
		t.Fatal("exact original keyed update recovery routing was rejected", err)
	}
}
