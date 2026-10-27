package apikey_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestIssuanceCannotRevealOnUnknownNoncommitOrStatusRecovery(t *testing.T) {
	secret, _ := apikey.GenerateSecret()
	c := configuration(t)
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	record := apikey.Record{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Owner: owner, Version: 1, AuthorityVersion: 1, ConfigurationID: "automation", ConfigurationRevision: 1, Status: apikey.KeyActive, CreatedAt: now, ExpiresAt: now.Add(time.Hour), RootID: "AQEBAQEBAQEBAQEBAQEBAQ", RootVersion: 1, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api"}
	staleRoot := record
	staleRoot.RootVersion = 2
	if staleRoot.Validate(c) == nil {
		t.Error("root version not bound to current key authority")
	}
	foreignRoot := record
	foreignRoot.RootID = "predecessor"
	if foreignRoot.Validate(c) == nil {
		t.Error("replacement ancestor accepted as current credential root")
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict} {
		receipt := issuanceReceipt(outcome)
		r, err := apikey.NewIssuanceResult(c, receipt, nil, secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reveal(); err == nil {
			t.Fatal("unproven issuance revealed")
		}
		q, err := r.Recovery()
		if err != nil || q.CommandID != receipt.Binding.CommandID || q.TenantID != receipt.Binding.TenantID || q.ActorID != receipt.Binding.ActorID || q.UserID != receipt.Binding.UserID || q.RecordID != receipt.Binding.RecordID || q.OperationID != receipt.Binding.OperationID {
			t.Fatal("unknown result lost exact original recovery identity")
		}
	}
	// Status recovery may report committed but never takes original plaintext.
	r, err := apikey.NewIssuanceResult(c, issuanceReceipt(identity.CommitOutcomeCommitted), &record, apikey.Secret{})
	if err != nil || r.DeliveryOutcome() != apikey.IssuanceCommittedDeliveryUnknown {
		t.Fatalf("recovery: %v", err)
	}
	if _, err := r.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("status recovery revealed")
	}
	r, err = apikey.NewIssuanceResult(c, issuanceReceipt(identity.CommitOutcomeCommitted), &record, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reveal(); err != nil {
		t.Fatal(err)
	}
	if r.DeliveryOutcome() != apikey.IssuanceCommittedAndRevealed {
		t.Fatal("reveal observation lost")
	}
	if _, err := r.Reveal(); !errors.Is(err, apikey.ErrAlreadyRevealed) {
		t.Fatal("re-revealed")
	}
}

func issuanceReceipt(outcome identity.CommitOutcome) identity.CommandResult {
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.create", SchemaID: "identity.apikey.create.native-human-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "api-key", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "AQEBAQEBAQEBAQEBAQEBAQ"}
	r := identity.CommandResult{Binding: b, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}
	if outcome == identity.CommitOutcomeCommitted {
		r.Feature.AfterVersion = 1
		r.AuditEventID = "audit"
	}
	return r
}
