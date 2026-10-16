package identity_test

import (
	"encoding/json"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func removalCascadeResult(t *testing.T) identity.CommandResult {
	t.Helper()
	r := featureResult()
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	r.Binding.OperationID, r.Binding.SchemaID, r.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	r.Binding.ActorID = identity.ActorID(r.Binding.UserID)
	r.Feature = &identity.FeatureReceipt{Operation: op, BeforeVersion: 2, AfterVersion: 3}
	id, err := identity.NewCascadeID()
	if err != nil {
		t.Fatal(err)
	}
	r.Cascade = &identity.LifecycleCascadeAdmission{CascadeID: id, Generation: 1, Kind: identity.IdentifierRemovalCascade, TenantID: r.Binding.TenantID, UserID: r.Binding.UserID, IdentifierID: identity.IdentifierID(r.Binding.RecordID), AuthorityVersion: 5, ManifestVersion: "identity-lifecycle-consumers-v1", Status: identity.RevocationPending}
	for _, owner := range identity.IdentifierRemovalConsumers() {
		r.Cascade.Owners = append(r.Cascade.Owners, identity.RevocationOwnerReceipt{Owner: owner, Status: identity.RevocationPending})
	}
	return r
}

func TestRemovalReceiptRequiresExactPendingCascade(t *testing.T) {
	r := removalCascadeResult(t)
	if err := r.Validate(); err != nil {
		t.Fatal("pending admission denied", err)
	}
	for name, alter := range map[string]func(*identity.CommandResult){
		"absent":        func(r *identity.CommandResult) { r.Cascade = nil },
		"foreign":       func(r *identity.CommandResult) { r.Cascade.UserID = "other" },
		"target":        func(r *identity.CommandResult) { r.Cascade.IdentifierID = "other" },
		"generation":    func(r *identity.CommandResult) { r.Cascade.Generation++ },
		"authority":     func(r *identity.CommandResult) { r.Cascade.AuthorityVersion = 1 },
		"completed":     func(r *identity.CommandResult) { r.Cascade.Status = identity.RevocationCompleted },
		"missing-owner": func(r *identity.CommandResult) { r.Cascade.Owners = r.Cascade.Owners[:9] },
		"fake-ack":      func(r *identity.CommandResult) { r.Cascade.Owners[0].Status = identity.RevocationCompleted },
		"duplicate":     func(r *identity.CommandResult) { r.Cascade.Owners[1] = r.Cascade.Owners[0] },
		"manifest":      func(r *identity.CommandResult) { r.Cascade.ManifestVersion = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := removalCascadeResult(t)
			alter(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("incomplete or fabricated admission admitted")
			}
		})
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress} {
		candidate := removalCascadeResult(t)
		candidate.Outcome, candidate.AuditEventID = outcome, ""
		candidate.Feature.BeforeVersion, candidate.Feature.AfterVersion = 0, 0
		if candidate.Validate() == nil {
			t.Fatal("uncommitted outcome invented cascade admission")
		}
	}
	clone := r.Cascade.Clone()
	clone.Owners[0].Status = identity.RevocationCompleted
	if r.Cascade.Owners[0].Status != identity.RevocationPending {
		t.Fatal("caller mutation changed retained admission")
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var restored identity.CommandResult
	if err := json.Unmarshal(wire, &restored); err != nil || restored.Validate() != nil || restored.Cascade.CascadeID != r.Cascade.CascadeID {
		t.Fatal("durable admission lost replay identity", err)
	}
	ordinary := featureResult()
	ordinary.Cascade = r.Cascade
	if ordinary.Validate() == nil {
		t.Fatal("unrelated feature borrowed removal cascade")
	}
}

func TestAdministrativeRemovalReceiptRetainsTargetCascadeAndDistinctHumanActor(t *testing.T) {
	r := removalCascadeResult(t)
	r.Binding.ActorID = "administrator"
	if err := r.Validate(); err != nil {
		t.Fatal("distinct human actor invalidated target-scoped historical cascade", err)
	}
	r.Cascade.UserID = identity.UserID(r.Binding.ActorID)
	if r.Validate() == nil {
		t.Fatal("actor substituted for cascade target")
	}
}
