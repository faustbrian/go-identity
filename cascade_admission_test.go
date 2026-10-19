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

func TestPhoneChangeReceiptRequiresExactPendingChangeCascade(t *testing.T) {
	makeResult := func() identity.CommandResult {
		r := removalCascadeResult(t)
		op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.update", SchemaID: "identity.phone.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		r.Binding.OperationID, r.Binding.SchemaID = op.OperationID, op.SchemaID
		r.Feature.Operation = op
		r.Cascade.Kind = identity.IdentifierChangeCascade
		return r
	}
	if err := makeResult().Validate(); err != nil {
		t.Fatal("phone change denied exact pending cascade", err)
	}
	for name, mutate := range map[string]func(*identity.CommandResult){
		"absent":             func(r *identity.CommandResult) { r.Cascade = nil },
		"removal-kind":       func(r *identity.CommandResult) { r.Cascade.Kind = identity.IdentifierRemovalCascade },
		"foreign-actor":      func(r *identity.CommandResult) { r.Binding.ActorID = "foreign" },
		"foreign-target":     func(r *identity.CommandResult) { r.Cascade.IdentifierID = "other" },
		"missing-consumer":   func(r *identity.CommandResult) { r.Cascade.Owners = r.Cascade.Owners[:9] },
		"fake-ack":           func(r *identity.CommandResult) { r.Cascade.Owners[0].Status = identity.RevocationCompleted },
		"double-record-step": func(r *identity.CommandResult) { r.Feature.AfterVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeResult()
			mutate(&r)
			if r.Validate() == nil {
				t.Fatal("invalid change admission or version step accepted")
			}
		})
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted} {
		r := makeResult()
		r.Outcome, r.AuditEventID = outcome, ""
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
		if r.Validate() == nil {
			t.Fatal("uncommitted result invented change cascade")
		}
	}
}

func TestPhoneChangeReceiptsRejectUnsupportedProfilesWithoutGenericFallback(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandResult){
		"schema": func(r *identity.CommandResult) {
			r.Feature.Operation.SchemaID, r.Binding.SchemaID = "identity.phone.update.other", "identity.phone.update.other"
		},
		"version": func(r *identity.CommandResult) {
			r.Feature.Operation.SchemaVersion, r.Binding.SchemaVersion = 2, 2
		},
		"owner": func(r *identity.CommandResult) { r.Feature.Operation.Owner = "identity/other" },
		"record-policy": func(r *identity.CommandResult) {
			r.Feature.Operation.RecordRequirement, r.Binding.RecordID = identity.FeatureRecordOmitted, ""
			r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := removalCascadeResult(t)
			r.Binding.OperationID, r.Binding.SchemaID = "identity.phone.update", "identity.phone.update.native-v1"
			r.Feature.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: r.Binding.OperationID, SchemaID: r.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			r.Cascade = nil
			change(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("unsupported phone-update profile fabricated generic success")
			}
		})
	}
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

func TestPhoneRemovalReceiptRequiresItsExactPendingSelfCascade(t *testing.T) {
	makeResult := func() identity.CommandResult {
		r := removalCascadeResult(t)
		op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.remove", SchemaID: "identity.phone.remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		r.Binding.OperationID, r.Binding.SchemaID = op.OperationID, op.SchemaID
		r.Feature.Operation = op
		return r
	}
	if err := makeResult().Validate(); err != nil {
		t.Fatal("phone removal lost its owning pending cascade", err)
	}
	for name, change := range map[string]func(*identity.CommandResult){
		"absent":    func(r *identity.CommandResult) { r.Cascade = nil },
		"actor":     func(r *identity.CommandResult) { r.Binding.ActorID = "foreign" },
		"target":    func(r *identity.CommandResult) { r.Cascade.IdentifierID = "other" },
		"completed": func(r *identity.CommandResult) { r.Cascade.Status = identity.RevocationCompleted },
		"fake-ack":  func(r *identity.CommandResult) { r.Cascade.Owners[0].Status = identity.RevocationCompleted },
		"other-operation": func(r *identity.CommandResult) {
			r.Binding.OperationID = "identity.phone.update"
			r.Binding.SchemaID = "identity.phone.update.native-v1"
			r.Feature.Operation.OperationID, r.Feature.Operation.SchemaID = r.Binding.OperationID, r.Binding.SchemaID
		},
		"unknown": func(r *identity.CommandResult) {
			r.Outcome, r.AuditEventID = identity.CommitOutcomeUnknown, ""
			r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := makeResult()
			change(&r)
			if r.Validate() == nil {
				t.Fatal("foreign or invented phone-removal cascade accepted")
			}
		})
	}
}
