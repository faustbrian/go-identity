package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

func TestSCIMBulkInvalidChildUsesOnlyItsOwnProtectedAudit(t *testing.T) {
	const code = FeatureFailureBulkChildInvalid
	if code != 12 {
		t.Fatal("append the invalid child journal code without renumbering")
	}
	seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCase{operation: "identity.scim.group-create"})
	seed.feature.Operation = SCIMBulkInvalidChildOperation()
	b := seed.binding
	b.OperationID, b.SchemaID, b.RecordID = seed.feature.Operation.OperationID, seed.feature.Operation.SchemaID, string(b.CommandID)
	seed.audits[0].BindingDigest[0] = 1
	p := CommandPlan{Feature: seed.feature, SubjectType: "scim_bulk_child", SCIMBulkDenial: code, Audits: seed.audits,
		Contributors: []ContributorDescriptor{seed.feature.Contributor,
			{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
			{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}}}
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		t.Fatal("encode the original resource-free denial", err)
	}
	decoded, err := decodeFeaturePlan(b, fingerprint, wire)
	if err != nil || decoded.SCIMBulkDenial != code || decoded.Lifecycle != nil {
		t.Fatal("decode the same no-effect plan", err)
	}
	if kind, target, err := featureAuditRecordScope(b, p.Feature.Operation, p.SubjectType, scimBulkApplyChildAudit); err != nil || kind != "scim_bulk_child" || target != string(b.CommandID) {
		t.Fatal("invalid child must use its own protected audit identity", kind, target, err)
	}
	for _, field := range []string{"record", "actor", "subject", "effect"} {
		t.Run(field, func(t *testing.T) {
			binding, candidate := b, p
			switch field {
			case "record":
				binding.RecordID = "foreign-resource"
			case "actor":
				binding.ActorKind = authorization.SubjectUser
			case "subject":
				candidate.SubjectType = "scim_group"
			case "effect":
				candidate.SCIMBulkDenial, candidate.Lifecycle = 0, seed.lifecycle
			}
			if _, err := encodeFeaturePlan(binding, fingerprint, candidate); err == nil {
				t.Fatal("accepted authority beyond the original invalid child")
			}
		})
	}
}

func TestSCIMBulkDenialPlanHasNoLifecycle(t *testing.T) {
	seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCases()[0])
	for _, code := range []FeatureFailureCode{FeatureFailureGroupMissing, FeatureFailureGroupVersionRequired, FeatureFailureSCIMBulkDependency} {
		p := CommandPlan{Feature: seed.feature, SubjectType: seed.subjectType,
			SCIMBulkDenial: code, Audits: append([]AuditPlan(nil), seed.audits...), Contributors: []ContributorDescriptor{
				seed.feature.Contributor,
				{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
				{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1},
			}}
		p.Audits[0].BindingDigest[0] = 7
		fingerprint := [32]byte{1}
		wire, err := encodeFeaturePlan(seed.binding, fingerprint, p)
		if err != nil {
			t.Fatal("encode a closed denial without an outbox or resource version", err)
		}
		decoded, err := decodeFeaturePlan(seed.binding, fingerprint, wire)
		if err != nil || decoded.SCIMBulkDenial != code || decoded.Lifecycle != nil || len(decoded.Contributors) != 3 {
			t.Fatal("recover the exact closed denial plan", err)
		}
		admitted := seed
		admitted.lifecycle, admitted.scimBulkDenial = nil, code
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := featureMutationAudits(t.Context(), &admitted, now, "committed"); err == nil {
			t.Fatal("a denial-only plan staged a successful audit")
		}
		denied, err := featureMutationAudits(t.Context(), &admitted, now, "conflict")
		if err != nil || len(denied) != 1 || !denied[0].Changes().NoChange() {
			t.Fatal("a denial-only plan did not stage one no-change audit", err)
		}
		for _, scenario := range []string{"lifecycle", "outbox", "actor", "parent", "retention", "outcome"} {
			t.Run(scenario, func(t *testing.T) {
				candidate, binding := p, seed.binding
				candidate.Audits = append([]AuditPlan(nil), p.Audits...)
				switch scenario {
				case "lifecycle":
					candidate.Lifecycle = seed.lifecycle
				case "outbox":
					candidate.Contributors = append(candidate.Contributors, ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1})
				case "actor":
					binding.ActorKind = authorization.SubjectUser
				case "parent":
					binding.CorrelationID = string(binding.CommandID)
				case "retention":
					candidate.Audits[0].RetentionClass = "standard"
				case "outcome":
					candidate.SCIMBulkDenial = FeatureFailureConflict
				}
				if _, err := encodeFeaturePlan(binding, fingerprint, candidate); err == nil {
					t.Fatal("admitted an incompatible denial plan")
				}
			})
		}
	}
}

func TestSCIMBulkDependencyDenialPlanAcceptsOnlyExactGroupCreate(t *testing.T) {
	seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCase{operation: "identity.scim.group-create"})
	seed.audits[0].BindingDigest[0] = 1
	plan := CommandPlan{Feature: seed.feature, SubjectType: seed.subjectType, SCIMBulkDenial: FeatureFailureSCIMBulkDependency,
		Audits: seed.audits, Contributors: []ContributorDescriptor{seed.feature.Contributor,
			{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
			{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}}}
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(seed.binding, fingerprint, plan)
	if err != nil {
		t.Fatal("a dependency can prevent the original Group create without a lifecycle", err)
	}
	got, err := decodeFeaturePlan(seed.binding, fingerprint, wire)
	if err != nil || got.SCIMBulkDenial != FeatureFailureSCIMBulkDependency || got.Lifecycle != nil {
		t.Fatal("recover the no-effect Group create dependency denial", err)
	}
	if featureFailureCodeAllowed(scimUserCreationOperation(), FeatureFailureSCIMBulkDependency) {
		t.Fatal("used Group dependency authority for a User")
	}
	plan.SCIMBulkDenial = FeatureFailureGroupMissing
	if _, err := encodeFeaturePlan(seed.binding, fingerprint, plan); err == nil {
		t.Fatal("a Group create cannot borrow the missing-projection mutation profile")
	}
}

func TestSCIMBulkGroupCreateValidationDenialHasNoEffects(t *testing.T) {
	const code = FeatureFailureGroupCreateInvalidValue
	if code != 11 {
		t.Fatal("the new journal code must append without renumbering existing codes")
	}
	seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCase{operation: "identity.scim.group-create"})
	seed.audits[0].BindingDigest[0] = 1
	plan := CommandPlan{Feature: seed.feature, SubjectType: seed.subjectType, SCIMBulkDenial: code,
		Audits: seed.audits, Contributors: []ContributorDescriptor{seed.feature.Contributor,
			{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
			{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}}}
	fingerprint := [32]byte{1}
	wire, err := encodeFeaturePlan(seed.binding, fingerprint, plan)
	if err != nil {
		t.Fatal("the exact Group-create validation denial must be journaled without a lifecycle", err)
	}
	got, err := decodeFeaturePlan(seed.binding, fingerprint, wire)
	if err != nil || got.SCIMBulkDenial != code || got.Lifecycle != nil {
		t.Fatal("recover the exact validation denial without a successful mutation plan", err)
	}
	mutation := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCases()[0])
	if featureFailureCodeAllowed(mutation.feature.Operation, code) || featureFailureCodeAllowed(scimUserCreationOperation(), code) {
		t.Fatal("another feature borrowed the Group-create validation denial")
	}
	notBulk := seed.binding
	notBulk.CorrelationID = string(notBulk.CommandID)
	if _, err := encodeFeaturePlan(notBulk, fingerprint, plan); err == nil {
		t.Fatal("an ordinary Group create borrowed a protected Bulk denial")
	}
}

func TestSCIMBulkUserMutationDenialsHaveNoUpdateOrLifecycle(t *testing.T) {
	for _, operation := range []string{"identity.scim.user-replace", "identity.scim.user-patch", "identity.scim.user-delete"} {
		t.Run(operation, func(t *testing.T) {
			seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCases()[0])
			seed.feature.Operation = scimUserUpdateOperation(operation)
			seed.binding.OperationID, seed.binding.SchemaID = operation, seed.feature.Operation.SchemaID
			seed.audits[0].BindingDigest[0] = 1
			plan := CommandPlan{Feature: seed.feature, SubjectType: "scim_user", SCIMBulkDenial: FeatureFailureSCIMBulkDependency,
				Audits: seed.audits, Contributors: []ContributorDescriptor{seed.feature.Contributor,
					{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
					{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}}}
			fingerprint := [32]byte{1}
			for _, code := range []FeatureFailureCode{FeatureFailureSCIMBulkDependency, FeatureFailureUserMissing, FeatureFailureUserVersionRequired, FeatureFailureUserVersionMismatch} {
				plan.SCIMBulkDenial = code
				wire, err := encodeFeaturePlan(seed.binding, fingerprint, plan)
				if err != nil {
					t.Fatal("an original User mutation denial must not require an update intent", code, err)
				}
				decoded, err := decodeFeaturePlan(seed.binding, fingerprint, wire)
				if err != nil || decoded.SCIMBulkDenial != code || decoded.Lifecycle != nil || decoded.SCIMUserUpdate != nil {
					t.Fatal("no-effect User denial changed during encoding", code, err)
				}
			}
			plan.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: true, ExpectedVersion: 1}
			if _, err := encodeFeaturePlan(seed.binding, fingerprint, plan); err == nil {
				t.Fatal("a no-effect denial cannot carry an update plan")
			}
		})
	}
}
