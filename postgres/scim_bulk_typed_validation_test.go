package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestSCIMBulkTypedValidationClosedOperationMatrix(t *testing.T) {
	for _, resource := range []string{"user", "group"} {
		for _, method := range []string{"create", "replace", "patch", "delete"} {
			operationID := "identity.scim." + resource + "-" + method
			operation := groupFailureOperation(operationID)
			if resource == "user" {
				operation = scimUserUpdateOperation(operationID)
				if method == "create" {
					operation = scimUserCreationOperation()
				}
			}
			for _, failure := range []struct {
				name    string
				code    FeatureFailureCode
				allowed bool
			}{
				{"invalidValue", 13, true},
				{"mutability", 14, method != "delete"},
				{"invalidSyntax", 15, method == "create" || method == "replace"},
				{"invalidPath", 16, method == "patch"},
				{"untypedBadRequest", 17, true},
				{"unknown", 18, false},
			} {
				t.Run(resource+"/"+method+"/"+failure.name, func(t *testing.T) {
					if got := featureFailureCodeAllowed(operation, failure.code); got != failure.allowed {
						t.Errorf("closed operation admission = %v, want %v", got, failure.allowed)
					}
					seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCase{operation: "identity.scim.group-create"})
					seed.feature.Operation, seed.subjectType = operation, "scim_"+resource
					seed.binding.OperationID, seed.binding.SchemaID = operation.OperationID, operation.SchemaID
					seed.audits[0].BindingDigest[0] = 1
					plan := CommandPlan{Feature: seed.feature, SubjectType: seed.subjectType, SCIMBulkDenial: failure.code,
						Audits: seed.audits, Contributors: []ContributorDescriptor{seed.feature.Contributor,
							{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
							{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1}}}
					fingerprint := [32]byte{1}
					wire, err := encodeFeaturePlan(seed.binding, fingerprint, plan)
					if !failure.allowed {
						if err == nil {
							t.Fatal("wrong-operation or unknown validation denial acquired a frozen plan")
						}
						return
					}
					if err != nil {
						t.Fatal("original validation denial must encode without effects", err)
					}
					decoded, err := decodeFeaturePlan(seed.binding, fingerprint, wire)
					if err != nil || decoded.SCIMBulkDenial != failure.code || decoded.Lifecycle != nil || decoded.SCIMUserUpdate != nil {
						t.Fatal("frozen validation denial lost its exact code or gained effects", err)
					}
					q := claimRequest{commandID: seed.binding.CommandID, tenant: seed.binding.TenantID, feature: &operation,
						safeFields: commandSafeFields(seed.binding, &operation)}
					result := featureOutcome(seed.binding, &operation, identity.CommitOutcomeNotCommitted, 0)
					journal, err := encodeJournalResultFailure(q, result, failure.code, "conflict")
					if err != nil {
						t.Fatal("original validation code could not enter the protected result", err)
					}
					restored, code, err := decodeJournalResultFailure(q, journal, "conflict")
					if err != nil || code != failure.code || restored.Binding != result.Binding || restored.Feature.Operation != operation {
						t.Fatal("protected terminal result changed validation code or command scope", err)
					}
					seed.lifecycle, seed.scimBulkDenial = nil, failure.code
					now := time.Unix(1700000000, 0).UTC()
					audits, err := featureMutationAudits(t.Context(), &seed, now, "conflict")
					if err != nil || len(audits) != 1 || !audits[0].Changes().NoChange() {
						t.Fatal("validation denial must retain one original no-change child audit", err)
					}
					if _, err := featureMutationAudits(t.Context(), &seed, now, "committed"); err == nil {
						t.Fatal("validation denial acquired a successful audit")
					}
					for _, scenario := range []string{"alien-owner", "alien-schema", "wrong-patch-policy", "lifecycle", "update", "non-bulk", "ordinary-audit", "unprotected", "human-actor", "foreign-subject"} {
						t.Run(scenario, func(t *testing.T) {
							binding, candidate := seed.binding, plan
							feature := *plan.Feature
							candidate.Feature = &feature
							candidate.Audits = append([]AuditPlan(nil), plan.Audits...)
							switch scenario {
							case "alien-owner":
								candidate.Feature.Operation.Owner = "alien"
							case "alien-schema":
								candidate.Feature.Operation.SchemaVersion++
							case "wrong-patch-policy":
								candidate.Feature.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
								if method == "patch" {
									candidate.Feature.Operation.VersionPolicy = identity.FeatureVersionSequential
								}
							case "lifecycle":
								candidate.Lifecycle = &LifecyclePlan{EventType: "identity.scim." + resource + "_created.v1", AfterVersion: 1}
							case "update":
								candidate.SCIMUserUpdate = &SCIMUserUpdatePlan{Required: true, ExpectedVersion: 1}
							case "non-bulk":
								binding.CorrelationID = string(binding.CommandID)
							case "ordinary-audit":
								candidate.Audits[0].EventType = "identity.scim." + resource + "-" + method
							case "unprotected":
								candidate.Audits[0].RetentionClass = "standard"
							case "human-actor":
								binding.ActorKind = authorization.SubjectUser
							case "foreign-subject":
								candidate.SubjectType = "scim_bulk_child"
							}
							if _, err := encodeFeaturePlan(binding, fingerprint, candidate); err == nil {
								t.Fatal("validation denial escaped its original no-effect Bulk scope")
							}
						})
					}
					w, participant, command := featureFailureOperationWork(t, operation)
					w.state.subjectType = "scim_" + resource
					_ = w.DenyFeature(t.Context(), participant, command, failure.code)
					if w.state.featureFailure != 0 {
						t.Fatal("ordinary feature failure borrowed Bulk validation retention")
					}
					w, participant, command = featureFailureOperationWork(t, operation)
					w.state.subjectType = "scim_" + resource
					w.state.execution.reservation.plan.scimBulkDenial = failure.code
					w.state.execution.reservation.plan.lifecycle = nil
					w.state.lifecycle = nil
					var conflict identity.ConflictError
					if err := w.DenyFeature(t.Context(), participant, command, failure.code); !errors.As(err, &conflict) || w.state.featureFailure != failure.code {
						t.Fatal("original frozen denial did not retain its exact validation code", err)
					}
				})
			}
		}
	}
}
