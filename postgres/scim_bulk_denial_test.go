package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

func TestSCIMBulkDenialPlanHasNoLifecycle(t *testing.T) {
	seed := scimBulkGroupMutationAuditPlan(t, scimBulkGroupMutationCases()[0])
	for _, code := range []FeatureFailureCode{FeatureFailureGroupMissing, FeatureFailureGroupVersionRequired} {
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
