package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestProviderRefreshUnattachedPreparationIsObservationOnly(t *testing.T) {
	_, original, plan := featurePlanFixture(t)
	spec, _ := original.Feature()
	spec.Operation = identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.refresh-token",
		SchemaID: "identity.account.refresh-token.pg-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	binding := spec.Binding
	binding.OperationID, binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	binding.RecordID, binding.ActorID = "provider-account", identity.ActorID(binding.UserID)
	spec.Binding = binding
	native := ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.provider-refresh", Version: 1}
	counter := ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
	plan.Contributors = []ContributorDescriptor{plan.Contributors[0], plan.Contributors[1], plan.Contributors[2], counter, native}
	plan.Feature = &FeatureRegistration{Contributor: native, Operation: spec.Operation}
	plan.SubjectType = "account"
	plan.Audits[0].RetentionClass, plan.Audits[0].EventType = "standard", "identity.oauth.refresh_grant"
	plan.Lifecycle = &LifecyclePlan{EventType: "social_provider.token_grant_changed.v1", BeforeVersion: 1, AfterVersion: 2}
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: binding.PolicyVersion, Fingerprint: [32]byte{2}}
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(binding, fp, plan)
	if err != nil {
		t.Fatal("encode exact refresh declaration", err)
	}
	claim, err := prepareClaim(featureCodecCommand(t, spec), [32]byte{1})
	if err != nil {
		t.Fatal("prepare exact refresh scope", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until, state, profile := now.Add(time.Second), "pending", int16(4)
	q, _ := queryInputs(binding)
	observed := commandObservation{tenant: string(binding.TenantID), purpose: binding.OperationID,
		scope: claim.safeFields, fingerprint: fp[:], state: &state, until: &until, now: now,
		preparationProfile: &profile, declaration: wire}
	result, err := commandReceipt(q, observed, nil)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != binding ||
		result.Feature == nil || result.Feature.Operation != spec.Operation || result.Feature.BeforeVersion != 0 || result.Feature.AfterVersion != 0 {
		t.Fatal("pending externally attempted refresh was not observable without granting authority", err)
	}
	if _, _, err := observedCommandPlan(binding, &spec.Operation, observed); err == nil {
		t.Fatal("metadata observation opened generic recovery of an ambiguous provider exchange")
	}
	for name, mutate := range map[string]func(*commandObservation){
		"other-profile":              func(o *commandObservation) { v := int16(3); o.preparationProfile = &v },
		"wrong-fingerprint":          func(o *commandObservation) { o.fingerprint = bytes.Repeat([]byte{2}, 32) },
		"missing-declaration":        func(o *commandObservation) { o.declaration = nil },
		"aborted-without-final-plan": func(o *commandObservation) { v := "aborted"; o.state = &v },
	} {
		t.Run(name, func(t *testing.T) {
			bad := observed
			mutate(&bad)
			if got, err := commandReceipt(q, bad, nil); err == nil || got.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("noncanonical or terminal history was treated as pending refresh")
			}
		})
	}
}
