package postgres

import (
	"bytes"
	"crypto/sha256"

	identity "github.com/faustbrian/go-identity"
)

// FeaturePlanDigest structurally binds an explicit feature preparation profile,
// ordered contributor identities, exact schema, required audits and lifecycle
// declaration to the command binding and nonzero fingerprint. Digest is excluded.
// It performs no I/O, registry lookup, authorization or native schema validation.
// Trusted adapters must declare every required action; these bounds do not prove
// that declaration complete. The coordinator alone computes authoritative keyed
// intent and matches its frozen registry. Preparation grants no reservation,
// Work or execution readiness. Feature capability/cascade phases are unsupported
// and rejected rather than silently omitted. Invalid input returns redacted
// identity.InvalidInputError. Do not mutate inputs concurrently with this call.
func FeaturePlanDigest(binding identity.CommandBinding, fingerprint [32]byte, plan CommandPlan) ([32]byte, error) {
	b, err := encodeFeaturePlan(binding, fingerprint, plan)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func encodeFeaturePlan(binding identity.CommandBinding, fingerprint [32]byte, p CommandPlan) ([]byte, error) {
	if p.Feature == nil || fingerprint == ([32]byte{}) || binding.ValidateFor(p.Feature.Operation) != nil || p.Feature.Contributor.Owner != p.Feature.Operation.Owner+"/postgres" || !validContributorDescriptor(p.Feature.Contributor) || p.Capability != nil || len(p.Contributors) != 4 || len(p.Audits) == 0 || len(p.Audits) > 64 || p.Lifecycle == nil || !featureEventName(p.Lifecycle.EventType) {
		return nil, invalidPlan()
	}
	l := p.Lifecycle
	if p.Feature.Operation.RecordRequirement == identity.FeatureRecordRequired {
		if l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
			return nil, invalidPlan()
		}
	} else if l.BeforeVersion != 0 || l.AfterVersion != 0 {
		return nil, invalidPlan()
	}
	entries := make([][]byte, len(p.Contributors))
	seen := make(map[string]bool, len(p.Contributors))
	domains, audits, outboxes, features := 0, 0, 0, 0
	for i, d := range p.Contributors {
		if !validContributorDescriptor(d) || seen[d.ContractID] {
			return nil, invalidPlan()
		}
		seen[d.ContractID] = true
		switch {
		case d == p.Feature.Contributor:
			features++
		case d.Owner == "identity/postgres":
			domains++
		case d.Owner == "audit/postgres":
			audits++
		case d.Owner == "outbox/postgres" && d.ContractID == "identity.lifecycle" && d.Version == 1:
			outboxes++
		default:
			return nil, invalidPlan()
		}
		entries[i] = cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))})
	}
	if domains != 1 || audits != 1 || outboxes != 1 || features != 1 {
		return nil, invalidPlan()
	}
	events := make([][]byte, len(p.Audits))
	for i, a := range p.Audits {
		if !featureEventName(a.EventType) || a.SchemaVersion != 1 || a.BindingDigest == ([32]byte{}) || a.RetentionPolicyVersion == 0 || a.RequiredRecordCount != 1 || !a.Required || a.MaxRecordBytes == 0 || a.MaxRecordBytes > 16384 || a.MaxAggregateBytes < a.MaxRecordBytes || a.MaxAggregateBytes > 16384 || i > 0 && p.Audits[i-1].EventIndex >= a.EventIndex {
			return nil, invalidPlan()
		}
		events[i] = cborMap(map[string][]byte{"event_type": cborText(a.EventType), "schema_version": cborUint(uint64(a.SchemaVersion)), "event_index": cborUint(uint64(a.EventIndex)), "binding_digest": cborBytes(a.BindingDigest[:]), "retention_policy_version": cborUint(a.RetentionPolicyVersion), "required_record_count": cborUint(uint64(a.RequiredRecordCount)), "max_record_bytes": cborUint(uint64(a.MaxRecordBytes)), "max_aggregate_bytes": cborUint(uint64(a.MaxAggregateBytes)), "required": cborBool(a.Required)})
	}
	d := p.Feature.Operation
	feature := cborMap(map[string][]byte{"owner": cborText(d.Owner), "operation_id": cborText(d.OperationID), "schema_id": cborText(d.SchemaID), "schema_version": cborUint(uint64(d.SchemaVersion)), "record_requirement": cborUint(uint64(d.RecordRequirement)), "contributor": cborMap(map[string][]byte{"owner": cborText(p.Feature.Contributor.Owner), "contract_id": cborText(p.Feature.Contributor.ContractID), "version": cborUint(uint64(p.Feature.Contributor.Version))})})
	return cborMap(map[string][]byte{"profile": cborText("identity-feature-plan-v1"), "binding": cborMap(commandScope(binding)), "fingerprint": cborBytes(fingerprint[:]), "contributors": cborArray(entries), "audits": cborArray(events), "feature": feature, "lifecycle": cborMap(map[string][]byte{"event_type": cborText(l.EventType), "event_index": cborUint(uint64(l.EventIndex)), "before_version": cborUint(l.BeforeVersion), "after_version": cborUint(l.AfterVersion)})}), nil
}

func featureEventName(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func (c *Coordinator) prepareFeature(binding identity.CommandBinding, command identity.Command, spec identity.FeatureCommandSpec, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	fail := func() (claimRequest, CommandPlan, *admittedKernelPlan, error) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	if binding != spec.Binding || p.Feature == nil || p.Feature.Operation != spec.Operation {
		return fail()
	}
	if _, err := c.registry.selectFeatureOperation(*p.Feature); err != nil {
		return fail()
	}
	entries, err := c.registry.selectContributors(p.Contributors)
	if err != nil {
		return fail()
	}
	for _, entry := range entries {
		if entry.descriptor.Owner == "audit/postgres" {
			if _, ok := entry.contributor.(AuditContributor); !ok {
				return fail()
			}
		}
		if entry.descriptor.Owner == "outbox/postgres" {
			if _, ok := entry.contributor.(LifecycleContributor); !ok {
				return fail()
			}
		}
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) || !bytes.Equal(q.safeFields, commandSafeFields(binding, &spec.Operation)) {
		return fail()
	}
	snapshot := CommandPlan{Contributors: append([]ContributorDescriptor(nil), p.Contributors...), Audits: append([]AuditPlan(nil), p.Audits...), Capability: p.Capability}
	feature := *p.Feature
	snapshot.Feature = &feature
	if p.Lifecycle != nil {
		lifecycle := *p.Lifecycle
		snapshot.Lifecycle = &lifecycle
	}
	snapshot.Digest, err = FeaturePlanDigest(binding, claimFingerprint(c.keys.retained[c.keys.current], q.canonical), snapshot)
	if err != nil {
		return fail()
	}
	// No admitted execution handle exists until native feature phases are owned.
	return q, snapshot, nil, nil
}
